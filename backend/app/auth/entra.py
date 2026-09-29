"""Microsoft Entra ID (OIDC authorization-code flow) protocol handling.

Backend-driven, confidential-client flow. Everything security-relevant
happens here, on the server:

  * the authorization request carries `state` + `nonce` + a PKCE S256
    challenge; the matching values live in a short-lived, SIGNED, HttpOnly
    cookie bound to the initiating browser (never in the URL we hand out
    beyond what the protocol requires);
  * the authorization code is exchanged at Microsoft's token endpoint with
    the server-side client secret (never sent to, or readable by, the
    frontend);
  * the returned ID token is never trusted on its face: RS256 only (the
    algorithm is fixed by us, never taken from the token header), signature
    checked against Microsoft's JWKS, and issuer, tenant, audience, expiry,
    issued-at and nonce are all verified.

Nothing here logs an authorization code, token, secret or cookie value -
only fixed event names, reason codes, timing, and (on a rejected token
exchange) Microsoft's own short machine-readable error diagnostics.

Pure protocol only: mapping an identity to an internal User/role lives in
app/services/entra_auth_service.py.
"""

import base64
import hashlib
import hmac
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlencode

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger(__name__)

# The ONLY algorithm accepted for Entra ID tokens. Fixed here - never
# derived from the token's own (attacker-controlled) header.
ALLOWED_ID_TOKEN_ALGORITHMS = ["RS256"]

SCOPES = "openid profile email"
OAUTH_COOKIE_NAME = "ss_entra_oauth"
OAUTH_COOKIE_TTL_SECONDS = 600
_OAUTH_COOKIE_TYP = "entra_oauth"

_HTTP_TIMEOUT_SECONDS = 10
# The connect phase gets its own, tighter budget than read/write/pool: a
# healthy TCP+TLS handshake to a well-known, globally distributed Microsoft
# endpoint should complete in well under a second in the ordinary case, so a
# connect stalling anywhere near _CONNECT_TIMEOUT_SECONDS already indicates a
# broken network path (a blackholed IPv6 route or a stalling proxy are the
# common causes). Failing that phase fast matters specifically because an
# authorization code has a short validity window - a connect stall that runs
# out the clock lets Microsoft's token endpoint reject the (by-then-expired)
# code with AADSTS70008 "expired due to inactivity" tens of seconds after it
# should have failed locally, burning the code for no reason.
_CONNECT_TIMEOUT_SECONDS = 5
_HTTP_TIMEOUT = httpx.Timeout(_HTTP_TIMEOUT_SECONDS, connect=_CONNECT_TIMEOUT_SECONDS)
_JWKS_TTL_SECONDS = 3600
_JWKS_MIN_FORCED_REFRESH_SECONDS = 60
_CLOCK_SKEW_LEEWAY_SECONDS = 60


class EntraAuthError(Exception):
    """Any failure in the Entra sign-in flow.

    `reason` is a fine-grained, internal code (logged, asserted on in
    tests). `public_code` is the coarse code that may appear in the
    redirect back to the login page - it never carries detail an attacker
    could use to probe the flow.
    """

    def __init__(self, reason: str, public_code: str = "auth_failed"):
        super().__init__(reason)
        self.reason = reason
        self.public_code = public_code


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------

def _authority(settings) -> str:
    return f"{settings.entra_authority_host.rstrip('/')}/{settings.entra_tenant_id}"


def authorize_endpoint(settings) -> str:
    return f"{_authority(settings)}/oauth2/v2.0/authorize"


def token_endpoint(settings) -> str:
    return f"{_authority(settings)}/oauth2/v2.0/token"


def jwks_endpoint(settings) -> str:
    return f"{_authority(settings)}/discovery/v2.0/keys"


def expected_issuer(settings) -> str:
    return f"{_authority(settings)}/v2.0"


# ---------------------------------------------------------------------------
# Authorization request + state cookie
# ---------------------------------------------------------------------------

def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_authorization_request(settings) -> Tuple[str, str]:
    """Returns (authorization_url, signed_state_cookie_value).

    The URL contains no secret: client_id and redirect_uri are public
    protocol parameters, and the PKCE *challenge* (not the verifier) is
    what's sent. The verifier and nonce ride only in the signed cookie.
    """
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)  # 86 chars, within RFC 7636's 43-128

    now = datetime.now(timezone.utc)
    cookie_value = jwt.encode(
        {
            "typ": _OAUTH_COOKIE_TYP,
            "state": state,
            "nonce": nonce,
            "cv": code_verifier,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=OAUTH_COOKIE_TTL_SECONDS)).timestamp()),
        },
        settings.jwt_secret_key,
        algorithm="HS256",
    )

    query = urlencode(
        {
            "client_id": settings.entra_client_id,
            "response_type": "code",
            "redirect_uri": settings.entra_redirect_uri,
            "response_mode": "query",
            "scope": SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": _pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
    )
    return f"{authorize_endpoint(settings)}?{query}", cookie_value


@dataclass
class OAuthState:
    state: str
    nonce: str
    code_verifier: str


def verify_state(settings, cookie_value: Optional[str], returned_state: Optional[str]) -> OAuthState:
    """Validate the browser-bound state cookie against the `state` the
    authorization server echoed back (CSRF / login-CSRF protection)."""
    if not cookie_value or not returned_state:
        raise EntraAuthError("state_missing", "invalid_state")
    try:
        payload = jwt.decode(
            cookie_value,
            settings.jwt_secret_key,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "state", "nonce", "cv"]},
        )
    except jwt.ExpiredSignatureError:
        raise EntraAuthError("state_expired", "invalid_state")
    except jwt.PyJWTError:
        raise EntraAuthError("state_cookie_invalid", "invalid_state")

    if payload.get("typ") != _OAUTH_COOKIE_TYP:
        raise EntraAuthError("state_cookie_wrong_type", "invalid_state")
    # Compare as bytes: compare_digest raises TypeError on non-ASCII str,
    # and `returned_state` is attacker-controlled input.
    if not hmac.compare_digest(str(payload["state"]).encode("utf-8"), returned_state.encode("utf-8")):
        raise EntraAuthError("state_mismatch", "invalid_state")
    return OAuthState(state=payload["state"], nonce=payload["nonce"], code_verifier=payload["cv"])


# ---------------------------------------------------------------------------
# Code exchange (server-side, with the client secret)
# ---------------------------------------------------------------------------

def exchange_code_for_id_token(settings, code: str, code_verifier: str) -> str:
    """Exchange the authorization code for tokens at Microsoft's token
    endpoint and return ONLY the ID token. The access/refresh tokens are
    never read, stored or returned. The client secret is sent in the POST
    body over TLS and appears nowhere else - not in logs, not in errors."""
    if settings.entra_client_secret is None:
        raise EntraAuthError("client_secret_not_configured")
    secret_value = settings.entra_client_secret.get_secret_value()

    # Timed separately from the callback route's own phase timing so a slow
    # or failed exchange is attributable specifically to this one network
    # call to Microsoft, not to anything else in the request - the redirect
    # URI and configured timeout are safe to log (no secret, code, or token).
    request_started = time.monotonic()
    try:
        response = httpx.post(
            token_endpoint(settings),
            data={
                "client_id": settings.entra_client_id,
                "client_secret": secret_value,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.entra_redirect_uri,
                "code_verifier": code_verifier,
                "scope": SCOPES,
            },
            headers={"Accept": "application/json"},
            timeout=_HTTP_TIMEOUT,
        )
    except httpx.HTTPError as e:
        duration_ms = round((time.monotonic() - request_started) * 1000, 2)
        logger.warning(
            "entra_token_request_failed error_type=%s duration_ms=%s configured_timeout_s=%s configured_connect_timeout_s=%s",
            type(e).__name__, duration_ms, _HTTP_TIMEOUT_SECONDS, _CONNECT_TIMEOUT_SECONDS,
        )
        raise EntraAuthError("token_request_failed")
    duration_ms = round((time.monotonic() - request_started) * 1000, 2)

    if response.status_code != 200:
        # Surface Microsoft's own structured diagnostics for the rejection -
        # `error`, `suberror` and the numeric `error_codes` (AADSTS codes)
        # are documented, machine-readable fields, and `error_description`
        # is Microsoft's own English diagnostic text (never our secret, the
        # authorization code, or a token) - these are exactly what
        # distinguishes an expired/reused code from a redirect_uri mismatch,
        # a bad client secret, etc. The rest of the response body is still
        # never logged, since it can otherwise echo request details we
        # don't want to assume are safe.
        try:
            body = response.json()
        except Exception:
            body = {}
        error_code = str(body.get("error", "unknown"))[:64]
        suberror = str(body.get("suberror") or "none")[:64]
        error_codes = body.get("error_codes")
        error_codes = error_codes if isinstance(error_codes, list) else []
        description = str(body.get("error_description") or "none")[:200].replace("\n", " ")
        # Defense in depth: error_description is untrusted network input
        # from Microsoft, not something we control - strip any of OUR OWN
        # secret material before it can reach a log line, in case a
        # misbehaving or spoofed response ever echoed it back.
        for secret_material in (secret_value, code, code_verifier):
            if secret_material:
                description = description.replace(secret_material, "[redacted]")
        logger.warning(
            "entra_token_exchange_rejected status=%s error=%s suberror=%s error_codes=%s description=%s duration_ms=%s",
            response.status_code, error_code, suberror, error_codes, description, duration_ms,
        )
        raise EntraAuthError("token_exchange_rejected")

    try:
        id_token = response.json().get("id_token")
    except Exception:
        raise EntraAuthError("token_response_unparseable")
    if not isinstance(id_token, str) or not id_token:
        raise EntraAuthError("id_token_missing")
    return id_token


# ---------------------------------------------------------------------------
# JWKS
# ---------------------------------------------------------------------------

def _fetch_jwks(settings) -> Dict[str, Any]:
    """Network fetch of Microsoft's signing keys. A module-level function so
    tests replace it - nothing in the suite depends on live Entra."""
    try:
        response = httpx.get(jwks_endpoint(settings), timeout=_HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.warning("entra_jwks_fetch_failed error_type=%s", type(e).__name__)
        raise EntraAuthError("jwks_unavailable")


class _JwksCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._keys: Dict[str, Any] = {}
        self._fetched_at = 0.0
        self._forced_at = 0.0

    def clear(self) -> None:
        with self._lock:
            self._keys, self._fetched_at, self._forced_at = {}, 0.0, 0.0

    def _load(self, settings) -> None:
        jwks = _fetch_jwks(settings)
        self._keys = {k["kid"]: k for k in jwks.get("keys", []) if k.get("kid")}
        self._fetched_at = time.monotonic()

    def get_public_key(self, settings, kid: str):
        with self._lock:
            now = time.monotonic()
            if not self._keys or now - self._fetched_at > _JWKS_TTL_SECONDS:
                self._load(settings)
            if kid not in self._keys and now - self._forced_at > _JWKS_MIN_FORCED_REFRESH_SECONDS:
                # Key rotation: refresh once - but rate-limited so a stream
                # of tokens with random kids can't turn us into a JWKS DoS.
                self._forced_at = now
                self._load(settings)
            jwk = self._keys.get(kid)
        if jwk is None:
            raise EntraAuthError("signing_key_unknown", "invalid_token")
        try:
            return RSAAlgorithm.from_jwk(jwk)
        except Exception:
            raise EntraAuthError("signing_key_invalid", "invalid_token")


jwks_cache = _JwksCache()


# ---------------------------------------------------------------------------
# ID token validation
# ---------------------------------------------------------------------------

def validate_id_token(settings, id_token: str, expected_nonce: str) -> Dict[str, Any]:
    """Fully validate an Entra ID token and return its claims.

    Raises EntraAuthError (never returns unvalidated claims) if the
    signature, algorithm, issuer, tenant, audience, timing or nonce is
    wrong, or the stable object ID claim is missing.
    """
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise EntraAuthError("token_malformed", "invalid_token")

    # Reject anything but RS256 up front (blocks alg=none and the classic
    # RS256->HS256 key-confusion attack) - jwt.decode below would too, but
    # the explicit check gives a precise reason.
    if header.get("alg") not in ALLOWED_ID_TOKEN_ALGORITHMS:
        raise EntraAuthError("token_algorithm_not_allowed", "invalid_token")
    kid = header.get("kid")
    if not kid:
        raise EntraAuthError("token_kid_missing", "invalid_token")

    key = jwks_cache.get_public_key(settings, kid)

    try:
        claims = jwt.decode(
            id_token,
            key,
            algorithms=ALLOWED_ID_TOKEN_ALGORITHMS,
            audience=settings.entra_client_id,
            issuer=expected_issuer(settings),
            leeway=_CLOCK_SKEW_LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise EntraAuthError("token_expired", "invalid_token")
    except jwt.InvalidAudienceError:
        raise EntraAuthError("token_wrong_audience", "invalid_token")
    except jwt.InvalidIssuerError:
        raise EntraAuthError("token_wrong_issuer", "invalid_token")
    except jwt.PyJWTError:
        # Bad signature, not-yet-valid, missing required claim, ...
        raise EntraAuthError("token_invalid", "invalid_token")

    # Tenant: the issuer already embeds the tenant, but `tid` is checked
    # explicitly too (defense in depth against a differently-scoped token).
    if str(claims.get("tid", "")).lower() != settings.entra_tenant_id.lower():
        raise EntraAuthError("token_wrong_tenant", "invalid_token")

    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or not hmac.compare_digest(
        token_nonce.encode("utf-8"), expected_nonce.encode("utf-8"),
    ):
        raise EntraAuthError("token_nonce_mismatch", "invalid_token")

    # Stable identity key: the Entra object ID. Never email.
    oid = claims.get("oid")
    if not isinstance(oid, str) or not oid.strip():
        raise EntraAuthError("token_oid_missing", "invalid_token")

    return claims
