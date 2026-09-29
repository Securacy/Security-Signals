"""Microsoft Entra ID sign-in endpoints.

    GET  /api/v1/auth/entra/login     start the authorization-code flow
    GET  /api/v1/auth/entra/callback  Entra redirects here; validate, map, hand off
    POST /api/v1/auth/entra/session   exchange the one-time handoff cookie for the app JWT

Session handoff - why it works this way. The callback is a top-level
browser navigation from Microsoft to this API, so it cannot return JSON to
the SPA, and an access token must NEVER be put in a redirect URL (history,
logs, Referer). Instead the callback sets a 60-second, single-use,
HttpOnly cookie and redirects to the SPA; the SPA then makes ONE credentialed
POST to /session, which trades that cookie for the SAME bearer JWT the
password login already returns. AuthContext, the bearer-token API client,
get_current_user and every require_admin/require_reviewer dependency are
therefore unchanged: Entra only replaces HOW a session is established.

The client secret is used solely inside app.auth.entra's server-side token
exchange. It is never in a response, a redirect, a cookie, or a log line.
"""

import logging
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode
from uuid import UUID

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api.rate_limit import limiter
from app.auth import entra
from app.auth.entra import EntraAuthError
from app.auth.session_payload import session_user_payload
from app.auth.tokens import create_access_token
from app.config import get_settings
from app.db.connection import get_db
from app.repositories import UserRepository
from app.services.entra_auth_service import EntraAuthService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth/entra", tags=["auth"])

_COOKIE_PATH = "/api/v1/auth/entra"
HANDOFF_COOKIE_NAME = "ss_entra_handoff"
HANDOFF_TTL_SECONDS = 60
_HANDOFF_TYP = "entra_handoff"
# Required on the session exchange: forces a CORS preflight for any
# cross-origin caller, so a foreign page can't even attempt the request.
SESSION_REQUEST_HEADER = ("x-requested-with", "ss-admin")

_login_rate_limit = get_settings().login_rate_limit


class _HandoffStore:
    """Remembers consumed handoff IDs until they would have expired anyway,
    making each handoff single-use. In-process: with several API replicas a
    replayed cookie could succeed once per replica within its 60s life -
    an accepted, documented limit (the cookie is HttpOnly, Path-scoped and
    never leaves the browser except to this API)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._used: dict = {}

    def consume(self, jti: str, expires_at: float) -> bool:
        now = time.time()
        with self._lock:
            self._used = {k: v for k, v in self._used.items() if v > now}
            if jti in self._used:
                return False
            self._used[jti] = expires_at
            return True

    def clear(self) -> None:
        with self._lock:
            self._used.clear()


handoff_store = _HandoffStore()


def _cookie_secure(settings) -> bool:
    # https redirect URI => production-style deployment: Secure cookies.
    # Plain-http localhost is supported for development only.
    return settings.entra_redirect_uri.startswith("https://")


def _set_cookie(response, settings, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        name, value, max_age=max_age, path=_COOKIE_PATH,
        httponly=True, secure=_cookie_secure(settings), samesite="lax",
    )


def _delete_cookie(response, settings, name: str) -> None:
    response.delete_cookie(
        name, path=_COOKIE_PATH, httponly=True, secure=_cookie_secure(settings), samesite="lax",
    )


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _require_enabled(settings) -> None:
    if not settings.entra_enabled:
        raise HTTPException(status_code=404, detail="Not found")


def _error_redirect(settings, public_code: str) -> RedirectResponse:
    """Back to the SPA's login page with a coarse, fixed error code only -
    no exception text, no token, no Microsoft error_description."""
    base = settings.frontend_url.rstrip("/")
    response = RedirectResponse(f"{base}/admin/login?{urlencode({'error': public_code})}", status_code=302)
    _delete_cookie(response, settings, entra.OAUTH_COOKIE_NAME)
    return _no_store(response)


@router.get("/login")
@limiter.limit(_login_rate_limit)
def entra_login(request: Request):
    """Begin sign-in: redirect the browser to Microsoft's authorize endpoint."""
    settings = get_settings()
    _require_enabled(settings)

    authorization_url, state_cookie = entra.build_authorization_request(settings)
    response = RedirectResponse(authorization_url, status_code=302)
    _set_cookie(response, settings, entra.OAUTH_COOKIE_NAME, state_cookie, entra.OAUTH_COOKIE_TTL_SECONDS)
    logger.info("entra_login_started")
    return _no_store(response)


@router.get("/callback")
@limiter.limit(_login_rate_limit)
def entra_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Microsoft redirects the browser here. Validate everything server-side;
    on success set the one-time handoff cookie and send the browser to the
    SPA. Deliberately logs nothing derived from `code`, `state`, tokens or
    cookies - only fixed event names, reason codes, and per-phase timing (to
    make a slow or failing sign-in diagnosable without ever touching secret
    material)."""
    settings = get_settings()
    _require_enabled(settings)

    # Per-phase timing - safe to log (phase name + duration only) and the
    # only way to tell, after the fact, WHICH step of the flow a slow or
    # failed sign-in actually spent its time in (e.g. distinguishing "the
    # POST to Microsoft's token endpoint was slow" from "something on our
    # side was slow").
    phase = "state_verification"
    phase_started = time.monotonic()

    def _phase_ms() -> float:
        return round((time.monotonic() - phase_started) * 1000, 2)

    try:
        # State first (login-CSRF protection), before touching anything else
        # the query string says - including an `error` response.
        oauth_state = entra.verify_state(settings, request.cookies.get(entra.OAUTH_COOKIE_NAME), state)

        if error:
            safe = re.sub(r"[^A-Za-z0-9_]", "", error)[:64]
            logger.warning("entra_authorization_error error=%s", safe)
            raise EntraAuthError("authorization_error", "access_denied")
        if not code:
            raise EntraAuthError("code_missing", "auth_failed")

        phase, phase_started = "code_exchange", time.monotonic()
        id_token = entra.exchange_code_for_id_token(settings, code, oauth_state.code_verifier)
        logger.info("entra_callback_phase_timing phase=%s duration_ms=%s", phase, _phase_ms())

        phase, phase_started = "token_validation", time.monotonic()
        claims = entra.validate_id_token(settings, id_token, oauth_state.nonce)
        logger.info("entra_callback_phase_timing phase=%s duration_ms=%s", phase, _phase_ms())

        phase, phase_started = "sign_in", time.monotonic()
        result = EntraAuthService(db, settings).sign_in(claims)
        logger.info("entra_callback_phase_timing phase=%s duration_ms=%s", phase, _phase_ms())
    except EntraAuthError as e:
        logger.warning("entra_login_denied reason=%s phase=%s phase_duration_ms=%s", e.reason, phase, _phase_ms())
        return _error_redirect(settings, e.public_code)
    except Exception as e:
        logger.error(
            "entra_login_unexpected_error error_type=%s phase=%s phase_duration_ms=%s",
            type(e).__name__, phase, _phase_ms(),
        )
        return _error_redirect(settings, "auth_failed")

    now = datetime.now(timezone.utc)
    handoff = jwt.encode(
        {
            "typ": _HANDOFF_TYP,
            "sub": str(result.user.id),
            "jti": secrets.token_urlsafe(16),
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=HANDOFF_TTL_SECONDS)).timestamp()),
        },
        settings.jwt_secret_key,
        algorithm="HS256",
    )
    base = settings.frontend_url.rstrip("/")
    # `signin=complete` is a flag, not a credential: it only tells the SPA
    # to make its one credentialed POST to /session.
    response = RedirectResponse(f"{base}/admin/?signin=complete", status_code=302)
    _delete_cookie(response, settings, entra.OAUTH_COOKIE_NAME)
    _set_cookie(response, settings, HANDOFF_COOKIE_NAME, handoff, HANDOFF_TTL_SECONDS)
    logger.info("entra_login_succeeded role=%s linked=%s", result.user.role.value, result.linked)
    return _no_store(response)


@router.post("/session")
def entra_session(request: Request, db: Session = Depends(get_db)):
    """Trade the one-time handoff cookie for the application's bearer JWT
    (same response shape as POST /api/v1/auth/login)."""
    settings = get_settings()
    _require_enabled(settings)

    header_name, header_value = SESSION_REQUEST_HEADER
    if request.headers.get(header_name) != header_value:
        raise HTTPException(status_code=403, detail="Forbidden")

    def _unauthorized() -> JSONResponse:
        response = JSONResponse(status_code=401, content={"detail": "No pending sign-in"})
        _delete_cookie(response, settings, HANDOFF_COOKIE_NAME)
        return _no_store(response)

    cookie = request.cookies.get(HANDOFF_COOKIE_NAME)
    if not cookie:
        return _unauthorized()
    try:
        payload = jwt.decode(
            cookie, settings.jwt_secret_key, algorithms=["HS256"],
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
        if payload.get("typ") != _HANDOFF_TYP:
            return _unauthorized()
        if not handoff_store.consume(payload["jti"], float(payload["exp"])):
            logger.warning("entra_handoff_replay_rejected")
            return _unauthorized()
        user = UserRepository(db).get_by_id(UUID(payload["sub"]))
    except (jwt.PyJWTError, ValueError):
        return _unauthorized()

    if user is None or not user.is_active:
        return _unauthorized()

    token = create_access_token(
        user_id=user.id, username=user.username, role=user.role.value,
        expires_in_hours=settings.entra_session_hours,
        password_changed_at=user.password_changed_at,
    )
    response = JSONResponse(content={
        "access_token": token,
        "token_type": "bearer",
        "user": session_user_payload(user),
    })
    _delete_cookie(response, settings, HANDOFF_COOKIE_NAME)
    return _no_store(response)
