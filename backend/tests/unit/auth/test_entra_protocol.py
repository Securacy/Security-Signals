"""Unit tests for app/auth/entra.py - the Entra OIDC protocol layer.
All Microsoft network calls are mocked; the ID tokens are signed with a
throwaway RSA key. Nothing here can reach live Entra."""
import base64
import hashlib
import hmac
import json
import logging
import time
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest

from app.auth import entra
from app.auth.entra import EntraAuthError
from app.config import get_settings
from tests.entra_support import (  # noqa: F401  (entra_settings is a fixture)
    CLIENT_ID, FAKE_CLIENT_SECRET, KID, OTHER_TENANT_ID, REDIRECT_URI, TENANT_ID,
    entra_settings, jwks_document, make_id_token, sign_with_other_key,
)

NONCE = "expected-nonce-value"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class TestAuthorizationRequest:
    def test_authorization_url_carries_exactly_the_required_protocol_parameters(self, entra_settings):
        url, _ = entra.build_authorization_request(get_settings())
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
            f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
        )
        assert params["client_id"] == CLIENT_ID
        assert params["response_type"] == "code"
        assert params["redirect_uri"] == REDIRECT_URI
        assert params["response_mode"] == "query"
        assert set(params["scope"].split()) == {"openid", "profile", "email"}
        assert params["code_challenge_method"] == "S256"
        assert params["state"] and params["nonce"] and params["code_challenge"]

    def test_authorization_url_never_contains_the_client_secret_or_pkce_verifier(self, entra_settings):
        url, cookie = entra.build_authorization_request(get_settings())
        verifier = jwt.decode(cookie, options={"verify_signature": False})["cv"]

        assert FAKE_CLIENT_SECRET not in url
        assert "client_secret" not in url
        assert verifier not in url

    def test_state_nonce_and_verifier_are_fresh_for_every_request(self, entra_settings):
        settings = get_settings()
        first = jwt.decode(entra.build_authorization_request(settings)[1], options={"verify_signature": False})
        second = jwt.decode(entra.build_authorization_request(settings)[1], options={"verify_signature": False})

        assert first["state"] != second["state"]
        assert first["nonce"] != second["nonce"]
        assert first["cv"] != second["cv"]

    def test_pkce_challenge_is_the_s256_of_the_verifier_kept_in_the_cookie(self, entra_settings):
        url, cookie = entra.build_authorization_request(get_settings())
        challenge = parse_qs(urlparse(url).query)["code_challenge"][0]
        verifier = jwt.decode(cookie, options={"verify_signature": False})["cv"]

        expected = _b64(hashlib.sha256(verifier.encode()).digest())
        assert challenge == expected
        assert 43 <= len(verifier) <= 128  # RFC 7636 bounds

    def test_state_and_nonce_in_the_url_match_the_signed_cookie(self, entra_settings):
        url, cookie = entra.build_authorization_request(get_settings())
        params = parse_qs(urlparse(url).query)
        payload = jwt.decode(cookie, options={"verify_signature": False})

        assert params["state"][0] == payload["state"]
        assert params["nonce"][0] == payload["nonce"]


class TestStateVerification:
    def _issue(self):
        settings = get_settings()
        url, cookie = entra.build_authorization_request(settings)
        return settings, cookie, parse_qs(urlparse(url).query)["state"][0]

    def test_matching_cookie_and_state_yield_the_nonce_and_verifier(self, entra_settings):
        settings, cookie, state = self._issue()
        result = entra.verify_state(settings, cookie, state)
        assert result.state == state and result.nonce and result.code_verifier

    def test_a_state_that_does_not_match_the_cookie_is_rejected(self, entra_settings):
        settings, cookie, _ = self._issue()
        with pytest.raises(EntraAuthError) as exc:
            entra.verify_state(settings, cookie, "attacker-chosen-state")
        assert exc.value.reason == "state_mismatch" and exc.value.public_code == "invalid_state"

    def test_a_non_ascii_state_is_a_clean_rejection_not_a_server_error(self, entra_settings):
        settings, cookie, _ = self._issue()
        with pytest.raises(EntraAuthError) as exc:
            entra.verify_state(settings, cookie, "sta\u00e9te-\u202e")
        assert exc.value.reason == "state_mismatch" and exc.value.public_code == "invalid_state"

    def test_missing_cookie_or_missing_state_is_rejected(self, entra_settings):
        settings, cookie, state = self._issue()
        with pytest.raises(EntraAuthError):
            entra.verify_state(settings, None, state)
        with pytest.raises(EntraAuthError):
            entra.verify_state(settings, cookie, None)

    def test_a_tampered_or_foreign_signed_cookie_is_rejected(self, entra_settings):
        settings, cookie, state = self._issue()
        forged = jwt.encode(
            {**jwt.decode(cookie, options={"verify_signature": False})}, "not-the-app-secret", algorithm="HS256",
        )
        with pytest.raises(EntraAuthError) as exc:
            entra.verify_state(settings, forged, state)
        assert exc.value.reason == "state_cookie_invalid"

    def test_an_expired_state_cookie_is_rejected(self, entra_settings):
        settings, cookie, state = self._issue()
        payload = jwt.decode(cookie, options={"verify_signature": False})
        payload["exp"] = int(time.time()) - 10
        expired = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
        with pytest.raises(EntraAuthError) as exc:
            entra.verify_state(settings, expired, state)
        assert exc.value.reason == "state_expired"

    def test_a_signed_cookie_of_another_purpose_is_rejected(self, entra_settings):
        """e.g. an app access token (same signing key) must not pass as state."""
        settings, cookie, state = self._issue()
        payload = jwt.decode(cookie, options={"verify_signature": False})
        payload["typ"] = "entra_handoff"
        wrong = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
        with pytest.raises(EntraAuthError) as exc:
            entra.verify_state(settings, wrong, state)
        assert exc.value.reason == "state_cookie_wrong_type"


class TestCodeExchange:
    def _ok_response(self, id_token="the.id.token"):
        response = MagicMock(status_code=200)
        response.json.return_value = {"id_token": id_token, "access_token": "must-be-ignored", "refresh_token": "ignored"}
        return response

    def test_secret_is_sent_only_in_the_post_body_to_the_token_endpoint(self, entra_settings):
        with patch("app.auth.entra.httpx.post", return_value=self._ok_response()) as post:
            token = entra.exchange_code_for_id_token(get_settings(), "auth-code-123", "the-verifier")

        assert token == "the.id.token"
        args, kwargs = post.call_args
        assert args[0] == f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
        data = kwargs["data"]
        assert data["client_secret"] == FAKE_CLIENT_SECRET
        assert data["grant_type"] == "authorization_code"
        assert data["code"] == "auth-code-123"
        assert data["code_verifier"] == "the-verifier"
        assert data["redirect_uri"] == REDIRECT_URI
        assert data["client_id"] == CLIENT_ID
        assert FAKE_CLIENT_SECRET not in args[0]  # never in the URL/query string

    def test_the_connect_phase_has_a_tighter_timeout_than_the_overall_request(self, entra_settings):
        """A stalled TCP/TLS handshake should fail fast rather than run out
        an authorization code's short validity window before Microsoft ever
        sees the request (observed in production: a slow connect let one
        exchange take 80s+, well past the code's validity, before Microsoft
        rejected the by-then-expired code)."""
        with patch("app.auth.entra.httpx.post", return_value=self._ok_response()) as post:
            entra.exchange_code_for_id_token(get_settings(), "c", "v")

        timeout = post.call_args.kwargs["timeout"]
        assert isinstance(timeout, httpx.Timeout)
        assert timeout.connect < timeout.read
        assert timeout.connect <= 5

    def test_only_the_id_token_is_returned_access_and_refresh_tokens_are_discarded(self, entra_settings):
        with patch("app.auth.entra.httpx.post", return_value=self._ok_response()):
            result = entra.exchange_code_for_id_token(get_settings(), "c", "v")
        assert isinstance(result, str) and "must-be-ignored" not in result

    def test_rejection_by_microsoft_raises_without_leaking_secret_code_or_body(self, entra_settings, caplog):
        response = MagicMock(status_code=400, text=f"echoed {FAKE_CLIENT_SECRET} and code-xyz")
        response.json.return_value = {"error": "invalid_grant", "error_description": f"contains {FAKE_CLIENT_SECRET}"}
        caplog.set_level(logging.DEBUG)
        with patch("app.auth.entra.httpx.post", return_value=response):
            with pytest.raises(EntraAuthError) as exc:
                entra.exchange_code_for_id_token(get_settings(), "code-xyz", "verifier-abc")

        assert exc.value.reason == "token_exchange_rejected"
        haystack = caplog.text + str(exc.value) + repr(exc.value)
        for secret in (FAKE_CLIENT_SECRET, "code-xyz", "verifier-abc"):
            assert secret not in haystack

    def test_network_failure_is_a_clean_error_with_no_secret_in_it(self, entra_settings, caplog):
        caplog.set_level(logging.DEBUG)
        with patch("app.auth.entra.httpx.post", side_effect=httpx.ConnectError(f"boom {FAKE_CLIENT_SECRET}")):
            with pytest.raises(EntraAuthError) as exc:
                entra.exchange_code_for_id_token(get_settings(), "c", "v")
        assert exc.value.reason == "token_request_failed"
        assert FAKE_CLIENT_SECRET not in caplog.text + str(exc.value)

    def test_response_without_an_id_token_is_rejected(self, entra_settings):
        response = MagicMock(status_code=200)
        response.json.return_value = {"access_token": "only-this"}
        with patch("app.auth.entra.httpx.post", return_value=response):
            with pytest.raises(EntraAuthError) as exc:
                entra.exchange_code_for_id_token(get_settings(), "c", "v")
        assert exc.value.reason == "id_token_missing"

    def test_a_rejection_logs_microsofts_own_diagnostic_fields_for_debugging(self, entra_settings, caplog):
        """error/suberror/error_codes/error_description are Microsoft's own
        documented, machine-readable diagnostics (e.g. distinguishing a
        reused/expired code from a redirect_uri mismatch) - surfacing them
        is what makes a rejected exchange diagnosable at all."""
        response = MagicMock(status_code=400)
        response.json.return_value = {
            "error": "invalid_grant",
            "suberror": "consent_required",
            "error_codes": [70000],
            "error_description": "AADSTS70000: Something Microsoft explains in plain English.",
        }
        caplog.set_level(logging.DEBUG)
        with patch("app.auth.entra.httpx.post", return_value=response):
            with pytest.raises(EntraAuthError):
                entra.exchange_code_for_id_token(get_settings(), "the-auth-code", "the-pkce-verifier")

        assert "invalid_grant" in caplog.text
        assert "consent_required" in caplog.text
        assert "70000" in caplog.text
        assert "Something Microsoft explains in plain English" in caplog.text

    def test_the_exchange_calls_duration_is_logged_on_both_success_and_rejection(self, entra_settings, caplog):
        caplog.set_level(logging.DEBUG)
        with patch("app.auth.entra.httpx.post", return_value=self._ok_response()):
            entra.exchange_code_for_id_token(get_settings(), "c", "v")
        # Success itself isn't logged by this function (the callback route
        # logs the phase timing) - only a rejection or network failure is.
        caplog.clear()

        response = MagicMock(status_code=400)
        response.json.return_value = {"error": "invalid_grant"}
        with patch("app.auth.entra.httpx.post", return_value=response):
            with pytest.raises(EntraAuthError):
                entra.exchange_code_for_id_token(get_settings(), "c", "v")
        assert "duration_ms=" in caplog.text

    def test_a_spoofed_error_description_echoing_the_secret_code_or_verifier_is_redacted_not_leaked(
        self, entra_settings, caplog,
    ):
        """Defense in depth: error_description is untrusted network input.
        Even if a misbehaving/spoofed response echoed our own secret
        material back at us, none of it may reach a log line."""
        response = MagicMock(status_code=400)
        response.json.return_value = {
            "error": "invalid_grant",
            "error_description": f"debug: secret={FAKE_CLIENT_SECRET} code=code-xyz verifier=verifier-abc",
        }
        caplog.set_level(logging.DEBUG)
        with patch("app.auth.entra.httpx.post", return_value=response):
            with pytest.raises(EntraAuthError):
                entra.exchange_code_for_id_token(get_settings(), "code-xyz", "verifier-abc")

        for secret in (FAKE_CLIENT_SECRET, "code-xyz", "verifier-abc"):
            assert secret not in caplog.text
        assert "[redacted]" in caplog.text


class TestIdTokenValidation:
    def _validate(self, token, nonce=NONCE):
        return entra.validate_id_token(get_settings(), token, nonce)

    def test_a_correctly_signed_token_for_this_tenant_and_client_is_accepted(self, entra_settings):
        claims = self._validate(make_id_token(nonce=NONCE, groups=["g"]))
        assert claims["tid"] == TENANT_ID and claims["aud"] == CLIENT_ID and claims["oid"]

    @pytest.mark.parametrize("scenario,kwargs,reason", [
        ("expired", {"expires_in": -3600}, "token_expired"),
        ("wrong audience / client ID", {"audience": "99999999-9999-4999-8999-999999999999"}, "token_wrong_audience"),
        ("wrong issuer (other tenant's issuer)", {"tenant": OTHER_TENANT_ID}, "token_wrong_issuer"),
        ("wrong issuer (non-Microsoft)", {"issuer": "https://evil.example/tenant/v2.0"}, "token_wrong_issuer"),
        ("wrong nonce", {"nonce": "some-other-nonce"}, "token_nonce_mismatch"),
    ])
    def test_invalid_tokens_are_rejected_with_a_precise_reason(self, entra_settings, scenario, kwargs, reason):
        params = {"nonce": NONCE, **kwargs}
        with pytest.raises(EntraAuthError) as exc:
            self._validate(make_id_token(**params))
        assert exc.value.reason == reason, scenario
        assert exc.value.public_code == "invalid_token"

    def test_a_token_whose_tid_claim_is_another_tenant_is_rejected_even_with_a_correct_issuer(self, entra_settings):
        token = make_id_token(nonce=NONCE, extra={"tid": OTHER_TENANT_ID})
        with pytest.raises(EntraAuthError) as exc:
            self._validate(token)
        assert exc.value.reason == "token_wrong_tenant"

    def test_a_token_with_no_nonce_claim_is_rejected(self, entra_settings):
        with pytest.raises(EntraAuthError) as exc:
            self._validate(make_id_token(nonce=NONCE, omit=["nonce"]))
        assert exc.value.reason == "token_nonce_mismatch"

    def test_a_token_without_the_stable_object_id_is_rejected(self, entra_settings):
        with pytest.raises(EntraAuthError) as exc:
            self._validate(make_id_token(nonce=NONCE, omit=["oid"]))
        assert exc.value.reason == "token_oid_missing"

    def test_a_token_signed_by_a_different_key_is_rejected(self, entra_settings):
        with pytest.raises(EntraAuthError) as exc:
            self._validate(sign_with_other_key(nonce=NONCE))
        assert exc.value.reason == "token_invalid"

    def test_alg_none_is_rejected(self, entra_settings):
        unsigned = jwt.encode({"iss": "x", "aud": CLIENT_ID}, key=None, algorithm="none", headers={"kid": KID})
        with pytest.raises(EntraAuthError) as exc:
            self._validate(unsigned)
        assert exc.value.reason == "token_algorithm_not_allowed"

    def test_rs256_to_hs256_key_confusion_is_rejected(self, entra_settings):
        """Classic attack: HMAC-sign with the (public) JWKS key material and
        claim alg=HS256. The algorithm is fixed by us, never taken from the token."""
        jwk = jwks_document()["keys"][0]
        header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
        body = _b64(json.dumps({
            "iss": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0", "aud": CLIENT_ID, "tid": TENANT_ID,
            "oid": "x", "nonce": NONCE, "iat": int(time.time()), "exp": int(time.time()) + 600,
        }).encode())
        signature = _b64(hmac.new(json.dumps(jwk).encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
        with pytest.raises(EntraAuthError) as exc:
            self._validate(f"{header}.{body}.{signature}")
        assert exc.value.reason == "token_algorithm_not_allowed"

    def test_malformed_tokens_are_rejected(self, entra_settings):
        for bad in ("", "not-a-jwt", "a.b.c"):
            with pytest.raises(EntraAuthError):
                self._validate(bad)

    def test_a_token_from_the_future_beyond_the_skew_allowance_is_rejected(self, entra_settings):
        future = int(time.time()) + 3600
        with pytest.raises(EntraAuthError) as exc:
            self._validate(make_id_token(nonce=NONCE, extra={"nbf": future, "iat": future}))
        assert exc.value.public_code == "invalid_token"

    def test_unknown_signing_key_id_is_rejected_after_a_single_rate_limited_refresh(self, entra_settings, monkeypatch):
        calls = []
        monkeypatch.setattr(entra, "_fetch_jwks", lambda s: (calls.append(1), jwks_document())[1])
        token = make_id_token(nonce=NONCE, kid="rotated-away-kid")

        for _ in range(3):
            with pytest.raises(EntraAuthError) as exc:
                self._validate(token)
            assert exc.value.reason == "signing_key_unknown"
        # initial load + at most ONE forced refresh inside the rate-limit
        # window - a stream of bogus kids cannot hammer Microsoft's JWKS.
        assert len(calls) <= 2

    def test_jwks_outage_denies_sign_in_rather_than_skipping_signature_checks(self, entra_settings, monkeypatch):
        def _down(settings):
            raise EntraAuthError("jwks_unavailable")
        monkeypatch.setattr(entra, "_fetch_jwks", _down)
        entra.jwks_cache.clear()
        with pytest.raises(EntraAuthError) as exc:
            self._validate(make_id_token(nonce=NONCE))
        assert exc.value.reason == "jwks_unavailable"
