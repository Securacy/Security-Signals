"""Security tests for JWT configuration hardening.

Covers the production JWT secret guard added to app/config.py, and
additional algorithm-confusion / claim-tampering checks on top of the
existing coverage in tests/integration/auth/test_login.py.
"""
import pytest
import jwt as pyjwt

from app.config import Settings
from app.auth.tokens import decode_access_token, ALLOWED_ALGORITHMS
from app.common.errors import AuthenticationError


class TestProductionJwtSecretGuard:
    """Settings() must refuse to construct with an insecure JWT secret when
    environment=production, so the app fails to boot rather than run with a
    forgeable secret."""

    def test_known_dev_secret_rejected_in_production(self):
        with pytest.raises(Exception):
            Settings(environment="production", jwt_secret_key="dev-secret-key-change-in-production")

    def test_known_alt_dev_secret_rejected_in_production(self):
        with pytest.raises(Exception):
            Settings(environment="production", jwt_secret_key="dev-secret-change-in-production")

    def test_short_secret_rejected_in_production(self):
        with pytest.raises(Exception):
            Settings(environment="production", jwt_secret_key="too-short")

    def test_strong_secret_accepted_in_production(self):
        settings = Settings(
            environment="production",
            jwt_secret_key="a" * 40,
        )
        assert settings.environment == "production"

    def test_dev_secret_allowed_outside_production(self):
        """The guard only applies in production - development/staging keep
        working with the default placeholder secret."""
        settings = Settings(environment="development", jwt_secret_key="dev-secret-key-change-in-production")
        assert settings.jwt_secret_key == "dev-secret-key-change-in-production"


class TestJwtAlgorithmHardening:
    def test_only_hs256_allowed(self):
        assert ALLOWED_ALGORITHMS == ["HS256"]

    def test_alg_none_token_rejected(self):
        """Classic alg=none confusion attack: a token with no signature at
        all must never be accepted."""
        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "00000000-0000-0000-0000-000000000000",
            "username": "attacker",
            "role": "admin",
            "iat": 0,
            "exp": 9999999999,
        }
        forged = pyjwt.encode(payload, key="", algorithm="none", headers=header)

        with pytest.raises(AuthenticationError):
            decode_access_token(forged)

    def test_hs256_token_signed_with_different_algorithm_rejected(self):
        """A token whose header claims HS384 (not in ALLOWED_ALGORITHMS)
        must be rejected even if otherwise well-formed."""
        payload = {
            "sub": "00000000-0000-0000-0000-000000000000",
            "username": "attacker",
            "role": "admin",
            "iat": 0,
            "exp": 9999999999,
        }
        forged = pyjwt.encode(payload, key="some-other-secret-value-1234567890", algorithm="HS384")

        with pytest.raises(AuthenticationError):
            decode_access_token(forged)

    def test_token_missing_role_claim_rejected(self):
        payload = {
            "sub": "00000000-0000-0000-0000-000000000000",
            "username": "attacker",
            "iat": 0,
            "exp": 9999999999,
        }
        from app.config import get_settings
        settings = get_settings()
        forged = pyjwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")

        with pytest.raises(AuthenticationError):
            decode_access_token(forged)
