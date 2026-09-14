"""
Test configuration loading and validation.
"""

import pytest
from app.config import Settings


def test_settings_defaults():
    """Test default configuration."""
    settings = Settings()
    assert settings.app_name == "Security Signals"
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.backend_port == 8000


def test_settings_environment_validation():
    """Test that invalid environment is rejected."""
    with pytest.raises(ValueError):
        Settings(environment="invalid")


def test_settings_log_level_validation():
    """Test log level validation."""
    settings = Settings(log_level="DEBUG")
    assert settings.log_level == "DEBUG"

    with pytest.raises(ValueError):
        Settings(log_level="INVALID_LEVEL")


def test_settings_jwt_config():
    """Test JWT configuration."""
    settings = Settings()
    assert settings.jwt_algorithm == "HS256"
    assert settings.jwt_expiration_hours == 24
    assert len(settings.jwt_secret_key) > 0


class TestCorsOriginsConfig:
    """CORS allowlist parsing and the wildcard-with-credentials guard."""

    def test_wildcard_cors_origin_rejected(self):
        """allow_credentials=True + allow_origins=['*'] makes
        CORSMiddleware reflect any Origin header - refused at config load
        rather than relying on every operator knowing that."""
        with pytest.raises(ValueError):
            Settings(cors_allowed_origins="*")

    def test_wildcard_with_surrounding_whitespace_rejected(self):
        with pytest.raises(ValueError):
            Settings(cors_allowed_origins="  *  ")

    def test_explicit_allowlist_accepted(self):
        settings = Settings(cors_allowed_origins="https://a.example.com,https://b.example.com")
        assert settings.cors_origins_list == ["https://a.example.com", "https://b.example.com"]

    def test_unset_falls_back_to_frontend_url(self):
        settings = Settings(cors_allowed_origins="", frontend_url="http://localhost:5173")
        assert settings.cors_origins_list == ["http://localhost:5173"]

    def test_single_real_origin_not_treated_as_wildcard(self):
        """A legitimate origin string must never trip the wildcard guard."""
        settings = Settings(cors_allowed_origins="https://securacy.ai")
        assert settings.cors_origins_list == ["https://securacy.ai"]
