"""Settings validation for the Entra configuration (fail loudly, never mis-validate)."""
import pytest
from pydantic import ValidationError

from app.config import Settings
from tests.entra_support import (  # noqa: F401
    CLIENT_ID, FAKE_CLIENT_SECRET, TENANT_ID, entra_settings,
)


def test_entra_is_off_by_default_and_an_unconfigured_disabled_entra_is_valid():
    settings = Settings()
    assert settings.entra_enabled is False


def test_a_complete_configuration_is_accepted(entra_settings):
    settings = Settings()
    assert settings.entra_enabled and settings.entra_tenant_id == TENANT_ID and settings.entra_client_id == CLIENT_ID


def test_the_client_secret_is_a_secretstr_that_never_appears_in_repr_or_str(entra_settings):
    settings = Settings()
    assert settings.entra_client_secret.get_secret_value() == FAKE_CLIENT_SECRET
    assert FAKE_CLIENT_SECRET not in repr(settings) and FAKE_CLIENT_SECRET not in str(settings)


def test_the_settings_model_has_no_application_side_group_configuration(entra_settings):
    """Application access is restricted entirely by the Security Signals
    Enterprise Application's own "user assignment required" setting in the
    Entra/Azure portal - this codebase has no group ID field to configure."""
    settings = Settings()
    assert not hasattr(settings, "entra_security_signals_group_id")
    assert not hasattr(settings, "entra_admin_group_id")


@pytest.mark.parametrize("name,value,fragment", [
    ("ENTRA_TENANT_ID", "common", "ENTRA_TENANT_ID"),
    ("ENTRA_TENANT_ID", "organizations", "ENTRA_TENANT_ID"),
    ("ENTRA_TENANT_ID", "", "ENTRA_TENANT_ID"),
    ("ENTRA_CLIENT_ID", "not-a-guid", "ENTRA_CLIENT_ID"),
    ("ENTRA_CLIENT_SECRET", "", "ENTRA_CLIENT_SECRET"),
    ("ENTRA_CLIENT_SECRET", "   ", "ENTRA_CLIENT_SECRET"),
    ("ENTRA_AUTHORITY_HOST", "http://login.microsoftonline.com", "ENTRA_AUTHORITY_HOST"),
    ("ENTRA_REDIRECT_URI", "javascript:alert(1)", "ENTRA_REDIRECT_URI"),
])
def test_an_unsafe_or_incomplete_configuration_is_refused_when_entra_is_enabled(entra_settings, monkeypatch, name, value, fragment):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError) as exc:
        Settings()
    assert fragment in str(exc.value)


def test_production_requires_https(entra_settings, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 48)
    with pytest.raises(ValidationError, match="https"):
        Settings()

    monkeypatch.setenv("ENTRA_REDIRECT_URI", "https://signals.example.test/api/v1/auth/entra/callback")
    monkeypatch.setenv("FRONTEND_URL", "https://signals.example.test")
    Settings()  # now valid
