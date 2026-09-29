"""uvicorn's access log prints the full request line, query string included.
For the OAuth callback that would put the authorization code and state into
the logs - the redaction filter must scrub them."""
import logging

from app.logging import RedactSensitiveQueryFilter, redact_sensitive_query_params, setup_logging


def _access_record(path: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="uvicorn.access", level=logging.INFO, pathname=__file__, lineno=1,
        msg='%s - "%s %s HTTP/%s" %d', args=("127.0.0.1:5000", "GET", path, "1.1", 302), exc_info=None,
    )


def test_oauth_callback_parameters_are_redacted_from_access_log_records():
    record = _access_record("/api/v1/auth/entra/callback?code=SUPER-SECRET-CODE&state=STATE123&session_state=SS9")
    assert RedactSensitiveQueryFilter().filter(record) is True

    rendered = record.getMessage()
    for secret in ("SUPER-SECRET-CODE", "STATE123", "SS9"):
        assert secret not in rendered
    assert "/api/v1/auth/entra/callback?code=[redacted]&state=[redacted]&session_state=[redacted]" in rendered


def test_every_sensitive_parameter_name_is_covered_and_ordinary_params_survive():
    text = redact_sensitive_query_params(
        "GET /x?limit=5&id_token=A&access_token=B&refresh_token=C&error_description=D&client_secret=E&sort=recent"
    )
    for value in "ABCDE":
        assert f"={value}" not in text
    assert "limit=5" in text and "sort=recent" in text


def test_the_filter_is_installed_on_uvicorns_access_logger_exactly_once():
    setup_logging()
    setup_logging()
    filters = [f for f in logging.getLogger("uvicorn.access").filters if isinstance(f, RedactSensitiveQueryFilter)]
    assert len(filters) == 1
