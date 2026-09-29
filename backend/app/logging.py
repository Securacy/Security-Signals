"""
Structured logging setup using structlog.
JSON output to stdout (Docker-friendly).
"""

import logging
import re
import sys

import structlog

from app.config import get_settings


# Query parameters that carry OAuth/OIDC one-time credentials or identity
# material. uvicorn's access log prints the full request line - including
# the query string - so /api/v1/auth/entra/callback?code=...&state=... would
# otherwise land the authorization code in the logs.
_SENSITIVE_QUERY_PARAMS = re.compile(
    r"(?P<key>[?&](?:code|state|id_token|access_token|refresh_token|session_state|"
    r"error_description|client_secret|client_assertion))=[^&\s\"]*",
    re.IGNORECASE,
)


def redact_sensitive_query_params(text: str) -> str:
    return _SENSITIVE_QUERY_PARAMS.sub(r"\g<key>=[redacted]", text)


class RedactSensitiveQueryFilter(logging.Filter):
    """Scrubs OAuth/OIDC query parameters from uvicorn access-log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                redact_sensitive_query_params(a) if isinstance(a, str) else a for a in record.args
            )
        if isinstance(record.msg, str):
            record.msg = redact_sensitive_query_params(record.msg)
        return True


def setup_logging():
    """Configure structlog for production-oriented logging."""
    settings = get_settings()

    access_logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, RedactSensitiveQueryFilter) for f in access_logger.filters):
        access_logger.addFilter(RedactSensitiveQueryFilter())

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.log_level),
    )


def get_logger(name: str):
    """Get a structured logger by name."""
    return structlog.get_logger(name)