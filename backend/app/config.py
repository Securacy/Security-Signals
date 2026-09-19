"""
Configuration management.
Reads from environment, validates, provides app-wide config.
"""

from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr, model_validator
from typing import Optional
import os

# Known development/placeholder JWT secrets that must never be used in production.
_INSECURE_JWT_SECRETS = {
    "dev-secret-key-change-in-production",
    "dev-secret-change-in-production",
    "changeme",
    "secret",
    "",
}

_MIN_PRODUCTION_JWT_SECRET_LENGTH = 32


class Settings(BaseSettings):
    """Application settings from environment."""

    # App
    app_name: str = "Security Signals"
    app_version: str = "0.1.0"
    environment: str = Field(default="development", pattern="^(development|staging|production)$")
    debug: bool = Field(default=False)

    # Server
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    frontend_url: str = "http://localhost:5173"

    # CORS: comma-separated list of allowed origins for the public widget
    # (e.g. the eventual Securacy.AI domain(s)). Left empty by default so
    # existing single-origin deployments keep working unchanged; set via
    # env at deploy time rather than hardcoding a production domain here.
    cors_allowed_origins: str = Field(default="")

    # Database
    database_url: str = Field(
        default="postgresql://user:password@localhost:5432/security_signals"
    )
    database_url_test: str | None = Field(default=None)
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # API Keys
    # Direct Anthropic API access. Kept for tests and as a documented
    # fallback path (see AISignalService), but AWS Bedrock below is the
    # production path for AI signal generation - Claude is invoked through
    # Bedrock, not the direct Anthropic API, in production.
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")

    # AWS Bedrock - production path for Claude invocation (AISignalService).
    # Credentials may be literal values (local/test) or AWS Secrets Manager
    # ARNs (this deployment's actual .env uses ARNs); resolution of an ARN
    # to its real secret value happens in app/intelligence/bedrock_client.py,
    # never here and never logged. SecretStr keeps the raw value out of
    # repr()/str()/logs by default even before that resolution step.
    aws_bedrock_access_key_id: Optional[SecretStr] = Field(default=None, alias="AWS_BEDROCK_ACCESS_KEY_ID")
    aws_bedrock_secret_access_key: Optional[SecretStr] = Field(default=None, alias="AWS_BEDROCK_SECRET_ACCESS_KEY")
    aws_region: str = Field(default="us-east-1", alias="AWS_REGION")
    bedrock_model_id: str = Field(default="", alias="BEDROCK_MODEL_ID")

    jwt_secret_key: str = Field(default="dev-secret-key-change-in-production")
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24

    # Rate limiting (Phase 6: brute-force protection)
    login_rate_limit: str = Field(default="10/minute")

    # Ingestion
    ingestion_timeout_seconds: int = 30
    ingestion_max_retries: int = 3
    ingestion_max_response_size_mb: int = 10

    # Freshness / current-feed policy (centralized - see
    # app/ingestion/freshness_policy.py for the functions that consume
    # these; nothing else should hardcode these numbers).
    #
    # freshness_grace_hours: how far before a source's last successful
    # checkpoint an entry's published time may still fall and count as
    # "new" - absorbs clock skew and delayed RSS publication.
    # max_current_signals_per_category: how many PUBLISHED signals stay
    # "current" (publicly visible) per category at once; publishing beyond
    # this retires the oldest current ones to historical - never deletes
    # them, and only ever happens as a side effect of a NEW signal actually
    # being published (see SignalService.publish_signal).
    freshness_grace_hours: int = Field(default=6)
    max_current_signals_per_category: int = Field(default=3)

    # AI-assisted natural-language search (Feature 3). A separate prompt/
    # service from signal generation - see app/intelligence/search_service.py.
    # Disabling this flag (or any runtime failure/timeout) falls back to
    # deterministic keyword search rather than breaking the public feed.
    search_ai_enabled: bool = Field(default=True)
    search_max_query_length: int = Field(default=300)
    search_candidate_limit: int = Field(default=50)
    search_ai_timeout_seconds: int = Field(default=8)
    search_rate_limit: str = Field(default="20/minute")

    # Per-signal AI-generated threat visuals (ThreatVisualService). Uses
    # the same AWS Bedrock account/region/credentials already configured
    # above for Claude - no separate provider credentials. Disabling this
    # flag (or any generation failure/timeout) never blocks signal
    # publication; the frontend falls back to a static category icon.
    visual_generation_enabled: bool = Field(default=True)
    bedrock_image_model_id: str = Field(default="amazon.nova-canvas-v1:0")
    visual_generation_timeout_seconds: int = Field(default=30)
    media_root: str = Field(default="media")
    media_url_prefix: str = Field(default="/media")

    # Scheduler (Phase 4): weekly automated ingestion. Defaults on for
    # normal operation; the app's test suite never triggers FastAPI's
    # startup event (TestClient(app) isn't used as a context manager here),
    # so tests never start a real background job regardless of this value -
    # this flag exists for explicit operational control (e.g. running one
    # API instance with scheduling disabled behind a separate cron/worker).
    scheduler_enabled: bool = Field(default=True)

    # Demo/development-only seed accounts (see app/services/demo_seed_service.py).
    # Never given a fallback value here - seeding refuses to run at all if
    # either is unset, rather than falling back to a predictable password.
    # SecretStr keeps the raw value out of repr()/str()/logs.
    demo_admin_password: Optional[SecretStr] = Field(default=None, alias="DEMO_ADMIN_PASSWORD")
    demo_reviewer_password: Optional[SecretStr] = Field(default=None, alias="DEMO_REVIEWER_PASSWORD")

    # Logging
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")

    class Config:
        env_file = ".env"
        case_sensitive = False

    @property
    def cors_origins_list(self) -> list[str]:
        """Parsed CORS allowlist. Falls back to `frontend_url` alone when
        `cors_allowed_origins` isn't set, preserving prior single-origin
        behavior for anyone who hasn't configured the new setting."""
        if self.cors_allowed_origins.strip():
            return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]
        return [self.frontend_url]

    @model_validator(mode="after")
    def _validate_production_jwt_secret(self):
        """Refuse to boot in production with a known/placeholder or weak JWT secret.

        A predictable JWT_SECRET_KEY lets anyone forge admin-role access tokens,
        so this is a hard failure rather than a warning.
        """
        if self.environment == "production":
            if self.jwt_secret_key in _INSECURE_JWT_SECRETS:
                raise ValueError(
                    "JWT_SECRET_KEY is set to a known development/placeholder value. "
                    "A unique secret must be set via the environment in production."
                )
            if len(self.jwt_secret_key) < _MIN_PRODUCTION_JWT_SECRET_LENGTH:
                raise ValueError(
                    f"JWT_SECRET_KEY must be at least {_MIN_PRODUCTION_JWT_SECRET_LENGTH} "
                    "characters in production."
                )
        return self

    @model_validator(mode="after")
    def _validate_cors_not_wildcard(self):
        """Refuse a wildcard CORS origin.

        The app enables allow_credentials=True (needed for the JWT-bearing
        widget/admin requests), and CORSMiddleware's own documented behavior
        for allow_origins=["*"] combined with allow_credentials=True is to
        reflect whatever Origin header the request sent - i.e. "*" here does
        not mean "no CORS", it silently becomes "allow any origin, with
        credentials", defeating the explicit-allowlist model this app is
        built on. Refusing it at config load time is cheaper than relying on
        every operator to know that Starlette-specific detail.
        """
        if self.cors_allowed_origins.strip() == "*":
            raise ValueError(
                "CORS_ALLOWED_ORIGINS must not be '*' - with allow_credentials=True this "
                "reflects any request's Origin header, allowing any site to make "
                "authenticated requests. Set an explicit comma-separated allowlist instead."
            )
        return self


def get_settings() -> Settings:
    """Get application settings (cached singleton in practice)."""
    return Settings()


# Validate on import
_settings = get_settings()
