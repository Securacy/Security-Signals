"""
Configuration management.
Reads from environment, validates, provides app-wide config.
"""

from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr, model_validator
from typing import Optional
import os
import re

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
    # Deliberately NOT bedrock_model_id (used for full signal generation,
    # where reasoning quality matters most) - query-understanding here is a
    # small, bounded classification task (extract categories/keywords from
    # a short phrase into a fixed schema), so a fast model is the right
    # trade-off and measurably faster: ~1.6-2.6s vs ~3.3-3.9s for the same
    # real search prompts against Sonnet, with identical schema validity
    # and identical prompt-injection refusal behavior (verified manually
    # against this account's actual Bedrock model access - older Haiku
    # versions (3, 3.5) have reached end-of-life on Bedrock and are no
    # longer invokable, hence pinning the current one explicitly rather
    # than a version-less alias). Overridable per-deployment without a
    # code change if this model is retired later.
    search_ai_model_id: str = Field(default="us.anthropic.claude-haiku-4-5-20251001-v1:0")
    # Cache the AI's understanding of a normalized (trimmed/lowercased)
    # query string for this long - short-lived, and only the AI
    # UNDERSTANDING (categories/keywords/etc.), never the DB result set,
    # which is always retrieved fresh per request (see
    # signal_search_service.py) so newly published/unpublished signals are
    # never masked by a stale cache entry.
    search_ai_cache_ttl_seconds: int = Field(default=300)
    search_ai_cache_max_entries: int = Field(default=256)

    # Per-signal AI-generated threat visuals (ThreatVisualService).
    # `image_provider` selects which ImageProvider app/intelligence/
    # visual_service.ThreatVisualService.from_settings constructs - the
    # provider is a swappable abstraction (see app/intelligence/
    # visual_service.ImageProvider); neither ThreatVisualService nor
    # SignalVisual persistence changes based on which one is active.
    # Disabling generation entirely (or any generation failure/timeout)
    # never blocks signal publication; the frontend falls back to a
    # static category icon.
    visual_generation_enabled: bool = Field(default=True)
    image_provider: str = Field(default="openai", pattern="^(bedrock|openai)$")
    visual_generation_timeout_seconds: int = Field(default=30)
    media_root: str = Field(default="media")
    media_url_prefix: str = Field(default="/media")

    # Bedrock image provider (image_provider="bedrock") - uses the same
    # AWS Bedrock account/region/credentials already configured above for
    # Claude, no separate provider credentials.
    bedrock_image_model_id: str = Field(default="amazon.nova-canvas-v1:0")

    # OpenAI image provider (image_provider="openai", the current
    # default). A separate credential from Bedrock/Claude - OpenAI is
    # used ONLY for image rendering; signal analysis, structured
    # intelligence, and visual CONCEPT generation all remain on Claude/
    # Bedrock (see VisualConceptService). Never logged, never hardcoded -
    # SecretStr keeps the raw key out of repr()/str()/logs, and callers
    # must call get_secret_value() explicitly to use it. The model id is
    # env-configurable rather than hardcoded so it can be updated without
    # a code change as OpenAI ships new image-model versions/retires old
    # ones (see OPENAI_IMAGE_MODEL_ID docs/shutdown_date on each model via
    # GET https://api.openai.com/v1/models/{id}).
    openai_api_key: Optional[SecretStr] = Field(default=None, alias="OPENAI_API_KEY")
    openai_image_model_id: str = Field(default="gpt-image-2.5-flare", alias="OPENAI_IMAGE_MODEL_ID")
    # Observed real-world latency for this model varies widely - 50s to
    # over 240s for the same request shape (not a code defect; image
    # generation is just slow and bursty). Generation runs as an
    # asynchronous background job started when a Signal is first persisted
    # as a DRAFT, so nothing ever waits on it and a generous ceiling costs
    # nothing. It is enforced as a true wall-clock deadline by
    # OpenAIImageProvider.generate() (see its docstring), so a genuinely
    # stuck request is still bounded and recorded as a real FAILED visual.
    openai_image_timeout_seconds: int = Field(default=420)

    # Signal-specific visual CONCEPT derivation (a Claude text call that
    # turns a signal's real content into a short, concrete visual scene
    # description before it reaches the image model - see
    # app/intelligence/visual_service.VisualConceptService). Disabling
    # this flag (or any failure/timeout) falls back to the previous
    # raw-field prompt construction, never blocking visual generation.
    visual_concept_ai_enabled: bool = Field(default=True)
    visual_concept_ai_timeout_seconds: int = Field(default=8)

    # Microsoft Entra ID (OIDC authorization-code flow, backend-driven).
    # The client secret exists ONLY here on the backend (SecretStr: never in
    # repr()/logs, never sent to the frontend). Disabled by default so an
    # existing deployment is unchanged until an operator opts in.
    entra_enabled: bool = Field(default=False)
    entra_tenant_id: str = Field(default="")
    entra_client_id: str = Field(default="")
    entra_client_secret: Optional[SecretStr] = Field(default=None)
    entra_redirect_uri: str = Field(default="http://localhost:8000/api/v1/auth/entra/callback")
    # Override only for sovereign clouds (e.g. https://login.microsoftonline.us).
    entra_authority_host: str = Field(default="https://login.microsoftonline.com")
    # No application-side access check lives here: the Security Signals
    # Enterprise Application's own "user assignment required" setting (in
    # the Entra/Azure portal, not this codebase) is what restricts who can
    # sign in at all. An unassigned user's flow is rejected by Microsoft
    # itself before our callback ever sees a valid code.
    # One-time link of an existing internal account (same email, not yet
    # linked) to the Entra object ID; the object ID is the identity key
    # from then on, never the email.
    entra_link_existing_users_by_email: bool = Field(default=True)
    # Lifetime of the application session issued after an Entra sign-in.
    entra_session_hours: int = Field(default=8, ge=1, le=24)
    # Keep the temporary username/password login available (development /
    # break-glass). Set false to make Entra the only way in.
    local_login_enabled: bool = Field(default=True)

    # Reviewer email notification (submit-for-review) via Resend.
    # resend_api_key is SecretStr (never in repr()/logs, never sent to the
    # frontend) - same discipline as entra_client_secret above. Both values
    # are already provisioned in the real .env; nothing here is a new
    # reviewer-notification-specific address/recipient setting - only the
    # transport credentials, matching exactly what the organization already
    # configured. See app/integrations/resend_mail.py.
    resend_api_key: Optional[SecretStr] = Field(default=None)
    resend_from_email: str = Field(default="hello@securacy.ai")

    # Dispatch kill-switch for the reviewer-notification background job -
    # same role/shape as visual_generation_enabled below (an operational
    # on/off toggle, not an email address/recipient setting). Defaults ON
    # now that real Resend credentials exist (unlike the old Graph flag,
    # which had to default off pending admin consent that was never
    # granted). tests/conftest.py's autouse fixture forces this off for the
    # whole suite by default, the same way it already does for
    # VISUAL_GENERATION_ENABLED, so routine test runs never place a real
    # call to Resend; only the tests that specifically exercise this
    # feature re-enable it locally.
    reviewer_notification_enabled: bool = Field(default=True)

    # ORG_APPROVAL_EMAIL is already present in the real .env for a
    # separate, existing organization-approval flow - NOT read by the
    # reviewer-notification code above (see app/services/
    # notification_service.py). Declared here only so Settings() can load
    # the real .env without error (pydantic-settings rejects undeclared
    # env vars by default); intentionally unused otherwise.
    org_approval_email: str = Field(default="hello@securacy.ai")

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
    def _validate_entra_configuration(self):
        """When Entra sign-in is enabled, refuse to boot with an incomplete
        or unsafe configuration - failing loudly at startup is safer than a
        login flow that silently denies (or, worse, mis-validates) users."""
        if not self.entra_enabled:
            return self

        guid = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
        problems = []
        if not guid.match(self.entra_tenant_id):
            problems.append("ENTRA_TENANT_ID must be the tenant's GUID (not 'common'/'organizations')")
        if not guid.match(self.entra_client_id):
            problems.append("ENTRA_CLIENT_ID must be the application (client) ID GUID")
        if self.entra_client_secret is None or not self.entra_client_secret.get_secret_value().strip():
            problems.append("ENTRA_CLIENT_SECRET is required")
        if not self.entra_authority_host.startswith("https://"):
            problems.append("ENTRA_AUTHORITY_HOST must be an https:// URL")
        if not self.entra_redirect_uri.startswith(("http://", "https://")):
            problems.append("ENTRA_REDIRECT_URI must be an absolute http(s) URL")
        if self.environment == "production":
            if not self.entra_redirect_uri.startswith("https://"):
                problems.append("ENTRA_REDIRECT_URI must use https in production")
            if not self.frontend_url.startswith("https://"):
                problems.append("FRONTEND_URL must use https in production")
        if problems:
            raise ValueError("Invalid Entra configuration: " + "; ".join(problems))
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
