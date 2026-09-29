"""
FastAPI application factory.
Entry point for uvicorn.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from app.config import get_settings
from app.logging import setup_logging, get_logger
from app.db.connection import verify_database_connection
from app.api.errors import security_signals_exception_handler, general_exception_handler
from app.api.middleware import setup_middleware
from app.api.rate_limit import limiter
from app.api.routes import health
from app.common.errors import SecuritySignalsException
#from app.api.routes import signals, auth

# Setup logging before anything else
setup_logging()
logger = get_logger(__name__)

settings = get_settings()


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
    )

    # Rate limiting (login brute-force protection - see app/api/rate_limit.py)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Setup middleware
    setup_middleware(app)

    # Exception handlers
    app.add_exception_handler(SecuritySignalsException, security_signals_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)

    # Routes
    app.include_router(health.router)

    # AI-assisted natural-language signal search (Feature 3) - registered
    # under /api/v1/signals/search, the SAME prefix as signals.router below.
    # It must be included first: signals.router's GET /{signal_id} is a
    # catch-all that would otherwise shadow this literal /search path,
    # since FastAPI/Starlette matches routes in registration order across
    # routers sharing a prefix, not just within one router.
    from app.api.routes import search
    app.include_router(search.router)

    # Phase 4-5: AI Intelligence & Signals
    from app.api.routes import signals
    app.include_router(signals.router)

    # Phase 6: Authentication, user management, audit visibility
    from app.api.routes import auth
    app.include_router(auth.router)

    from app.api.routes import entra_auth
    app.include_router(entra_auth.router)

    from app.api.routes import users
    app.include_router(users.router)

    from app.api.routes import audit
    app.include_router(audit.router)

    # Phase 5: Analytics (monthly trends, category/principle counts)
    from app.api.routes import analytics
    app.include_router(analytics.router)

    # Category/source coverage health - admin-only (Feature 2)
    from app.api.routes import category_health
    app.include_router(category_health.router)

    # Per-signal AI-generated threat visuals (ThreatVisualService writes
    # files under settings.media_root; served statically here, read-only -
    # no route ever accepts a client-supplied path into this directory).
    media_root = Path(settings.media_root)
    media_root.mkdir(parents=True, exist_ok=True)
    app.mount(settings.media_url_prefix, StaticFiles(directory=str(media_root)), name="media")

    # Startup events
    @app.on_event("startup")
    async def startup():
        logger.info("app_startup", app_name=settings.app_name, environment=settings.environment)
        db_ok = await verify_database_connection()
        if not db_ok:
            logger.warning("app_startup_incomplete", reason="database_not_available")
        else:
            logger.info("app_startup_complete")

        # Phase 4: weekly automated ingestion. Guarded by a config flag so
        # a deployment can run the API without also running the scheduler
        # (e.g. multiple API replicas, where only one process should
        # schedule jobs - see the Celery migration note in
        # app/scheduler/ingestion_scheduler.py for the N>1 replica case).
        if settings.scheduler_enabled:
            from app.scheduler.ingestion_scheduler import ingestion_scheduler
            ingestion_scheduler.start()

    @app.on_event("shutdown")
    async def shutdown():
        if settings.scheduler_enabled:
            from app.scheduler.ingestion_scheduler import ingestion_scheduler
            ingestion_scheduler.shutdown(wait=False)
        logger.info("app_shutdown")

    return app


app = create_app()
