"""
FastAPI middleware for logging, CORS, rate limiting, etc.

Phase 6: Login-specific rate limiting lives in app/api/rate_limit.py and is
applied directly to the login route (see app/api/routes/auth.py) rather than
as global middleware, so it doesn't affect unrelated endpoints.
"""

import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings
from app.logging import get_logger

logger = get_logger(__name__)

settings = get_settings()


def setup_middleware(app: FastAPI):
    """Configure all middleware."""

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        """Structured request logging.

        Logs method, path, status, and duration only. Never logs headers
        (which may carry Authorization/Bearer tokens), query strings, or the
        request body (which may carry passwords), so secrets never reach logs.
        """
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = round((time.monotonic() - start) * 1000, 2)
        logger.info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
        return response

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        """Baseline security headers for this JSON API (and its /docs
        Swagger UI). Independent of the frontend widget's own iframe-embed
        headers/CSP, which live in the separate frontend project - nothing
        here affects the widget's ability to be embedded elsewhere.
        """
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
