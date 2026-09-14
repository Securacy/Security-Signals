"""
FastAPI error handlers and response models.
"""

from fastapi import Request, status
from fastapi.responses import JSONResponse
from app.common.errors import (
    SecuritySignalsException,
    NotFoundError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
)
from app.logging import get_logger

logger = get_logger(__name__)


async def security_signals_exception_handler(request: Request, exc: SecuritySignalsException):
    """Handle custom application exceptions."""
    logger.error(
        "application_error",
        error_type=type(exc).__name__,
        message=str(exc),
        path=request.url.path,
    )

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    detail = "Internal server error"

    if isinstance(exc, NotFoundError):
        status_code = status.HTTP_404_NOT_FOUND
        detail = str(exc)
    elif isinstance(exc, ValidationError):
        status_code = status.HTTP_400_BAD_REQUEST
        detail = str(exc)
    elif isinstance(exc, AuthenticationError):
        status_code = status.HTTP_401_UNAUTHORIZED
        detail = str(exc)
    elif isinstance(exc, AuthorizationError):
        status_code = status.HTTP_403_FORBIDDEN
        detail = str(exc)

    return JSONResponse(
        status_code=status_code,
        content={"detail": detail, "error_type": type(exc).__name__},
    )


async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(
        "unexpected_error",
        error_type=type(exc).__name__,
        message=str(exc),
        path=request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "error_type": "UnexpectedException"},
    )
