"""
Health check endpoint for monitoring and readiness probes.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.db.connection import get_db, verify_database_connection
from app.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/", response_model=dict)
async def health_check():
    """Basic health check."""
    return {
        "status": "healthy",
        "version": "0.1.0",
    }


@router.get("/ready", response_model=dict)
async def readiness_check(db: Session = Depends(get_db)):
    """
    Readiness check: includes database connectivity.
    Used by orchestrators (K8s, Docker, etc.) to decide if service is ready.
    """
    db_ok = await verify_database_connection()

    if not db_ok:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "reason": "database_unreachable",
            },
        )

    return {
        "status": "ready",
    }