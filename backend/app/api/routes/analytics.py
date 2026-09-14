"""Analytics API routes.

Phase 5: monthly signal trends, category/principle counts, dominant theme.

/public is unauthenticated and computed ONLY from PUBLISHED signals - it can
never reveal that a DRAFT/IN_REVIEW/APPROVED/REJECTED signal exists.
/internal is protected (REVIEWER or ADMIN) and reveals full pipeline volume
across all statuses, so it must never be exposed without authentication.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.connection import get_db
from app.db.models import User
from app.api.dependencies import require_reviewer
from app.services.analytics_service import AnalyticsService

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])

_MIN_MONTHS = 1
_MAX_MONTHS = 36


@router.get("/public", response_model=dict)
def get_public_analytics(
    months: int = Query(default=12, ge=_MIN_MONTHS, le=_MAX_MONTHS),
    db: Session = Depends(get_db),
):
    """Monthly published-signal counts, category counts, principle counts,
    and dominant theme - PUBLIC endpoint, PUBLISHED signals only."""
    service = AnalyticsService(db)
    return service.get_public_analytics(months=months)


@router.get("/internal", response_model=dict)
def get_internal_analytics(
    months: int = Query(default=12, ge=_MIN_MONTHS, le=_MAX_MONTHS),
    current_user: User = Depends(require_reviewer),
    db: Session = Depends(get_db),
):
    """Monthly signal counts across ALL statuses with a per-status
    breakdown - REVIEWER/ADMIN only. Reveals unpublished pipeline volume."""
    service = AnalyticsService(db)
    return service.get_internal_analytics(months=months)
