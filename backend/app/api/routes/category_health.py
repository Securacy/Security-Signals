"""Admin-only category/source coverage health (Feature 2).

Answers "is every advertised category currently being maintained?" for
operators - never exposed publicly, since it reveals internal source
health/failure-count details beyond what the public feed already shows.
"""

import logging
from dataclasses import asdict

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.connection import get_db
from app.db.models import User
from app.api.dependencies import require_admin
from app.services.category_health_service import compute_category_health

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/category-health", tags=["admin"])


@router.get("", response_model=list)
def get_category_health(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Per-category coverage/source health - ADMIN only.

    For every advertised category: its primary/secondary trusted sources,
    each source's health (enabled, consecutive failures, last
    success/failure), whether current published coverage exists, how many
    current signals it has, and how stale that coverage is.
    """
    health = compute_category_health(db)
    return [
        {
            "category": h.category,
            "primary_sources": h.primary_sources,
            "secondary_sources": h.secondary_sources,
            "source_health": [asdict(s) for s in h.source_health],
            "has_current_coverage": h.has_current_coverage,
            "current_signal_count": h.current_signal_count,
            "last_current_signal_at": h.last_current_signal_at,
            "coverage_age_days": h.coverage_age_days,
            "is_stale": h.is_stale,
            "last_new_article_at": h.last_new_article_at,
            "coverage_status": h.coverage_status,
        }
        for h in health
    ]
