"""Integration tests for AnalyticsService against real PostgreSQL, covering
at least 3 months of signal data."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.services.analytics_service import AnalyticsService
from app.services.signal_service import SignalService
from app.db.models import (
    Signal, SignalCategory, SignalStatus, SecurityCategoryType, SecurityEvent,
    EventType, EventSeverity,
)
from app.intelligence.schemas.signal_request import AISignalGenerationResponse


def _make_signal(
    db: Session,
    security_event: SecurityEvent,
    status: SignalStatus,
    published_at: datetime = None,
    created_at: datetime = None,
    category: SecurityCategoryType = SecurityCategoryType.VULNERABILITY,
    principle: str = "Least Privilege",
) -> Signal:
    """Create a Signal directly with explicit timestamps, bypassing the
    normal now()-stamped lifecycle - needed to build a dataset spanning
    multiple real months without waiting real time."""
    signal = Signal(
        id=uuid4(),
        event_id=security_event.id,
        status=status,
        title="Test Signal",
        summary="Comprehensive test signal summary for analytics coverage.",
        security_impact="Test impact",
        principle=principle,
        recommended_action="Test action",
        published_at=published_at,
        created_at=created_at or datetime.now(timezone.utc),
    )
    db.add(signal)
    db.flush()

    db.add(SignalCategory(
        id=uuid4(), signal_id=signal.id, category=category,
        confidence=0.9, assigned_by="AI",
    ))
    db.commit()
    db.refresh(signal)
    return signal


@pytest.fixture
def three_month_dataset(db: Session, security_event):
    """Published signals across 3 distinct real months, plus unpublished
    signals in the mix, to exercise both public (published-only) and
    internal (all-status) analytics."""
    now = datetime.now(timezone.utc)

    def months_ago(n: int) -> datetime:
        y, m = now.year, now.month - n
        while m <= 0:
            m += 12
            y -= 1
        return now.replace(year=y, month=m, day=1, hour=12, minute=0, second=0, microsecond=0)

    signals = {
        "published_2mo_ago_vuln": _make_signal(
            db, security_event, SignalStatus.PUBLISHED,
            published_at=months_ago(2), created_at=months_ago(2),
            category=SecurityCategoryType.VULNERABILITY, principle="Least Privilege",
        ),
        "published_1mo_ago_iam": _make_signal(
            db, security_event, SignalStatus.PUBLISHED,
            published_at=months_ago(1), created_at=months_ago(1),
            category=SecurityCategoryType.IAM, principle="Defense in Depth",
        ),
        "published_this_month_iam_a": _make_signal(
            db, security_event, SignalStatus.PUBLISHED,
            published_at=months_ago(0), created_at=months_ago(0),
            category=SecurityCategoryType.IAM, principle="Defense in Depth; Least Privilege",
        ),
        "published_this_month_iam_b": _make_signal(
            db, security_event, SignalStatus.PUBLISHED,
            published_at=months_ago(0), created_at=months_ago(0),
            category=SecurityCategoryType.IAM, principle="Defense in Depth",
        ),
        "draft_this_month": _make_signal(
            db, security_event, SignalStatus.DRAFT,
            published_at=None, created_at=months_ago(0),
            category=SecurityCategoryType.RANSOMWARE, principle="Secure Defaults",
        ),
        "in_review_1mo_ago": _make_signal(
            db, security_event, SignalStatus.IN_REVIEW,
            published_at=None, created_at=months_ago(1),
            category=SecurityCategoryType.SUPPLY_CHAIN, principle="Secure Defaults",
        ),
    }
    return {"now": now, "months_ago": months_ago, "signals": signals}


class TestPublicAnalytics:
    """Public analytics must reflect ONLY published signals."""

    def test_excludes_unpublished_signals_entirely(self, db: Session, three_month_dataset):
        service = AnalyticsService(db)
        result = service.get_public_analytics(months=3)

        assert result["total_published"] == 4  # not 6 - draft/in_review excluded

    def test_monthly_counts_span_three_months(self, db: Session, three_month_dataset):
        service = AnalyticsService(db)
        result = service.get_public_analytics(months=3)

        assert len(result["monthly_counts"]) == 3
        counts_by_month = {m["month"]: m["count"] for m in result["monthly_counts"]}
        total = sum(counts_by_month.values())
        assert total == 4

    def test_zero_signal_months_still_present(self, db: Session, three_month_dataset):
        """A month bucket with no published signals must appear with
        count=0, not be silently omitted."""
        service = AnalyticsService(db)
        result = service.get_public_analytics(months=6)

        assert len(result["monthly_counts"]) == 6
        assert any(m["count"] == 0 for m in result["monthly_counts"])

    def test_category_counts_from_published_signals_only(self, db: Session, three_month_dataset):
        service = AnalyticsService(db)
        result = service.get_public_analytics(months=3)

        assert result["category_counts"] == {"vulnerability": 1, "iam": 3}
        # RANSOMWARE (draft) and SUPPLY_CHAIN (in_review) must not appear:
        assert "ransomware" not in result["category_counts"]
        assert "supply_chain" not in result["category_counts"]

    def test_dominant_theme_is_highest_published_category(self, db: Session, three_month_dataset):
        service = AnalyticsService(db)
        result = service.get_public_analytics(months=3)

        assert result["dominant_theme"] == {"category": "iam", "count": 3}

    def test_principle_counts_split_and_exclude_unpublished(self, db: Session, three_month_dataset):
        service = AnalyticsService(db)
        result = service.get_public_analytics(months=3)

        # "Defense in Depth" appears in 3 published signals (once as part of
        # a joined "Defense in Depth; Least Privilege" string).
        assert result["principle_counts"]["Defense in Depth"] == 3
        assert result["principle_counts"]["Least Privilege"] == 2
        # "Secure Defaults" only appears on draft/in_review signals:
        assert "Secure Defaults" not in result["principle_counts"]

    def test_generated_at_is_utc_iso_timestamp(self, db: Session, three_month_dataset):
        service = AnalyticsService(db)
        result = service.get_public_analytics(months=1)

        parsed = datetime.fromisoformat(result["generated_at"])
        assert parsed.tzinfo is not None


class TestInternalAnalytics:
    """Internal analytics must reveal all statuses, for pipeline visibility."""

    def test_includes_all_statuses(self, db: Session, three_month_dataset):
        service = AnalyticsService(db)
        result = service.get_internal_analytics(months=3)

        assert result["total_signals"] == 6

    def test_status_totals_broken_down(self, db: Session, three_month_dataset):
        service = AnalyticsService(db)
        result = service.get_internal_analytics(months=3)

        assert result["status_totals"]["published"] == 4
        assert result["status_totals"]["draft"] == 1
        assert result["status_totals"]["in_review"] == 1

    def test_monthly_counts_by_status(self, db: Session, three_month_dataset):
        service = AnalyticsService(db)
        result = service.get_internal_analytics(months=3)

        month_keys = [m["month"] for m in result["monthly_counts"]]
        current_month_key = month_keys[-1]
        by_status = result["monthly_counts_by_status"][current_month_key]

        assert by_status.get("published") == 2
        assert by_status.get("draft") == 1


class TestAnalyticsAPIAccessControl:
    """Public endpoint requires no auth; internal endpoint does."""

    def test_public_endpoint_accessible_without_auth(self, client, three_month_dataset):
        response = client.get("/api/v1/analytics/public")
        assert response.status_code == 200
        body = response.json()
        assert "monthly_counts" in body
        assert "total_published" in body

    def test_internal_endpoint_rejects_unauthenticated(self, client, three_month_dataset):
        response = client.get("/api/v1/analytics/internal")
        assert response.status_code == 401

    def test_public_endpoint_never_exposes_status_totals(self, client, three_month_dataset):
        """Defense in depth: even if the service were ever miswired, the
        public response shape itself must not carry a per-status
        breakdown field."""
        response = client.get("/api/v1/analytics/public")
        body = response.json()
        assert "status_totals" not in body
        assert "total_signals" not in body
