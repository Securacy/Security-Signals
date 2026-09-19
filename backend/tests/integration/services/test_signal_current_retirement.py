"""Integration tests for current-vs-historical signal visibility
(Feature 1/2): publishing a new signal in a category that already has
max_current_signals_per_category current signals retires the OLDEST excess
ones to historical - never deletes them, and never empties a category.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from app.db.models import Signal, SignalStatus, User, UserRole
from app.ingestion.freshness_policy import FreshnessPolicy
from app.services.signal_service import SignalService
from app.intelligence.schemas.signal_request import AISignalGenerationResponse


@pytest.fixture
def reviewer(db: Session) -> User:
    user = User(
        username="retirement_reviewer", email="retirement_reviewer@test.local",
        role=UserRole.REVIEWER, password_hash="x", is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _publish_signal(service: SignalService, db: Session, event, reviewer, title: str, category="insecure_design"):
    response = AISignalGenerationResponse(
        signal_title=title,
        signal_description="A sufficiently long description of a design-level security concern.",
        category=category,
        confidence=0.9,
        evidence_summary="Evidence discovered in security audit.",
        secure_design_principles=[],
    )
    signal = service.create_signal_from_ai(event_id=event.id, ai_response=response)
    service.add_evidence(signal_id=signal.id, source_url=f"https://example.com/{signal.id}", source_title="T", excerpt="E")
    service.submit_for_review(signal.id)
    service.approve_signal(signal.id, reviewer_id=reviewer.id)
    service.publish_signal(signal.id, actor_id=reviewer.id)
    db.commit()
    db.refresh(signal)
    return signal


def _tight_policy_service(db: Session, max_current=1) -> SignalService:
    return SignalService(db, freshness_policy=FreshnessPolicy(
        grace_period=timedelta(hours=6), max_current_signals_per_category=max_current,
    ))


class TestSingleSlotRetirement:
    """max_current_signals_per_category=1 - the simplest 'week 1 -> week 2'
    scenario from the spec: Signal B replaces Signal A as current."""

    def test_publishing_a_second_signal_retires_the_first(self, db: Session, security_event, reviewer):
        service = _tight_policy_service(db, max_current=1)

        signal_a = _publish_signal(service, db, security_event, reviewer, "Signal A")
        signal_b = _publish_signal(service, db, security_event, reviewer, "Signal B")

        db.refresh(signal_a)
        db.refresh(signal_b)
        assert signal_a.is_current is False
        assert signal_b.is_current is True

    def test_retired_signal_keeps_published_status(self, db: Session, security_event, reviewer):
        """Retirement changes visibility only, never the lifecycle status -
        history/audit/evidence for the retired signal are all intact."""
        service = _tight_policy_service(db, max_current=1)

        signal_a = _publish_signal(service, db, security_event, reviewer, "Signal A")
        _publish_signal(service, db, security_event, reviewer, "Signal B")

        db.refresh(signal_a)
        assert signal_a.status == SignalStatus.PUBLISHED
        assert signal_a.published_at is not None
        assert len(signal_a.evidence) == 1

    def test_no_second_signal_means_first_remains_current(self, db: Session, security_event, reviewer):
        """'No valid newer article exists: Signal A remains current.'"""
        service = _tight_policy_service(db, max_current=1)

        signal_a = _publish_signal(service, db, security_event, reviewer, "Signal A")

        db.refresh(signal_a)
        assert signal_a.is_current is True

    def test_category_never_empty_after_retirement(self, db: Session, security_event, reviewer):
        service = _tight_policy_service(db, max_current=1)

        _publish_signal(service, db, security_event, reviewer, "Signal A")
        _publish_signal(service, db, security_event, reviewer, "Signal B")
        _publish_signal(service, db, security_event, reviewer, "Signal C")

        current_count = (
            db.query(Signal)
            .filter(Signal.status == SignalStatus.PUBLISHED, Signal.is_current.is_(True))
            .count()
        )
        assert current_count >= 1

    def test_retirement_logs_audit_entry(self, db: Session, security_event, reviewer):
        from app.repositories import AuditLogRepository

        service = _tight_policy_service(db, max_current=1)
        signal_a = _publish_signal(service, db, security_event, reviewer, "Signal A")
        signal_b = _publish_signal(service, db, security_event, reviewer, "Signal B")

        audit_repo = AuditLogRepository(db)
        logs = audit_repo.get_by_resource("SIGNAL", signal_a.id)
        actions = [l.action for l in logs]
        assert "SIGNAL_RETIRED_FROM_CURRENT" in actions

        retire_log = next(l for l in logs if l.action == "SIGNAL_RETIRED_FROM_CURRENT")
        assert retire_log.changes["superseded_by"] == str(signal_b.id)


class TestRetentionCapAppliesPerCategory:
    def test_default_cap_keeps_multiple_current_signals(self, db: Session, security_event, reviewer):
        """The default cap (3) means the first 3 publishes in a category
        all stay current - retirement only kicks in beyond that."""
        service = SignalService(db)  # default policy from settings

        signals = [
            _publish_signal(service, db, security_event, reviewer, f"Signal {i}")
            for i in range(3)
        ]
        for s in signals:
            db.refresh(s)
        assert all(s.is_current for s in signals)

    def test_fourth_publish_retires_the_oldest(self, db: Session, security_event, reviewer):
        service = _tight_policy_service(db, max_current=3)

        signals = [
            _publish_signal(service, db, security_event, reviewer, f"Signal {i}")
            for i in range(4)
        ]
        for s in signals:
            db.refresh(s)

        assert signals[0].is_current is False  # oldest retired
        assert all(s.is_current for s in signals[1:])

    def test_different_categories_do_not_affect_each_others_retention(self, db: Session, security_event, reviewer):
        service = _tight_policy_service(db, max_current=1)

        design_signal = _publish_signal(service, db, security_event, reviewer, "Design Signal", category="insecure_design")
        iam_signal = _publish_signal(service, db, security_event, reviewer, "IAM Signal", category="iam")

        db.refresh(design_signal)
        db.refresh(iam_signal)
        # Different categories - publishing IAM must not retire the
        # insecure_design signal.
        assert design_signal.is_current is True
        assert iam_signal.is_current is True


class TestCurrentFeedExcludesHistorical:
    def test_public_api_only_returns_current_signals(self, db: Session, security_event, reviewer, client):
        service = _tight_policy_service(db, max_current=1)
        signal_a = _publish_signal(service, db, security_event, reviewer, "Signal A")
        signal_b = _publish_signal(service, db, security_event, reviewer, "Signal B")

        response = client.get("/api/v1/signals/published")
        ids = [s["id"] for s in response.json()]

        assert str(signal_b.id) in ids
        assert str(signal_a.id) not in ids

    def test_historical_signal_still_reachable_by_direct_id(self, db: Session, security_event, reviewer, client):
        """Historical records remain available for audit/traceability - a
        direct link to a retired signal still resolves."""
        service = _tight_policy_service(db, max_current=1)
        signal_a = _publish_signal(service, db, security_event, reviewer, "Signal A")
        _publish_signal(service, db, security_event, reviewer, "Signal B")

        response = client.get(f"/api/v1/signals/published/{signal_a.id}")
        assert response.status_code == 200
