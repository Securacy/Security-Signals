"""Integration tests for find_stale_visuals/regenerate_stale_visuals against
real PostgreSQL (Section 5 of the visual-relevance fix: stale v1 visuals
must be identifiable and explicitly regenerable, never silently treated
as signal-specific, never regenerated automatically on every page view).

Uses a fake ImageProvider (no real Bedrock calls) - only the DB query/
persistence behavior is under test here; prompt content is covered by
tests/unit/intelligence/test_visual_service.py.
"""

from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.db.models import (
    AssignmentMethod, EventSeverity, EventType, SecurityCategoryType, SecurityEvent, Signal,
    SignalCategory, SignalStatus, SignalVisual, VisualStatus,
)
from app.intelligence.visual_service import (
    PROMPT_VERSION, ImageProvider, ThreatVisualService, find_stale_visuals,
    regenerate_stale_visuals,
)


class _FakeProvider(ImageProvider):
    def __init__(self, should_fail_for=None):
        self.calls = []
        self._should_fail_for = should_fail_for or set()

    def generate(self, prompt: str) -> bytes:
        self.calls.append(prompt)
        return b"fake-png-bytes"


def _make_published_signal(db: Session, title: str, category=SecurityCategoryType.INSECURE_DESIGN) -> Signal:
    event = SecurityEvent(
        id=uuid4(), name=f"Event for {title}", description="A real event description.",
        event_type=EventType.VULNERABILITY, severity=EventSeverity.MEDIUM,
    )
    db.add(event)
    db.flush()

    signal = Signal(
        id=uuid4(), event_id=event.id, title=title, summary="A summary.",
        security_impact="An impact.", principle="A principle.", recommended_action="An action.",
        status=SignalStatus.PUBLISHED,
    )
    db.add(signal)
    db.flush()

    db.add(SignalCategory(
        signal_id=signal.id, category=category, confidence=0.9, assigned_by=AssignmentMethod.AI,
    ))
    db.commit()
    db.refresh(signal)
    return signal


class TestFindStaleVisuals:
    def test_finds_rows_with_an_older_prompt_version(self, db: Session):
        signal = _make_published_signal(db, "Stale v1 Visual Signal")
        db.add(SignalVisual(
            signal_id=signal.id, status=VisualStatus.GENERATED, url="/media/signals/old.png",
            prompt_version="v1",
        ))
        db.commit()

        stale = find_stale_visuals(db)

        assert any(v.signal_id == signal.id for v in stale)

    def test_current_version_rows_are_not_stale(self, db: Session):
        signal = _make_published_signal(db, "Current v2 Visual Signal")
        db.add(SignalVisual(
            signal_id=signal.id, status=VisualStatus.GENERATED, url="/media/signals/new.png",
            prompt_version=PROMPT_VERSION,
        ))
        db.commit()

        stale = find_stale_visuals(db)

        assert not any(v.signal_id == signal.id for v in stale)

    def test_pending_rows_are_never_stale_candidates(self, db: Session):
        """A PENDING row means a generation attempt is (or was) in flight
        - not something this explicit, on-demand path should touch."""
        signal = _make_published_signal(db, "Pending Visual Signal")
        db.add(SignalVisual(signal_id=signal.id, status=VisualStatus.PENDING, prompt_version="v1"))
        db.commit()

        stale = find_stale_visuals(db)

        assert not any(v.signal_id == signal.id for v in stale)

    def test_stale_failed_rows_are_included(self, db: Session):
        """A stale FAILED row deserves a retry under the improved prompt
        too, not just stale GENERATED ones."""
        signal = _make_published_signal(db, "Stale Failed Visual Signal")
        db.add(SignalVisual(
            signal_id=signal.id, status=VisualStatus.FAILED, error="old failure", prompt_version="v1",
        ))
        db.commit()

        stale = find_stale_visuals(db)

        assert any(v.signal_id == signal.id for v in stale)

    def test_failed_rows_already_at_the_current_prompt_version_are_still_retryable(self, db: Session):
        """A FAILED row can fail for reasons entirely unrelated to prompt
        quality - a transient provider outage, a temporary OpenAI account/
        model-access issue - so it must stay retryable even once it's
        already at the current PROMPT_VERSION, not just when its prompt is
        also stale. See task requirement: "Existing FAILED visuals should
        be retryable using the current OpenAI provider."."""
        signal = _make_published_signal(db, "Current-Version Failed Visual Signal")
        db.add(SignalVisual(
            signal_id=signal.id, status=VisualStatus.FAILED, error="simulated OpenAI outage",
            prompt_version=PROMPT_VERSION,
        ))
        db.commit()

        stale = find_stale_visuals(db)

        assert any(v.signal_id == signal.id for v in stale)


class TestRegenerateStaleVisualsBatch:
    def test_regenerates_a_stale_row_and_preserves_exactly_one_row_per_signal(self, db: Session):
        signal = _make_published_signal(db, "Batch Regeneration Signal")
        db.add(SignalVisual(
            signal_id=signal.id, status=VisualStatus.GENERATED, url="/media/signals/old.png",
            prompt_version="v1",
        ))
        db.commit()

        provider = _FakeProvider()
        service = ThreatVisualService(provider, media_root="/tmp/does-not-matter", media_url_prefix="/media")

        summary = regenerate_stale_visuals(db, service)

        assert summary.considered >= 1
        assert summary.regenerated >= 1
        rows = db.query(SignalVisual).filter_by(signal_id=signal.id).all()
        assert len(rows) == 1  # never a duplicate row
        assert rows[0].prompt_version == PROMPT_VERSION
        assert rows[0].status == VisualStatus.GENERATED

    def test_never_runs_for_a_signal_already_on_the_current_version(self, db: Session):
        signal = _make_published_signal(db, "Already Current Signal")
        db.add(SignalVisual(
            signal_id=signal.id, status=VisualStatus.GENERATED, url="/media/signals/current.png",
            prompt_version=PROMPT_VERSION,
        ))
        db.commit()

        provider = _FakeProvider()
        service = ThreatVisualService(provider, media_root="/tmp/does-not-matter", media_url_prefix="/media")

        regenerate_stale_visuals(db, service)

        assert provider.calls == []
        row = db.query(SignalVisual).filter_by(signal_id=signal.id).one()
        assert row.url == "/media/signals/current.png"

    def test_respects_an_explicit_limit(self, db: Session):
        for i in range(3):
            signal = _make_published_signal(db, f"Limited Batch Signal {i}")
            db.add(SignalVisual(signal_id=signal.id, status=VisualStatus.GENERATED, prompt_version="v1"))
        db.commit()

        provider = _FakeProvider()
        service = ThreatVisualService(provider, media_root="/tmp/does-not-matter", media_url_prefix="/media")

        summary = regenerate_stale_visuals(db, service, limit=1)

        assert summary.considered == 1
