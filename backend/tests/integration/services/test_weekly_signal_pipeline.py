"""Integration tests for WeeklySignalPipeline against real PostgreSQL.

Uses a mocked AISignalService (no real Bedrock calls in the standard test
suite) so these tests are fast and deterministic, while every DB write
still goes through the real SignalService/SignalCategory/Evidence path -
only the AI call itself is mocked.
"""

from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.db.models import (
    Article, EventArticleMapping, EventType, EventSeverity, Signal,
    SignalStatus, Source, SourceType,
)
from app.intelligence.schemas.signal_request import AISignalGenerationResponse
from app.services.weekly_signal_pipeline import WeeklySignalPipeline


@pytest.fixture
def source(db: Session) -> Source:
    src = Source(
        id=uuid4(), name="Test Source", source_type=SourceType.RSS,
        url="https://example.com/feed", is_active=True,
    )
    db.add(src)
    db.commit()
    db.refresh(src)
    return src


def _make_event_with_article(db: Session, source: Source, name: str, description: str = "A real security event description that is long enough."):
    from app.db.models import SecurityEvent

    event = SecurityEvent(
        id=uuid4(), name=name, description=description,
        event_type=EventType.VULNERABILITY, severity=EventSeverity.MEDIUM,
    )
    db.add(event)
    db.flush()

    article = Article(
        id=uuid4(), source_id=source.id, url=f"https://example.com/{uuid4()}",
        title=name, description=description,
        content_hash=str(uuid4()), is_relevant=True,
    )
    db.add(article)
    db.flush()

    db.add(EventArticleMapping(event_id=event.id, article_id=article.id))
    db.commit()
    db.refresh(event)
    return event


def _valid_ai_response(category="insecure_design"):
    return AISignalGenerationResponse(
        signal_title="Generated Signal Title",
        signal_description="A sufficiently long generated description of the design implication for this event.",
        category=category,
        ai_subcategory="agent_abuse" if category == "ai_security" else None,
        confidence=0.9,
        evidence_summary="Evidence grounded in the real linked article content.",
        secure_design_principles=[],
    )


class TestWeeklyPipelineNoCandidates:
    def test_zero_candidates_completes_successfully_with_zero_generated(self, db: Session):
        """No un-signaled events at all - a normal, successful outcome
        (Change 11), not an error."""
        pipeline = WeeklySignalPipeline(db, ai_service=MagicMock())

        result = pipeline.run()

        assert result["candidates_considered"] == 0
        assert result["generated_count"] == 0
        assert result["failed_count"] == 0

    def test_never_calls_ai_service_when_no_candidates(self, db: Session):
        mock_ai = MagicMock()
        pipeline = WeeklySignalPipeline(db, ai_service=mock_ai)

        pipeline.run()

        mock_ai.generate_signal.assert_not_called()


class TestWeeklyPipelineGeneration:
    def test_generates_real_signal_for_a_real_candidate(self, db: Session, source):
        event = _make_event_with_article(db, source, "Insecure design flaw in auth architecture")
        mock_ai = MagicMock()
        mock_ai.generate_signal.return_value = _valid_ai_response()

        pipeline = WeeklySignalPipeline(db, ai_service=mock_ai)
        result = pipeline.run()

        assert result["generated_count"] == 1
        assert result["failed_count"] == 0
        signal = db.query(Signal).filter(Signal.event_id == event.id).one()
        assert signal.status == SignalStatus.DRAFT
        assert signal.title == "Generated Signal Title"

    def test_generated_signal_never_auto_published(self, db: Session, source):
        _make_event_with_article(db, source, "Insecure design flaw in auth architecture")
        mock_ai = MagicMock()
        mock_ai.generate_signal.return_value = _valid_ai_response()

        pipeline = WeeklySignalPipeline(db, ai_service=mock_ai)
        pipeline.run()

        signal = db.query(Signal).one()
        assert signal.status == SignalStatus.DRAFT
        assert signal.published_at is None

    def test_ai_failure_for_one_event_does_not_crash_the_run(self, db: Session, source):
        from app.intelligence.ai_service import AISecurityError

        _make_event_with_article(db, source, "Insecure design flaw in auth architecture")
        mock_ai = MagicMock()
        mock_ai.generate_signal.side_effect = AISecurityError("simulated failure")

        pipeline = WeeklySignalPipeline(db, ai_service=mock_ai)
        result = pipeline.run()  # must not raise

        assert result["generated_count"] == 0
        assert result["failed_count"] == 1
        assert db.query(Signal).count() == 0

    def test_no_signal_fabricated_when_ai_fails(self, db: Session, source):
        """A failed AI call must never leave behind a placeholder/fabricated
        signal - only a real, validated AI response ever creates one."""
        from app.intelligence.ai_service import AISecurityError

        _make_event_with_article(db, source, "Insecure design flaw in auth architecture")
        mock_ai = MagicMock()
        mock_ai.generate_signal.side_effect = AISecurityError("simulated failure")

        pipeline = WeeklySignalPipeline(db, ai_service=mock_ai)
        pipeline.run()

        assert db.query(Signal).count() == 0

    def test_events_that_already_have_a_signal_are_never_reselected(self, db: Session, source):
        """No duplicate signal generation for an event already covered."""
        event = _make_event_with_article(db, source, "Insecure design flaw in auth architecture")
        mock_ai = MagicMock()
        mock_ai.generate_signal.return_value = _valid_ai_response()

        pipeline = WeeklySignalPipeline(db, ai_service=mock_ai)
        first_result = pipeline.run()
        assert first_result["generated_count"] == 1

        second_result = pipeline.run()

        assert second_result["candidates_considered"] == 0
        assert second_result["generated_count"] == 0
        assert db.query(Signal).filter(Signal.event_id == event.id).count() == 1

    def test_evidence_created_from_real_linked_articles(self, db: Session, source):
        event = _make_event_with_article(db, source, "Insecure design flaw in auth architecture")
        mock_ai = MagicMock()
        mock_ai.generate_signal.return_value = _valid_ai_response()

        pipeline = WeeklySignalPipeline(db, ai_service=mock_ai)
        pipeline.run()

        signal = db.query(Signal).filter(Signal.event_id == event.id).one()
        assert len(signal.evidence) == 1
        assert signal.evidence[0].source_url.startswith("https://example.com/")

    def test_category_counts_and_ai_fraction_reported(self, db: Session, source):
        _make_event_with_article(db, source, "Insecure design flaw in auth architecture")
        mock_ai = MagicMock()
        mock_ai.generate_signal.return_value = _valid_ai_response()

        pipeline = WeeklySignalPipeline(db, ai_service=mock_ai)
        result = pipeline.run()

        assert result["selected_count"] == 1
        assert isinstance(result["category_counts"], dict)
        assert isinstance(result["ai_fraction"], float)


class TestWeeklyPipelineCategoryCoveragePriority:
    """Feature 2/4: the pipeline reads real, already-persisted current-
    signal coverage before selecting candidates, so categories the
    published feed has lost coverage for get first claim on this run's
    real candidates."""

    def test_with_no_published_signals_every_category_is_priority(self, db: Session):
        pipeline = WeeklySignalPipeline(db, ai_service=MagicMock())

        result = pipeline.run()

        assert set(result["priority_categories"]) == {
            "insecure_design", "cloud_security", "iam", "app_api", "supply_chain",
            "data_privacy", "ransomware", "threat_intel", "ai_security", "infrastructure",
        }

    def test_category_with_real_current_published_signal_is_not_priority(self, db: Session, source):
        from app.db.models import User, UserRole

        reviewer = User(username="pipeline_coverage_reviewer", email="pipeline_coverage_reviewer@test.local",
                         role=UserRole.REVIEWER, password_hash="x", is_active=True)
        db.add(reviewer)
        db.commit()
        db.refresh(reviewer)

        event = _make_event_with_article(db, source, "Ransomware campaign encrypts shared drives")
        from app.services.signal_service import SignalService
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=event.id, ai_response=_valid_ai_response(category="ransomware"))
        service.add_evidence(signal_id=signal.id, source_url="https://example.com/a", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id, reviewer_id=reviewer.id)
        service.publish_signal(signal.id, actor_id=reviewer.id)
        db.commit()

        pipeline = WeeklySignalPipeline(db, ai_service=MagicMock())
        result = pipeline.run()

        assert "ransomware" not in result["priority_categories"]
        assert "iam" in result["priority_categories"]  # still uncovered

    def test_priority_categories_key_always_present_even_with_zero_candidates(self, db: Session):
        """Coverage analysis runs even when there are no un-signaled events
        this cycle - it reflects real persisted state, not this run's
        candidate pool."""
        pipeline = WeeklySignalPipeline(db, ai_service=MagicMock())

        result = pipeline.run()

        assert "priority_categories" in result
        assert isinstance(result["priority_categories"], list)


class TestAISecurityStandingPriority:
    """Section 19: AI Security is a standing product priority - it always
    gets first claim on real candidate allocation, independent of whether
    it happens to already have current coverage, but this must never
    fabricate a candidate that doesn't exist."""

    def test_ai_security_stays_priority_even_when_already_covered(self, db: Session, source):
        """Every OTHER covered category drops out of priority_categories,
        but ai_security must remain - it is a standing priority, not just a
        coverage-gap trigger."""
        from app.db.models import User, UserRole
        from app.services.signal_service import SignalService

        reviewer = User(username="ai_priority_reviewer", email="ai_priority_reviewer@test.local",
                         role=UserRole.REVIEWER, password_hash="x", is_active=True)
        db.add(reviewer)
        db.commit()
        db.refresh(reviewer)

        service = SignalService(db)
        for category in ["insecure_design", "cloud_security", "iam", "app_api", "supply_chain",
                          "data_privacy", "ransomware", "threat_intel", "ai_security", "infrastructure"]:
            event = _make_event_with_article(db, source, f"Real event for {category}", f"A real event description for {category}.")
            signal = service.create_signal_from_ai(event_id=event.id, ai_response=_valid_ai_response(category=category))
            service.add_evidence(signal_id=signal.id, source_url=f"https://example.com/{category}", source_title="T", excerpt="E")
            service.submit_for_review(signal.id)
            service.approve_signal(signal.id, reviewer_id=reviewer.id)
            service.publish_signal(signal.id, actor_id=reviewer.id)
        db.commit()

        pipeline = WeeklySignalPipeline(db, ai_service=MagicMock())
        result = pipeline.run()

        # Every category now has real current coverage, so a coverage-gap
        # trigger alone would leave priority_categories empty - but
        # ai_security must still be present as a standing priority.
        assert result["priority_categories"] == ["ai_security"]

    def test_ai_security_priority_never_fabricates_without_real_candidates(self, db: Session):
        """With zero real AI-security candidates in the pool this run,
        ai_security being a standing priority must change nothing about
        what gets generated - no signal is invented to satisfy it."""
        pipeline = WeeklySignalPipeline(db, ai_service=MagicMock())

        result = pipeline.run()

        assert result["generated_count"] == 0
        assert "ai_security" in result["priority_categories"]
        assert result["category_counts"] == {}
