"""Integration tests for SignalService with real PostgreSQL."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.services.signal_service import SignalService
from app.intelligence.schemas.signal_request import AISignalGenerationResponse, SecureDesignPrinciple
from app.db.models import SignalStatus, SecurityCategoryType, User, UserRole
from app.common.errors import NotFoundError, DatabaseError


@pytest.fixture
def ai_response():
    """Valid AI response for testing."""
    return AISignalGenerationResponse(
        signal_title="Critical Apache RCE",
        signal_description="Critical remote code execution requiring immediate patch for Apache HTTP Server",
        category="insecure_design",
        ai_subcategory=None,
        confidence=0.95,
        evidence_summary="Apache released security update for CVE-2024-12345",
        secure_design_principles=[]
    )


@pytest.fixture
def test_reviewer(db: Session):
    """Create test reviewer user."""
    user = User(
        username="reviewer",
        email="reviewer@example.com",
        role=UserRole.REVIEWER,
        password_hash="hashed_password",
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


class TestSignalServiceCreation:
    """Signal creation tests."""
    
    def test_create_signal_from_ai_valid(self, db: Session, security_event, ai_response):
        """Create DRAFT signal from AI response."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        assert signal.id is not None
        assert signal.event_id == security_event.id
        assert signal.status == SignalStatus.DRAFT
        assert signal.title == ai_response.signal_title
        assert signal.summary == ai_response.signal_description
        assert signal.ai_generated_at is not None
        assert len(signal.categories) == 1
        assert signal.categories[0].category == SecurityCategoryType.INSECURE_DESIGN
    
    def test_create_signal_persists_ai_principles_and_recommended_action(
        self, db: Session, security_event
    ):
        """Regression test: previously, Signal.principle and
        Signal.recommended_action were always the hardcoded placeholder
        text, discarding the AI's validated secure_design_principles
        entirely. They must now be derived from that real, already-Pydantic
        -validated data instead."""
        ai_response = AISignalGenerationResponse(
            signal_title="Critical Apache RCE",
            signal_description="Critical remote code execution requiring immediate patch for Apache HTTP Server",
            category="insecure_design",
            ai_subcategory=None,
            confidence=0.95,
            evidence_summary="Apache released security update for CVE-2024-12345",
            secure_design_principles=[
                SecureDesignPrinciple(
                    principle="Input Validation",
                    connection="Unvalidated request parameters allow RCE",
                    confidence=0.9,
                ),
                SecureDesignPrinciple(
                    principle="Defense in Depth",
                    connection="No secondary control blocks the exploit chain",
                    confidence=0.8,
                ),
            ],
        )
        service = SignalService(db)

        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response,
        )

        assert signal.principle == "Input Validation; Defense in Depth"
        assert "Input Validation: Unvalidated request parameters allow RCE" in signal.recommended_action
        assert "Defense in Depth: No secondary control blocks the exploit chain" in signal.recommended_action
        # Not the old discarded-data placeholders:
        assert signal.principle != "AI-Generated Security Principle"
        assert signal.recommended_action != "Review and validate signal"

        # Persisted for real, not just held on the in-memory object.
        db.commit()
        db.refresh(signal)
        assert signal.principle == "Input Validation; Defense in Depth"

    def test_create_signal_falls_back_to_placeholder_when_no_principles(
        self, db: Session, security_event, ai_response
    ):
        """The `ai_response` fixture has secure_design_principles=[] - an
        empty list is valid per the schema, not an error - so the original
        placeholder text must still be used in that case."""
        service = SignalService(db)

        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response,
        )

        assert signal.principle == "AI-Generated Security Principle"
        assert signal.recommended_action == "Review and validate signal"

    def test_create_signal_invalid_event(self, db: Session, ai_response):
        """Reject creation with nonexistent event."""
        service = SignalService(db)
        
        with pytest.raises(NotFoundError) as exc:
            service.create_signal_from_ai(
                event_id=uuid4(),
                ai_response=ai_response
            )
        assert "not found" in str(exc.value).lower()
    
    def test_signal_never_directly_published(self, db: Session, security_event, ai_response):
        """Verify AI output creates DRAFT signal, not PUBLISHED."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        # Must be DRAFT, never PUBLISHED
        assert signal.status == SignalStatus.DRAFT
        assert signal.published_at is None


class TestSignalServiceEvidence:
    """Evidence management tests."""
    
    def test_add_evidence(self, db: Session, security_event, ai_response):
        """Add evidence to signal."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        evidence = service.add_evidence(
            signal_id=signal.id,
            source_url="https://apache.org/advisory.html",
            source_title="Apache Security Advisory",
            excerpt="Apache HTTP Server 2.4.x vulnerable to RCE"
        )
        
        assert evidence.id is not None
        assert evidence.signal_id == signal.id
        assert evidence.source_url == "https://apache.org/advisory.html"
    
    def test_add_evidence_nonexistent_signal(self, db: Session):
        """Reject evidence for nonexistent signal."""
        service = SignalService(db)
        
        with pytest.raises(NotFoundError):
            service.add_evidence(
                signal_id=uuid4(),
                source_url="https://example.com",
                source_title="Title",
                excerpt="Excerpt"
            )


class TestSignalServiceLifecycle:
    """Signal lifecycle state transition tests."""
    
    def test_submit_for_review_success(self, db: Session, security_event, ai_response):
        """Submit DRAFT signal to IN_REVIEW."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        # Add evidence first
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com",
            source_title="Title",
            excerpt="Excerpt"
        )
        
        updated = service.submit_for_review(signal.id)
        
        assert updated.status == SignalStatus.IN_REVIEW
    
    def test_submit_for_review_requires_evidence(self, db: Session, security_event, ai_response):
        """Reject submission without evidence."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        # Don't add evidence
        with pytest.raises(ValueError) as exc:
            service.submit_for_review(signal.id)
        assert "evidence" in str(exc.value).lower()
    
    def test_submit_for_review_invalid_status(self, db: Session, security_event, ai_response):
        """Reject submission if not DRAFT."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        # Add evidence
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com",
            source_title="Title",
            excerpt="Excerpt"
        )
        
        # Move to IN_REVIEW
        service.submit_for_review(signal.id)
        
        # Try to submit again
        with pytest.raises(ValueError) as exc:
            service.submit_for_review(signal.id)
        assert "DRAFT" in str(exc.value)
    
    def test_approve_signal_success(self, db: Session, security_event, ai_response, test_reviewer):
        """Move IN_REVIEW signal to APPROVED."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com",
            source_title="Title",
            excerpt="Excerpt"
        )
        
        service.submit_for_review(signal.id)
        
        approved = service.approve_signal(signal.id, reviewer_id=test_reviewer.id)
        
        assert approved.status == SignalStatus.APPROVED
        assert approved.reviewed_at is not None
        assert approved.reviewed_by == test_reviewer.id
    
    def test_approve_requires_in_review(self, db: Session, security_event, ai_response):
        """Cannot approve DRAFT signal."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        with pytest.raises(ValueError) as exc:
            service.approve_signal(signal.id)
        assert "IN_REVIEW" in str(exc.value)
    
    def test_reject_signal_success(self, db: Session, security_event, ai_response, test_reviewer):
        """Move IN_REVIEW signal to REJECTED."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com",
            source_title="Title",
            excerpt="Excerpt"
        )
        
        service.submit_for_review(signal.id)
        rejected = service.reject_signal(signal.id, reviewer_id=test_reviewer.id)
        
        assert rejected.status == SignalStatus.REJECTED
        assert rejected.reviewed_at is not None
        assert rejected.reviewed_by == test_reviewer.id
    
    def test_publish_success(self, db: Session, security_event, ai_response, test_reviewer):
        """Move APPROVED signal to PUBLISHED."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com",
            source_title="Title",
            excerpt="Excerpt"
        )
        
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id, reviewer_id=test_reviewer.id)
        
        published = service.publish_signal(signal.id)
        
        assert published.status == SignalStatus.PUBLISHED
        assert published.published_at is not None
    
    def test_publish_requires_approved(self, db: Session, security_event, ai_response):
        """Cannot publish non-APPROVED signal."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        with pytest.raises(ValueError) as exc:
            service.publish_signal(signal.id)
        assert "APPROVED" in str(exc.value)


class TestSignalServiceRetrieval:
    """Signal retrieval and filtering tests."""
    
    def test_get_signal(self, db: Session, security_event, ai_response):
        """Retrieve signal by ID."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        retrieved = service.get_signal(signal.id)
        
        assert retrieved is not None
        assert retrieved.id == signal.id
        assert retrieved.title == signal.title
    
    def test_get_published_signals(self, db: Session, security_event, ai_response, test_reviewer):
        """List only published signals."""
        service = SignalService(db)
        
        # Create multiple signals
        signal1 = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        signal2 = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        # Publish only signal1
        service.add_evidence(signal_id=signal1.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal1.id)
        service.approve_signal(signal1.id, reviewer_id=test_reviewer.id)
        service.publish_signal(signal1.id)
        
        # Retrieve published
        published = service.get_published_signals()
        
        assert len(published) >= 1
        assert any(s.id == signal1.id for s in published)
        assert not any(s.id == signal2.id for s in published)  # signal2 still DRAFT


class TestSignalServiceVisualGenerationWiring:
    """Publish-time visual generation (Section 15 of the taxonomy/visuals
    spec): SignalService.publish_signal() triggers ThreatVisualService
    exactly once per signal, and its failure never blocks publication."""

    def test_publish_triggers_visual_generation_with_a_mocked_service(
        self, db: Session, security_event, ai_response, test_reviewer, monkeypatch,
    ):
        from unittest.mock import MagicMock
        from app.db.models import SignalVisual, VisualStatus

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        mock_visual_service = MagicMock()

        def _fake_generate(session, signal, public_categories):
            visual = SignalVisual(signal_id=signal.id, status=VisualStatus.GENERATED, url="/media/signals/fake.png")
            session.add(visual)
            session.flush()
            return visual

        mock_visual_service.generate_for_signal.side_effect = _fake_generate

        service = SignalService(db, visual_service=mock_visual_service)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id, reviewer_id=test_reviewer.id)

        published = service.publish_signal(signal.id)

        assert published.status == SignalStatus.PUBLISHED  # publish itself succeeded
        mock_visual_service.generate_for_signal.assert_called_once()
        call_args = mock_visual_service.generate_for_signal.call_args
        assert call_args[0][1].id == signal.id
        assert call_args[0][2] == ["product_security"]  # insecure_design -> product_security

        visual = db.query(SignalVisual).filter_by(signal_id=signal.id).one()
        assert visual.status == VisualStatus.GENERATED

    def test_visual_generation_failure_does_not_block_publication(
        self, db: Session, security_event, ai_response, test_reviewer, monkeypatch,
    ):
        from unittest.mock import MagicMock

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        mock_visual_service = MagicMock()
        mock_visual_service.generate_for_signal.side_effect = RuntimeError("simulated total visual service failure")

        service = SignalService(db, visual_service=mock_visual_service)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id, reviewer_id=test_reviewer.id)

        published = service.publish_signal(signal.id)  # must not raise

        assert published.status == SignalStatus.PUBLISHED
        assert published.published_at is not None

    def test_publish_queues_a_background_job_instead_of_generating_inline_when_scheduler_is_running(
        self, db: Session, security_event, ai_response, test_reviewer, monkeypatch,
    ):
        """When the application's background scheduler is active, publish
        must queue the visual job and return immediately - it must NOT
        call the (potentially slow, real-Bedrock-backed) visual service
        synchronously on the publish request itself."""
        from unittest.mock import MagicMock
        from app.scheduler.ingestion_scheduler import ingestion_scheduler

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        mock_visual_service = MagicMock()
        queued_signal_ids = []
        monkeypatch.setattr(
            ingestion_scheduler, "schedule_visual_generation",
            lambda signal_id: (queued_signal_ids.append(signal_id), True)[1],
        )

        service = SignalService(db, visual_service=mock_visual_service)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id, reviewer_id=test_reviewer.id)

        published = service.publish_signal(signal.id)

        assert published.status == SignalStatus.PUBLISHED
        assert queued_signal_ids == [signal.id]
        mock_visual_service.generate_for_signal.assert_not_called()  # never run inline

    def test_publish_falls_back_to_inline_generation_when_queueing_fails(
        self, db: Session, security_event, ai_response, test_reviewer, monkeypatch,
    ):
        """If schedule_visual_generation reports it could not queue the
        job (scheduler not running), publish still attempts generation
        inline rather than silently never generating a visual at all."""
        from unittest.mock import MagicMock
        from app.scheduler.ingestion_scheduler import ingestion_scheduler

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        mock_visual_service = MagicMock()
        monkeypatch.setattr(ingestion_scheduler, "schedule_visual_generation", lambda signal_id: False)

        service = SignalService(db, visual_service=mock_visual_service)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id, reviewer_id=test_reviewer.id)

        service.publish_signal(signal.id)

        mock_visual_service.generate_for_signal.assert_called_once()

    def test_visual_generation_skipped_entirely_when_disabled(
        self, db: Session, security_event, ai_response, test_reviewer, monkeypatch,
    ):
        from unittest.mock import MagicMock
        from app.db.models import SignalVisual

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "false")
        mock_visual_service = MagicMock()

        service = SignalService(db, visual_service=mock_visual_service)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id, reviewer_id=test_reviewer.id)

        service.publish_signal(signal.id)

        mock_visual_service.generate_for_signal.assert_not_called()
        assert db.query(SignalVisual).filter_by(signal_id=signal.id).one_or_none() is None
