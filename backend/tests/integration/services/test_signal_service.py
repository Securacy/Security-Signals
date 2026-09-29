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


class _VisualLifecycleHarness:
    """Shared helpers for the DRAFT-time visual-generation lifecycle tests.
    These exercise the REAL SignalService, the REAL ThreatVisualService and
    the REAL background-job function
    (app/scheduler/visual_generation_job._generate_visual_sync) - only the
    actual network call at the very boundary (ImageProvider.generate) is
    faked, and the scheduler's queueing call is recorded instead of run."""

    @staticmethod
    def make_fake_provider(should_fail: bool = False):
        from app.intelligence.visual_service import ImageGenerationError, ImageProvider

        class _FakeProvider(ImageProvider):
            def __init__(self):
                self.calls = []

            def generate(self, prompt: str) -> bytes:
                self.calls.append(prompt)
                if should_fail:
                    raise ImageGenerationError("simulated OpenAI outage")
                return b"fake-openai-png-bytes"

        return _FakeProvider()

    @classmethod
    def wire_fake_provider(cls, monkeypatch, db, provider):
        """Makes ThreatVisualService.from_settings and
        visual_generation_job.SessionLocal use the fake provider and the
        real test database, without touching the real OpenAI/Bedrock
        account or the app's own SessionLocal (bound to the dev DB)."""
        from sqlalchemy.orm import Session as SQLASession
        from app.intelligence.visual_service import ThreatVisualService
        from app.scheduler import visual_generation_job

        def _fake_from_settings(cls_, settings):
            return ThreatVisualService(provider, media_root="/tmp/test-visual-media", media_url_prefix="/media")

        monkeypatch.setattr(ThreatVisualService, "from_settings", classmethod(_fake_from_settings))
        bind = db.get_bind()
        engine = getattr(bind, "engine", bind)
        monkeypatch.setattr(
            visual_generation_job, "SessionLocal",
            lambda: SQLASession(bind=engine, expire_on_commit=False),
        )

    @staticmethod
    def record_queueing(monkeypatch, scheduler_running: bool = True):
        """Record every visual-generation queue request instead of running
        it. Returns a list of (kind, signal_id) where kind is "scheduler"
        or "background" (the no-scheduler worker-thread fallback)."""
        from app.scheduler import visual_generation_job
        from app.scheduler.ingestion_scheduler import ingestion_scheduler

        queued = []

        def _schedule(signal_id):
            if not scheduler_running:
                return False
            queued.append(("scheduler", signal_id))
            return True

        monkeypatch.setattr(ingestion_scheduler, "schedule_visual_generation", _schedule)
        monkeypatch.setattr(
            visual_generation_job, "submit_visual_generation_in_background",
            lambda signal_id: queued.append(("background", signal_id)),
        )
        return queued

    @staticmethod
    def create_draft(db, security_event, title, description=None):
        response = AISignalGenerationResponse(
            signal_title=title,
            signal_description=description or f"A sufficiently long real description for {title}.",
            category="insecure_design", confidence=0.9,
            evidence_summary="Evidence grounded in real audit content.", secure_design_principles=[],
        )
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=response)
        service.add_evidence(signal_id=signal.id, source_url=f"https://example.com/{signal.id}",
                              source_title="T", excerpt="E")
        return service, signal


class TestVisualGenerationQueuedAtDraftCreation(_VisualLifecycleHarness):
    """The Signal-creation boundary (create_signal_from_ai) is where visual
    generation starts - not publication."""

    def test_creation_writes_a_pending_row_and_queues_the_job_only_after_commit(
        self, db: Session, security_event, monkeypatch,
    ):
        from app.db.models import SignalVisual, VisualStatus

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        queued = self.record_queueing(monkeypatch)

        service, signal = self.create_draft(db, security_event, "Brand New Draft Signal")

        # The PENDING marker is part of the SAME transaction as the Signal...
        row = db.query(SignalVisual).filter_by(signal_id=signal.id).one()
        assert row.status == VisualStatus.PENDING
        assert row.url is None
        assert signal.status == SignalStatus.DRAFT
        # ...but nothing is queued until that transaction has committed.
        assert queued == []
        db.commit()

        assert queued == [("scheduler", signal.id)]  # exactly once

    def test_creation_never_calls_the_provider_or_visual_service_inline(
        self, db: Session, security_event, ai_response, monkeypatch,
    ):
        from unittest.mock import MagicMock

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        queued = self.record_queueing(monkeypatch)
        mock_visual_service = MagicMock()

        service = SignalService(db, visual_service=mock_visual_service)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        db.commit()

        assert queued == [("scheduler", signal.id)]
        mock_visual_service.generate_for_signal.assert_not_called()

    def test_without_a_running_scheduler_creation_hands_off_to_a_background_worker_not_inline(
        self, db: Session, security_event, ai_response, monkeypatch,
    ):
        """Never blocks the ingestion loop: with no scheduler in this
        process the job goes to a background worker, never runs inline."""
        from unittest.mock import MagicMock

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        queued = self.record_queueing(monkeypatch, scheduler_running=False)
        mock_visual_service = MagicMock()

        service = SignalService(db, visual_service=mock_visual_service)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        db.commit()

        assert queued == [("background", signal.id)]
        mock_visual_service.generate_for_signal.assert_not_called()

    def test_disabled_generation_creates_no_row_and_queues_nothing(
        self, db: Session, security_event, ai_response, monkeypatch,
    ):
        from app.db.models import SignalVisual

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "false")
        queued = self.record_queueing(monkeypatch)

        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        db.commit()

        assert queued == []
        assert db.query(SignalVisual).filter_by(signal_id=signal.id).one_or_none() is None

    def test_a_rolled_back_signal_never_queues_or_keeps_a_visual(
        self, db: Session, security_event, ai_response, monkeypatch,
    ):
        from app.db.models import SignalVisual

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        queued = self.record_queueing(monkeypatch)

        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        signal_id = signal.id
        db.rollback()

        assert queued == []
        assert db.query(SignalVisual).filter_by(signal_id=signal_id).one_or_none() is None


class TestDraftVisualJobExecution(_VisualLifecycleHarness):
    def _draft_with_queued_job(self, db, security_event, monkeypatch, title, provider):
        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        monkeypatch.setenv("VISUAL_CONCEPT_AI_ENABLED", "false")  # isolate to image generation
        self.wire_fake_provider(monkeypatch, db, provider)
        queued = self.record_queueing(monkeypatch)
        service, signal = self.create_draft(db, security_event, title)
        db.commit()
        return service, signal, queued

    def test_the_queued_job_fulfils_the_pending_row_with_a_signal_specific_image(
        self, db: Session, security_event, monkeypatch,
    ):
        from app.db.models import SignalVisual, VisualStatus
        from app.scheduler.visual_generation_job import _generate_visual_sync

        provider = self.make_fake_provider()
        _, signal, queued = self._draft_with_queued_job(
            db, security_event, monkeypatch, "OAuth authorization flow permits privilege escalation", provider,
        )
        assert queued == [("scheduler", signal.id)]

        _generate_visual_sync(signal.id)  # the real function the scheduler would have run

        db.expire_all()
        rows = db.query(SignalVisual).filter_by(signal_id=signal.id).all()
        assert len(rows) == 1  # the PENDING row was fulfilled, not duplicated
        assert rows[0].status == VisualStatus.GENERATED
        assert rows[0].url is not None
        assert len(provider.calls) == 1
        assert "OAuth authorization flow permits privilege escalation" in provider.calls[0]

    def test_visual_prompts_differ_between_signals(self, db: Session, security_event, monkeypatch):
        from app.scheduler.visual_generation_job import _generate_visual_sync

        provider = self.make_fake_provider()
        _, a, _ = self._draft_with_queued_job(
            db, security_event, monkeypatch, "OAuth authorization flow permits privilege escalation", provider,
        )
        _, b, _ = self._draft_with_queued_job(
            db, security_event, monkeypatch, "Ransomware disrupts healthcare infrastructure resilience", provider,
        )
        _generate_visual_sync(a.id)
        _generate_visual_sync(b.id)

        assert len(provider.calls) == 2
        assert provider.calls[0] != provider.calls[1]
        assert "Ransomware" not in provider.calls[0]
        assert "OAuth" not in provider.calls[1]

    def test_provider_failure_marks_failed_never_fabricates_generated_and_stays_retryable(
        self, db: Session, security_event, monkeypatch,
    ):
        from app.db.models import SignalVisual, VisualStatus
        from app.intelligence.visual_service import ThreatVisualService, find_stale_visuals, regenerate_stale_visuals
        from app.config import get_settings
        from app.scheduler.visual_generation_job import _generate_visual_sync

        failing = self.make_fake_provider(should_fail=True)
        service, signal, _ = self._draft_with_queued_job(db, security_event, monkeypatch, "Outage Signal", failing)

        _generate_visual_sync(signal.id)  # must not raise
        db.expire_all()

        visual = db.query(SignalVisual).filter_by(signal_id=signal.id).one()
        assert visual.status == VisualStatus.FAILED
        assert visual.error is not None
        assert visual.url is None
        assert db.get(type(signal), signal.id).status == SignalStatus.DRAFT  # the signal itself is unaffected

        # Existing retry mechanism (regenerate_visuals.py) still picks it up.
        assert any(v.signal_id == signal.id for v in find_stale_visuals(db))
        self.wire_fake_provider(monkeypatch, db, self.make_fake_provider())
        summary = regenerate_stale_visuals(db, ThreatVisualService.from_settings(get_settings()))
        assert summary.regenerated == 1
        db.refresh(visual)
        assert visual.status == VisualStatus.GENERATED

    def test_running_the_job_twice_never_creates_duplicates_or_a_second_image(
        self, db: Session, security_event, monkeypatch,
    ):
        from app.db.models import SignalVisual
        from app.scheduler.visual_generation_job import _generate_visual_sync

        provider = self.make_fake_provider()
        _, signal, _ = self._draft_with_queued_job(db, security_event, monkeypatch, "Double Queued Signal", provider)

        _generate_visual_sync(signal.id)
        _generate_visual_sync(signal.id)

        db.expire_all()
        assert db.query(SignalVisual).filter_by(signal_id=signal.id).count() == 1
        assert len(provider.calls) == 1


class TestReviewTransitionsNeverRegenerateVisuals(_VisualLifecycleHarness):
    """DRAFT -> (visual) -> IN_REVIEW -> APPROVED -> PUBLISHED, and the
    reject branch: no review transition ever triggers another generation."""

    def _generated_draft(self, db, security_event, monkeypatch, title):
        from app.scheduler.visual_generation_job import _generate_visual_sync

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        monkeypatch.setenv("VISUAL_CONCEPT_AI_ENABLED", "false")
        provider = self.make_fake_provider()
        self.wire_fake_provider(monkeypatch, db, provider)
        queued = self.record_queueing(monkeypatch)
        service, signal = self.create_draft(db, security_event, title)
        db.commit()
        _generate_visual_sync(signal.id)
        db.expire_all()
        return service, signal, provider, queued

    def test_submit_approve_publish_trigger_no_further_generation(
        self, db: Session, security_event, test_reviewer, monkeypatch,
    ):
        from app.db.models import SignalVisual, VisualStatus

        service, signal, provider, queued = self._generated_draft(db, security_event, monkeypatch, "Full Lifecycle Signal")
        original_url = db.query(SignalVisual).filter_by(signal_id=signal.id).one().url
        assert queued == [("scheduler", signal.id)] and len(provider.calls) == 1

        service.submit_for_review(signal.id)
        db.commit()
        service.approve_signal(signal.id, reviewer_id=test_reviewer.id)
        db.commit()
        published = service.publish_signal(signal.id)
        db.commit()

        assert published.status == SignalStatus.PUBLISHED
        assert queued == [("scheduler", signal.id)]  # nothing new queued by submit/approve/publish
        assert len(provider.calls) == 1  # provider never called again
        visual = db.query(SignalVisual).filter_by(signal_id=signal.id).one()
        assert visual.status == VisualStatus.GENERATED and visual.url == original_url

    def test_rejection_leaves_the_persisted_visual_intact_and_regenerates_nothing(
        self, db: Session, security_event, test_reviewer, monkeypatch,
    ):
        from app.db.models import SignalVisual, VisualStatus

        service, signal, provider, queued = self._generated_draft(db, security_event, monkeypatch, "Rejected Signal")
        original = db.query(SignalVisual).filter_by(signal_id=signal.id).one()
        original_url, original_generated_at = original.url, original.generated_at

        service.submit_for_review(signal.id)
        db.commit()
        rejected = service.reject_signal(signal.id, reviewer_id=test_reviewer.id, reason="Not relevant")
        db.commit()

        assert rejected.status == SignalStatus.REJECTED
        assert queued == [("scheduler", signal.id)]
        assert len(provider.calls) == 1
        db.expire_all()
        visual = db.query(SignalVisual).filter_by(signal_id=signal.id).one()
        assert visual.status == VisualStatus.GENERATED
        assert visual.url == original_url and visual.generated_at == original_generated_at

    def test_a_current_version_generated_visual_is_never_auto_regenerated(
        self, db: Session, security_event, monkeypatch,
    ):
        from app.db.models import SignalVisual
        from app.intelligence.visual_service import ThreatVisualService, regenerate_stale_visuals
        from app.config import get_settings
        from app.scheduler.visual_generation_job import _generate_visual_sync

        service, signal, provider, _ = self._generated_draft(db, security_event, monkeypatch, "Already Current Signal")
        original_url = db.query(SignalVisual).filter_by(signal_id=signal.id).one().url

        summary = regenerate_stale_visuals(db, ThreatVisualService.from_settings(get_settings()))
        assert summary.considered == 0
        _generate_visual_sync(signal.id)  # a stray duplicate job

        db.expire_all()
        assert db.query(SignalVisual).filter_by(signal_id=signal.id).one().url == original_url
        assert len(provider.calls) == 1


class TestPublishTimeBackstopOnlyForLegacySignals(_VisualLifecycleHarness):
    """Publishing only ever queues generation for a legacy signal that has
    NO visual row at all (persisted before visuals were generated at DRAFT
    time). Any existing row - pending, generated or failed - means publish
    triggers nothing."""

    def _approve(self, service, signal, reviewer, db):
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id, reviewer_id=reviewer.id)
        db.commit()

    def test_publish_queues_generation_for_a_legacy_signal_with_no_visual_row(
        self, db: Session, security_event, test_reviewer, monkeypatch,
    ):
        from app.db.models import SignalVisual

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "false")  # legacy: created without a visual
        service, signal = self.create_draft(db, security_event, "Legacy Signal")
        db.commit()
        assert db.query(SignalVisual).filter_by(signal_id=signal.id).one_or_none() is None

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        queued = self.record_queueing(monkeypatch)
        self._approve(service, signal, test_reviewer, db)
        service.publish_signal(signal.id)
        assert queued == []  # never before commit
        db.commit()

        assert queued == [("scheduler", signal.id)]

    def test_publish_triggers_nothing_when_a_visual_row_already_exists_in_any_status(
        self, db: Session, security_event, test_reviewer, monkeypatch,
    ):
        from app.db.models import SignalVisual, VisualStatus

        for status in (VisualStatus.PENDING, VisualStatus.GENERATED, VisualStatus.FAILED):
            monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "false")
            service, signal = self.create_draft(db, security_event, f"Has {status.value} Visual")
            db.add(SignalVisual(signal_id=signal.id, status=status,
                                url="/media/signals/x.png" if status == VisualStatus.GENERATED else None))
            db.commit()

            monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
            queued = self.record_queueing(monkeypatch)
            self._approve(service, signal, test_reviewer, db)
            service.publish_signal(signal.id)
            db.commit()

            assert queued == [], f"publish must not queue generation for an existing {status.value} visual"

    def test_backstop_falls_back_to_inline_generation_only_when_no_scheduler_and_no_row(
        self, db: Session, security_event, test_reviewer, monkeypatch,
    ):
        from unittest.mock import MagicMock

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "false")
        service, signal = self.create_draft(db, security_event, "Legacy Inline Signal")
        db.commit()

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        self.record_queueing(monkeypatch, scheduler_running=False)
        mock_visual_service = MagicMock()
        service = SignalService(db, visual_service=mock_visual_service)
        self._approve(service, signal, test_reviewer, db)

        service.publish_signal(signal.id)
        mock_visual_service.generate_for_signal.assert_not_called()  # only after commit
        db.commit()
        mock_visual_service.generate_for_signal.assert_called_once()

    def test_visual_failure_at_publish_never_blocks_publication(
        self, db: Session, security_event, test_reviewer, monkeypatch,
    ):
        from unittest.mock import MagicMock

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "false")
        service, signal = self.create_draft(db, security_event, "Legacy Failing Signal")
        db.commit()

        monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "true")
        self.record_queueing(monkeypatch, scheduler_running=False)
        mock_visual_service = MagicMock()
        mock_visual_service.generate_for_signal.side_effect = RuntimeError("total visual service failure")
        service = SignalService(db, visual_service=mock_visual_service)
        self._approve(service, signal, test_reviewer, db)

        published = service.publish_signal(signal.id)  # must not raise
        db.commit()  # must not raise either

        assert published.status == SignalStatus.PUBLISHED
