"""Signal service layer - business logic for signal lifecycle."""
from typing import Optional, List
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy import event
from sqlalchemy.orm import Session
import logging

from app.db.models import (
    Signal, SignalStatus, SignalCategory, Evidence, SecurityEvent,
    SecurityCategoryType, SignalVisual, User
)
from app.repositories import (
    SignalRepository, SignalCategoryRepository, EvidenceRepository,
    SecurityEventRepository, AuditLogRepository
)
from app.intelligence.schemas.signal_request import AISignalGenerationResponse
from app.intelligence.visual_service import ThreatVisualService, create_pending_visual
from app.common.errors import NotFoundError, DatabaseError
from app.ingestion.freshness_policy import FreshnessPolicy
from app.taxonomy import internal_categories_to_public

logger = logging.getLogger(__name__)

# Fallback text used only when the AI genuinely returned zero secure design
# principles (an empty list is valid per AISignalGenerationResponse's
# schema - not an error case).
_PLACEHOLDER_PRINCIPLE = "AI-Generated Security Principle"
_PLACEHOLDER_RECOMMENDED_ACTION = "Review and validate signal"

# Matches Signal.principle: Column(String(500), ...) in app/db/models.py.
_SIGNAL_PRINCIPLE_MAX_LENGTH = 500


def _map_principle_and_recommended_action(
    ai_response: AISignalGenerationResponse,
) -> tuple[str, str]:
    """Derive Signal.principle and Signal.recommended_action from the AI's
    validated secure_design_principles, instead of discarding them behind a
    hardcoded placeholder.

    Uses only data Pydantic has already validated on the response - each
    SecureDesignPrinciple's `principle` and `connection` are required,
    non-empty fields - so this persists real AI output rather than
    fabricating anything new. Falls back to the original placeholder text
    only when the AI returned no principles at all.
    """
    principles = ai_response.secure_design_principles
    if not principles:
        return _PLACEHOLDER_PRINCIPLE, _PLACEHOLDER_RECOMMENDED_ACTION

    principle_text = "; ".join(p.principle for p in principles)
    if len(principle_text) > _SIGNAL_PRINCIPLE_MAX_LENGTH:
        principle_text = principle_text[: _SIGNAL_PRINCIPLE_MAX_LENGTH - 1].rstrip() + "…"

    recommended_action = " ".join(f"{p.principle}: {p.connection}" for p in principles)

    return principle_text, recommended_action


class SignalService:
    """Service for managing signals across their lifecycle."""
    
    def __init__(
        self,
        session: Session,
        freshness_policy: Optional[FreshnessPolicy] = None,
        visual_service: Optional[ThreatVisualService] = None,
    ):
        self.session = session
        self.signal_repo = SignalRepository(session)
        self.category_repo = SignalCategoryRepository(session)
        self.evidence_repo = EvidenceRepository(session)
        self.event_repo = SecurityEventRepository(session)
        self.audit_repo = AuditLogRepository(session)
        if freshness_policy is None:
            from app.config import get_settings
            freshness_policy = FreshnessPolicy.from_settings(get_settings())
        self.freshness_policy = freshness_policy
        self._visual_service = visual_service

    def _get_visual_service(self) -> ThreatVisualService:
        """Lazily build the production visual service (provider selected
        by settings.image_provider - OpenAI by default, Bedrock available)
        only when actually needed, so constructing a SignalService for
        tests that never publish never requires real provider credentials."""
        if self._visual_service is None:
            from app.config import get_settings
            self._visual_service = ThreatVisualService.from_settings(get_settings())
        return self._visual_service
    
    def _audit_signal_action(
        self,
        signal_id: UUID,
        action: str,
        reviewer_id: Optional[UUID],
        changes: dict
    ) -> None:
        """
        Create an audit log entry for a signal lifecycle action.
        
        Audit entry is created in the SAME transaction as the signal state change.
        If audit creation fails, the exception propagates and the transaction rolls back.
        This ensures signal state changes and their audit trails are atomic.
        
        Args:
            signal_id: ID of the signal
            action: Audit action (e.g., "SIGNAL_APPROVED", "SIGNAL_PUBLISHED")
            reviewer_id: User ID who performed the action (may be None)
            changes: Dictionary of state changes to record
        
        Raises:
            DatabaseError: If audit entry creation fails (transaction will rollback)
        """
        try:
            self.audit_repo.create(
                user_id=reviewer_id,
                action=action,
                resource_type="SIGNAL",
                resource_id=signal_id,
                changes=changes
            )
            self.session.flush()
        except Exception as e:
            # Do NOT catch and continue. Audit failure means transaction must fail.
            logger.error(f"Failed to create audit entry for {action}: {e}")
            raise DatabaseError(f"Failed to create audit log for {action}: {e}")
    
    def create_signal_from_ai(
        self,
        event_id: UUID,
        ai_response: AISignalGenerationResponse
    ) -> Signal:
        """
        Create a DRAFT signal from AI-generated response.
        
        Maps Phase 4 AI output to Phase 2 Signal canonical model:
        - AI signal_title → Signal title
        - AI signal_description → Signal summary AND security_impact
        - AI category → SignalCategory
        - AI secure_design_principles → Signal principle and
          recommended_action (see _map_principle_and_recommended_action) -
          falls back to placeholder text only if the AI returned none.

        AI output is NEVER directly published.
        Signal starts in DRAFT status, must go through review.
        
        Args:
            event_id: SecurityEvent this signal is derived from
            ai_response: Validated AISignalGenerationResponse from Phase 4
        
        Returns:
            Signal in DRAFT status with categories
        
        Raises:
            NotFoundError: If event_id doesn't exist
            DatabaseError: If database operation fails
        """
        # Verify event exists
        event = self.event_repo.get_by_id(event_id)
        if not event:
            raise NotFoundError(f"SecurityEvent {event_id} not found")
        
        try:
            # Create signal in DRAFT status
            # Map AI output to canonical Signal fields (Phase 2)
            principle, recommended_action = _map_principle_and_recommended_action(ai_response)
            signal = self.signal_repo.create(
                event_id=event_id,
                title=ai_response.signal_title,
                summary=ai_response.signal_description,
                security_impact=ai_response.signal_description,
                principle=principle,
                recommended_action=recommended_action,
                status=SignalStatus.DRAFT,
                ai_generated_at=datetime.now(timezone.utc),
                reviewed_by=None  # No reviewer yet
            )
            
            # Create signal category from AI response
            category_name = ai_response.category.upper()
            if hasattr(SecurityCategoryType, category_name):
                category_enum = getattr(SecurityCategoryType, category_name)
            else:
                raise ValueError(f"Invalid category: {ai_response.category}")
            
            category = self.category_repo.create(
                signal_id=signal.id,
                category=category_enum,
                subcategory=ai_response.ai_subcategory,
                confidence=ai_response.confidence,
                assigned_by="AI"
            )
            
            self.session.flush()
            logger.info(f"Created DRAFT signal {signal.id} from AI for event {event_id}")

            # Signal-specific visual generation starts NOW, at DRAFT
            # persistence, not at publication - so the visual is (usually)
            # ready by the time a human reviews the signal. The PENDING
            # SignalVisual row is written in this SAME transaction as the
            # Signal (atomic with it - the reviewer UI can always tell
            # "generating" apart from "never queued"), and the actual
            # provider call is only ever queued as a background job AFTER
            # this transaction commits. Never generated inline: signal
            # creation (and therefore the ingestion loop) never waits on
            # an image provider.
            self._register_visual_generation_at_creation(signal.id)

            return signal
        
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to create signal from AI: {e}")
            raise DatabaseError(f"Failed to create signal: {e}")
    
    def add_evidence(
        self,
        signal_id: UUID,
        source_url: str,
        source_title: str,
        excerpt: str
    ) -> Evidence:
        """Add evidence to a signal (immutable once created)."""
        signal = self.signal_repo.get_by_id(signal_id)
        if not signal:
            raise NotFoundError(f"Signal {signal_id} not found")
        
        try:
            evidence = self.evidence_repo.create(
                signal_id=signal_id,
                source_url=source_url,
                source_title=source_title,
                excerpt=excerpt
            )
            self.session.flush()
            logger.info(f"Added evidence to signal {signal_id}")
            return evidence
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to add evidence: {e}")
            raise DatabaseError(f"Failed to add evidence: {e}")
    
    def submit_for_review(self, signal_id: UUID, actor_id: Optional[UUID] = None) -> Signal:
        """
        Move signal from DRAFT to IN_REVIEW.

        REQUIREMENT: Signal must have at least one evidence record.

        Args:
            signal_id: Signal to submit
            actor_id: User ID of the authenticated user performing the
                submission, recorded on the audit entry (may be None for
                internal/non-HTTP callers).

        Returns:
            Updated signal in IN_REVIEW status

        Raises:
            NotFoundError: If signal not found
            ValueError: If signal not in DRAFT status or missing evidence
            DatabaseError: If database operation fails
        """
        signal = self.signal_repo.get_by_id(signal_id)
        if not signal:
            raise NotFoundError(f"Signal {signal_id} not found")

        if signal.status != SignalStatus.DRAFT:
            raise ValueError(f"Can only submit DRAFT signals. Current status: {signal.status}")

        # Verify at least one evidence record exists
        if not signal.evidence or len(signal.evidence) == 0:
            raise ValueError(f"Signal must have at least one evidence record before review")

        try:
            # Create audit entry BEFORE state change
            self._audit_signal_action(
                signal_id=signal_id,
                action="SIGNAL_SUBMITTED_FOR_REVIEW",
                reviewer_id=actor_id,
                changes={"status_from": SignalStatus.DRAFT.value, "status_to": SignalStatus.IN_REVIEW.value}
            )
            
            updated = self.signal_repo.update(
                signal_id,
                status=SignalStatus.IN_REVIEW
            )
            self.session.flush()
            logger.info(f"Moved signal {signal_id} to IN_REVIEW")
            return updated
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to submit signal for review: {e}")
            raise DatabaseError(f"Failed to submit for review: {e}")
    
    def approve_signal(
        self,
        signal_id: UUID,
        reviewer_id: Optional[UUID] = None
    ) -> Signal:
        """
        Approve a signal, moving it from IN_REVIEW to APPROVED.
        
        Args:
            signal_id: Signal to approve
            reviewer_id: User ID of reviewer (Phase 6 auth placeholder)
        
        Returns:
            Updated signal in APPROVED status
        
        Raises:
            NotFoundError: If signal not found
            ValueError: If signal not in IN_REVIEW status
            DatabaseError: If database operation fails
        """
        signal = self.signal_repo.get_by_id(signal_id)
        if not signal:
            raise NotFoundError(f"Signal {signal_id} not found")
        
        if signal.status != SignalStatus.IN_REVIEW:
            raise ValueError(f"Can only approve IN_REVIEW signals. Current status: {signal.status}")
        
        try:
            # Create audit entry BEFORE state change
            self._audit_signal_action(
                signal_id=signal_id,
                action="SIGNAL_APPROVED",
                reviewer_id=reviewer_id,
                changes={
                    "status_from": SignalStatus.IN_REVIEW.value,
                    "status_to": SignalStatus.APPROVED.value,
                    "reviewed_by": str(reviewer_id) if reviewer_id else None
                }
            )
            
            updated = self.signal_repo.update(
                signal_id,
                status=SignalStatus.APPROVED,
                reviewed_by=reviewer_id,
                reviewed_at=datetime.now(timezone.utc)
            )
            self.session.flush()
            logger.info(f"Approved signal {signal_id}")
            return updated
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to approve signal: {e}")
            raise DatabaseError(f"Failed to approve signal: {e}")
    
    def reject_signal(
        self,
        signal_id: UUID,
        reviewer_id: Optional[UUID] = None,
        reason: Optional[str] = None
    ) -> Signal:
        """
        Reject a signal, moving it from IN_REVIEW to REJECTED.

        Args:
            signal_id: Signal to reject
            reviewer_id: User ID of reviewer (Phase 6 auth placeholder)
            reason: Optional review note explaining the rejection, recorded
                on the audit entry (never on the Signal row itself)

        Returns:
            Updated signal in REJECTED status

        Raises:
            NotFoundError: If signal not found
            ValueError: If signal not in IN_REVIEW status
            DatabaseError: If database operation fails
        """
        signal = self.signal_repo.get_by_id(signal_id)
        if not signal:
            raise NotFoundError(f"Signal {signal_id} not found")

        if signal.status != SignalStatus.IN_REVIEW:
            raise ValueError(f"Can only reject IN_REVIEW signals. Current status: {signal.status}")

        try:
            # Create audit entry BEFORE state change
            self._audit_signal_action(
                signal_id=signal_id,
                action="SIGNAL_REJECTED",
                reviewer_id=reviewer_id,
                changes={
                    "status_from": SignalStatus.IN_REVIEW.value,
                    "status_to": SignalStatus.REJECTED.value,
                    "reviewed_by": str(reviewer_id) if reviewer_id else None,
                    "reason": reason
                }
            )
            
            updated = self.signal_repo.update(
                signal_id,
                status=SignalStatus.REJECTED,
                reviewed_by=reviewer_id,
                reviewed_at=datetime.now(timezone.utc)
            )
            self.session.flush()
            logger.info(f"Rejected signal {signal_id}")
            return updated
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to reject signal: {e}")
            raise DatabaseError(f"Failed to reject signal: {e}")
    
    def publish_signal(self, signal_id: UUID, actor_id: Optional[UUID] = None) -> Signal:
        """
        Publish a signal, moving it from APPROVED to PUBLISHED.

        REQUIREMENT: Signal must be in APPROVED status.

        Args:
            signal_id: Signal to publish
            actor_id: User ID of the authenticated user performing the
                publish action, recorded on the audit entry (may be None
                for internal/non-HTTP callers). Not written to
                Signal.reviewed_by - that field tracks the reviewer from
                approve/reject, not the publisher.

        Returns:
            Updated signal in PUBLISHED status

        Raises:
            NotFoundError: If signal not found
            ValueError: If signal not in APPROVED status
            DatabaseError: If database operation fails
        """
        signal = self.signal_repo.get_by_id(signal_id)
        if not signal:
            raise NotFoundError(f"Signal {signal_id} not found")

        if signal.status != SignalStatus.APPROVED:
            raise ValueError(f"Can only publish APPROVED signals. Current status: {signal.status}")

        try:
            # Create audit entry BEFORE state change
            self._audit_signal_action(
                signal_id=signal_id,
                action="SIGNAL_PUBLISHED",
                reviewer_id=actor_id,
                changes={
                    "status_from": SignalStatus.APPROVED.value,
                    "status_to": SignalStatus.PUBLISHED.value,
                    "published_at": datetime.now(timezone.utc).isoformat()
                }
            )

            updated = self.signal_repo.update(
                signal_id,
                status=SignalStatus.PUBLISHED,
                published_at=datetime.now(timezone.utc),
                is_current=True,
            )
            self.session.flush()

            # Current-feed retention (Feature 2 / Feature 1 "week 2"
            # behavior): this newly-published signal takes a "current" slot
            # in each of its categories. If that pushes a category over its
            # configured retention count, retire the OLDEST excess current
            # signals in that category to historical - never delete them,
            # and this only ever runs as a side effect of a successful new
            # publish, so a category can never be emptied by this step
            # (there is always at least one current signal left: the one
            # that just triggered the retirement).
            self._retire_superseded_current_signals(updated)

            logger.info(f"Published signal {signal_id}")
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to publish signal: {e}")
            raise DatabaseError(f"Failed to publish signal: {e}")

        # Signal-specific visual generation must only ever be queued once
        # this signal's PUBLISH is durably COMMITTED - see
        # _queue_visual_generation_after_commit's docstring for why a
        # naive "queue it right here" (this method only flush()es; the
        # caller, typically FastAPI's get_db(), commits afterward) is a
        # real race against the background job's own separate DB
        # connection, not just a theoretical one.
        self._queue_visual_generation_after_commit(updated.id)

        return updated

    def _register_visual_generation_at_creation(self, signal_id: UUID) -> None:
        """Called from create_signal_from_ai (the single Signal-creation
        boundary). No-op when visual generation is disabled. Otherwise: (1)
        flush a PENDING SignalVisual row in the caller's transaction, and
        (2) arrange, exactly once and only after that transaction has
        durably COMMITTED, for the generation job to be queued (see
        _queue_visual_generation_after_commit for why "after commit" is
        essential). Failure here is logged and never fails signal
        creation."""
        try:
            from app.config import get_settings
            if not get_settings().visual_generation_enabled:
                return
            # SAVEPOINT: a failure writing the visual marker must never
            # poison the transaction that persists the Signal itself.
            with self.session.begin_nested():
                create_pending_visual(self.session, signal_id)
            self._queue_visual_generation_after_commit(signal_id, background_only=True)
        except Exception as e:
            logger.warning(f"visual_generation_registration_failed signal_id={signal_id} error={e}")

    def _queue_visual_generation_after_commit(self, signal_id: UUID, background_only: bool = False) -> None:
        """Arrange for signal-specific visual generation to be triggered
        exactly once this signal's enclosing transaction has actually
        COMMITTED at the database level - never before, and never at all
        if the transaction is later rolled back.

        Two callers:
          - create_signal_from_ai (background_only=True): the normal path.
            The job is queued on the scheduler, or - if no scheduler is
            running in this process - handed to a background worker
            thread; it is NEVER generated inline, so signal creation and
            the ingestion loop never block on the image provider.
          - publish_signal (background_only=False): a BACKSTOP only, for
            legacy signals persisted before visuals were generated at
            DRAFT time. If a SignalVisual row already exists (pending,
            generated, or failed) publishing triggers nothing at all.

        Registers a one-shot SQLAlchemy `after_commit` listener rather
        than acting immediately, because this method only ever runs
        inside publish_signal() BEFORE the caller's own commit (this
        service flushes, never commits - the caller, typically FastAPI's
        get_db(), owns the transaction boundary so a whole request stays
        atomic). SQLAlchemy fires `after_commit` strictly after the real
        DBAPI-level COMMIT has been issued, which is the only point at
        which:
          - a background job scheduled to run "as soon as possible" (see
            app/scheduler/ingestion_scheduler.schedule_visual_generation's
            DateTrigger()) is guaranteed to find the signal when it
            queries for it on its OWN, separate DB connection (before
            that point, an eager job could race ahead of this request's
            own commit and see nothing - not an error, just a silently
            never-retried missed visual).
          - a signal that ends up rolled back (an error elsewhere in the
            same request, after publish_signal() returns) can never have
            already triggered generation - `after_commit` simply never
            fires when a session rolls back instead of committing.

        Deliberately wrapped in its own try/except: image-generation
        failure (or being disabled, or the queueing itself failing) must
        NEVER unpublish or fail an otherwise-valid publish action - and
        critically, since this callback runs as part of the caller's own
        session.commit() call, an uncaught exception here would propagate
        out of that commit() and could make an already-successful publish
        look like a failure to the caller.

        One-shot via a closure guard, NOT via event.remove() inside the
        callback: SQLAlchemy's own event.listen() docs are explicit that
        "an event cannot be added [or removed] from inside the listener
        function for itself" - the listener list is a mutable collection
        being iterated live while callbacks run, and removing from it
        there raises "RuntimeError: deque mutated during iteration". A
        plain closure flag makes this callback idempotent instead, which
        is enough for the realistic case (one request/session = one
        commit, e.g. FastAPI's get_db()) - a session that goes on to
        commit again later for unrelated work would just no-op this
        already-fired callback rather than re-run it.
        """
        session = self.session
        # session.get_bind() returns the session's currently CHECKED-OUT
        # Connection (not the Engine) whenever a transaction is already
        # in flight - true here, since publish_signal's own flush()es
        # keep one open the whole time. Resolving to the underlying
        # Engine (Connection.engine, or the bind itself if it's already
        # an Engine) is essential: the fallback path below builds an
        # INDEPENDENT Session from this `bind` and closes it when done -
        # binding that independent Session to the ORIGINAL session's live
        # Connection instead would close that shared connection out from
        # under `session` too, detaching it from its own transaction.
        bind = session.get_bind()
        engine = getattr(bind, "engine", bind)
        already_fired = False

        def _on_commit(_sess: Session) -> None:
            nonlocal already_fired
            if already_fired:
                return
            already_fired = True
            try:
                from app.config import get_settings
                if not get_settings().visual_generation_enabled:
                    return

                if not background_only:
                    # Publish-time backstop: never trigger another
                    # generation when a visual row already exists.
                    check_session = Session(bind=engine)
                    try:
                        already_has_visual = (
                            check_session.query(SignalVisual.id).filter_by(signal_id=signal_id).first()
                            is not None
                        )
                    finally:
                        check_session.close()
                    if already_has_visual:
                        return

                # The real Bedrock/OpenAI call this eventually makes can
                # take several seconds (or hang on a slow/unavailable
                # provider), so it must never run inline on the original
                # HTTP request - queue it as a background job on the
                # application's existing scheduler (see
                # app/scheduler/ingestion_scheduler.py and
                # app/scheduler/visual_generation_job.py), which opens its
                # own DB session once the job actually runs.
                from app.scheduler.ingestion_scheduler import ingestion_scheduler
                queued = ingestion_scheduler.schedule_visual_generation(signal_id)
                if queued:
                    return

                if background_only:
                    from app.scheduler.visual_generation_job import submit_visual_generation_in_background
                    submit_visual_generation_in_background(signal_id)
                    return

                # No background scheduler active in this process (tests,
                # a one-off script, or a replica with
                # SCHEDULER_ENABLED=false) - fall back to a synchronous
                # inline attempt, still strictly after commit. Uses a
                # FRESH session bound to the same engine as the original
                # (never the original `session`, which has already
                # committed - reusing it here would silently start a new,
                # separate, never-committed transaction on it) - the same
                # commit-and-close-independently pattern
                # visual_generation_job.py's background-job path already
                # uses, so this also works correctly against whichever
                # database the caller was actually using (dev/prod, or a
                # test's own database via the `db` fixture).
                # expire_on_commit=False: this session exists purely for
                # this one write-and-commit, so a caller (e.g. a test
                # asserting on the Signal object passed into a mocked
                # generate_for_signal) can still read attributes off the
                # objects it touched after this function returns and the
                # session is closed below, without an unexpected refresh
                # attempt against an already-closed session.
                fallback_session = Session(bind=engine, expire_on_commit=False)
                try:
                    signal = fallback_session.query(Signal).filter_by(id=signal_id).one_or_none()
                    if signal is None:
                        return
                    categories = fallback_session.query(SignalCategory).filter_by(signal_id=signal_id).all()
                    public_categories = internal_categories_to_public(c.category for c in categories)
                    self._get_visual_service().generate_for_signal(fallback_session, signal, public_categories)
                    fallback_session.commit()
                finally:
                    fallback_session.close()
            except Exception as e:
                logger.warning(f"visual_generation_skipped signal_id={signal_id} error={e}")

        event.listen(session, "after_commit", _on_commit)

    def _retire_superseded_current_signals(self, new_signal: Signal) -> None:
        """Retire the oldest excess current signals in each of
        `new_signal`'s categories, keeping at most
        freshness_policy.max_current_signals_per_category current signals
        per category (the new one included). Retired signals keep their
        PUBLISHED status and all history/evidence/audit records - only
        is_current flips to False, so they remain fully queryable for
        audit/analytics/dedup, just excluded from the public "current" feed.
        """
        keep = self.freshness_policy.max_current_signals_per_category
        category_ids = {c.category for c in new_signal.categories}

        for category in category_ids:
            current_in_category = (
                self.session.query(Signal)
                .join(SignalCategory, SignalCategory.signal_id == Signal.id)
                .filter(
                    SignalCategory.category == category,
                    Signal.status == SignalStatus.PUBLISHED,
                    Signal.is_current.is_(True),
                )
                .order_by(Signal.published_at.desc())
                .all()
            )
            # Newest-first list; anything beyond `keep` is retired, oldest first.
            to_retire = current_in_category[keep:]

            for stale_signal in to_retire:
                self.signal_repo.update(stale_signal.id, is_current=False)
                self._audit_signal_action(
                    signal_id=stale_signal.id,
                    action="SIGNAL_RETIRED_FROM_CURRENT",
                    reviewer_id=None,
                    changes={
                        "is_current_from": True,
                        "is_current_to": False,
                        "superseded_by": str(new_signal.id),
                        "category": category.value if hasattr(category, "value") else category,
                    },
                )
        self.session.flush()
    
    def get_published_signals(
        self,
        skip: int = 0,
        limit: int = 10
    ) -> List[Signal]:
        """Get paginated list of published signals."""
        try:
            signals = self.signal_repo.get_by_status(SignalStatus.PUBLISHED)
            paginated = signals[skip : skip + limit]
            return paginated
        except Exception as e:
            logger.error(f"Failed to get published signals: {e}")
            raise DatabaseError(f"Failed to retrieve published signals: {e}")
    
    def get_signal(self, signal_id: UUID) -> Optional[Signal]:
        """Get a signal by ID."""
        try:
            return self.signal_repo.get_by_id(signal_id)
        except Exception as e:
            logger.error(f"Failed to get signal: {e}")
            raise DatabaseError(f"Failed to retrieve signal: {e}")
