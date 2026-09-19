"""Signal service layer - business logic for signal lifecycle."""
from typing import Optional, List
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy.orm import Session
import logging

from app.db.models import (
    Signal, SignalStatus, SignalCategory, Evidence, SecurityEvent,
    SecurityCategoryType, User
)
from app.repositories import (
    SignalRepository, SignalCategoryRepository, EvidenceRepository,
    SecurityEventRepository, AuditLogRepository
)
from app.intelligence.schemas.signal_request import AISignalGenerationResponse
from app.intelligence.visual_service import ThreatVisualService
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
        """Lazily build the production Bedrock-backed visual service only
        when actually needed, so constructing a SignalService for tests
        that never publish never requires real AWS credentials."""
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
        reviewer_id: Optional[UUID] = None
    ) -> Signal:
        """
        Reject a signal, moving it from IN_REVIEW to REJECTED.
        
        Args:
            signal_id: Signal to reject
            reviewer_id: User ID of reviewer (Phase 6 auth placeholder)
        
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
                    "reviewed_by": str(reviewer_id) if reviewer_id else None
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

        # Signal-specific visual generation is queued AFTER the publish
        # transaction above has fully succeeded, and is deliberately
        # isolated in its own try/except: image-generation failure (or
        # being disabled, or the queueing itself failing) must NEVER
        # unpublish or fail an otherwise-valid publish action.
        #
        # The real Bedrock call this eventually makes can take several
        # seconds (or hang on a slow/unavailable provider), so it must
        # never run inline on this HTTP request - it's queued as a
        # background job on the application's existing scheduler (see
        # app/scheduler/ingestion_scheduler.py's schedule_visual_generation
        # and app/scheduler/visual_generation_job.py), which opens its own
        # DB session once the job actually runs. If no background
        # scheduler is active in this process (tests, a one-off script, or
        # a replica with SCHEDULER_ENABLED=false), this falls back to a
        # synchronous inline attempt - still after publish has already
        # committed, so it can be slow but can never roll back the publish.
        try:
            from app.config import get_settings
            if get_settings().visual_generation_enabled:
                from app.scheduler.ingestion_scheduler import ingestion_scheduler
                queued = ingestion_scheduler.schedule_visual_generation(updated.id)
                if not queued:
                    categories = self.category_repo.get_by_signal(updated.id)
                    public_categories = internal_categories_to_public(c.category for c in categories)
                    self._get_visual_service().generate_for_signal(self.session, updated, public_categories)
                    self.session.flush()
        except Exception as e:
            logger.warning(f"visual_generation_skipped signal_id={signal_id} error={e}")

        return updated

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
