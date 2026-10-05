"""Reviewer email notification - sent when a signal moves DRAFT -> IN_REVIEW.

Wired as a best-effort, post-commit side effect of SignalService.
submit_for_review (see that method and _notify_reviewers_after_commit),
mirroring the exact "commit the real state change first, queue the
side effect after, never let the side effect fail the request" shape
already used for visual generation (SignalService.
_register_visual_generation_at_creation / _queue_visual_generation_after_commit).

Idempotency without a new column/table: before sending, this checks
whether a REVIEWER_NOTIFICATION_SENT audit row already exists for this
signal_id. The current lifecycle only ever transitions a signal from DRAFT
to IN_REVIEW once (there is no resubmit path), so "has this signal already
been notified about, ever" is a correct, sufficient idempotency check, and
it reuses the existing, already-durable audit_log table as the ledger
instead of inventing a second one.
"""

import html
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models import Signal, SignalStatus
from app.repositories import AuditLogRepository, SignalRepository, UserRepository
from app.integrations.resend_mail import send_mail, ResendMailError

logger = logging.getLogger(__name__)

_REVIEWER_ROLE = "reviewer"

# Small, dedicated pool - sending one notification email is low-volume (at
# most one per submit-for-review call) and I/O-bound (a token acquisition
# plus one HTTP POST to Graph), same reasoning as the dedicated executors
# already used for image generation (app/scheduler/visual_generation_job.py)
# and AI search understanding (app/intelligence/search_service.py). Keeps
# the real network call off the request thread entirely, so a slow or
# unresponsive mail provider can never add latency to the submit-for-review
# HTTP response, on top of never being able to roll back its already-
# committed transition.
_NOTIFICATION_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="reviewer-notify")


class ReviewerNotificationService:
    """Construct with a session; call notify_submission after the
    triggering transaction has already committed."""

    def __init__(self, session: Session):
        self.session = session
        self.user_repo = UserRepository(session)
        self.signal_repo = SignalRepository(session)
        self.audit_repo = AuditLogRepository(session)

    def _already_notified(self, signal_id: UUID) -> bool:
        existing = self.audit_repo.get_by_resource(resource_type="SIGNAL", resource_id=signal_id)
        return any(e.action == "REVIEWER_NOTIFICATION_SENT" for e in existing)

    def _build_message(self, signal: Signal, settings) -> tuple[str, str]:
        """Returns (subject, html_body). Every dynamic value (signal title,
        pending count, review queue URL) is run through html.escape before
        being interpolated into the HTML string - nothing here ever trusts
        AI-generated or otherwise externally-influenced content (the signal
        title) to be safe to place directly into an HTML email body."""
        pending_count = len(self.signal_repo.get_by_status(SignalStatus.IN_REVIEW))
        review_queue_url = f"{settings.frontend_url.rstrip('/')}/admin/signals/in-review"
        safe_title = html.escape(signal.title)
        safe_count = html.escape(str(pending_count))
        safe_url = html.escape(review_queue_url)

        subject = "Security Signals — Review Required"
        plural = "s" if pending_count != 1 else ""
        verb = "are" if pending_count != 1 else "is"
        html_body = (
            f"<p>There {verb} currently {safe_count} security signal{plural} waiting for review.</p>"
            f"<p>Newly submitted:</p>"
            f"<ul><li>{safe_title}</li></ul>"
            f"<p>Please review the pending signals in the "
            f'<a href="{safe_url}">Security Signals Review Queue</a>.</p>'
        )
        return subject, html_body

    def notify_submission(self, signal_id: UUID, actor_id: Optional[UUID] = None) -> None:
        """Best-effort: never raises. Logs and writes a
        REVIEWER_NOTIFICATION_SENT or REVIEWER_NOTIFICATION_FAILED audit
        entry either way, so there's always a human-readable record of
        whether reviewers were actually told about a submission."""
        from app.config import get_settings
        settings = get_settings()

        if self._already_notified(signal_id):
            logger.info(f"reviewer_notification_skipped_already_sent signal_id={signal_id}")
            return

        signal = self.signal_repo.get_by_id(signal_id)
        if signal is None:
            logger.warning(f"reviewer_notification_signal_missing signal_id={signal_id}")
            return

        reviewers = self.user_repo.get_active_users_by_role(_REVIEWER_ROLE)
        recipients = [r.email for r in reviewers if r.email]

        if not recipients:
            logger.info(f"reviewer_notification_no_active_reviewers signal_id={signal_id}")
            self.audit_repo.create(
                user_id=actor_id, action="REVIEWER_NOTIFICATION_FAILED", resource_type="SIGNAL",
                resource_id=signal_id, changes={"reason": "no_active_reviewers"},
            )
            self.session.commit()
            return

        subject, html_body = self._build_message(signal, settings)

        try:
            send_mail(settings, to=recipients, subject=subject, html_body=html_body)
        except ResendMailError as e:
            logger.warning(f"reviewer_notification_send_failed signal_id={signal_id} error={e}")
            self.audit_repo.create(
                user_id=actor_id, action="REVIEWER_NOTIFICATION_FAILED", resource_type="SIGNAL",
                resource_id=signal_id, changes={"reason": str(e), "recipient_count": len(recipients)},
            )
            self.session.commit()
            return

        self.audit_repo.create(
            user_id=actor_id, action="REVIEWER_NOTIFICATION_SENT", resource_type="SIGNAL",
            resource_id=signal_id,
            changes={"recipient_count": len(recipients), "signal_title": signal.title},
        )
        self.session.commit()
        logger.info(f"reviewer_notification_sent signal_id={signal_id} recipient_count={len(recipients)}")


def _notify_reviewers_sync(signal_id: UUID, actor_id: Optional[UUID]) -> None:
    """Blocking body: opens its own fresh DB session (the request that
    triggered this has already returned/committed by the time this runs on
    a worker thread), runs on a worker thread, never on the request thread.
    Mirrors app/scheduler/visual_generation_job.py's _generate_visual_sync
    shape exactly. Never raises - any failure is caught and logged here, in
    addition to notify_submission's own internal failure-audit handling, so
    one bad notification attempt can never crash or destabilize anything
    else."""
    from app.db.connection import SessionLocal

    session = SessionLocal()
    try:
        ReviewerNotificationService(session).notify_submission(signal_id, actor_id)
    except Exception as e:
        session.rollback()
        logger.warning(f"reviewer_notification_job_failed signal_id={signal_id} error={e}")
    finally:
        session.close()


def submit_reviewer_notification_in_background(signal_id: UUID, actor_id: Optional[UUID] = None) -> None:
    """Fire-and-forget: hands the notification work to this module's small
    worker pool and returns immediately. Never blocks the caller (in
    particular never the submit-for-review HTTP response) on the mail
    provider, and never raises - _notify_reviewers_sync catches and logs
    everything. Called from SignalService.submit_for_review's after-commit
    listener (see _queue_reviewer_notification_after_commit)."""
    _NOTIFICATION_EXECUTOR.submit(_notify_reviewers_sync, signal_id, actor_id)
