"""Background job body for per-signal visual generation.

Publishing a signal must never block on a real Bedrock image-generation
call (it can take several seconds, or hang/fail on a slow or unavailable
provider). This module holds the job APScheduler actually runs: it opens
its OWN database session (the HTTP request that queued it has already
returned by the time this executes) and runs the blocking
provider/file-I/O work in a thread so it never blocks the FastAPI/uvicorn
event loop the scheduler shares (same reasoning as the existing
ThreadPoolExecutor use in app/intelligence/search_service.py for AI search
calls).

Never raises back to the scheduler: any failure is caught and logged here,
in addition to ThreatVisualService's own internal FAILED-row handling, so
one bad job can never crash or destabilize the scheduler.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

from app.db.connection import SessionLocal
from app.db.models import Signal, SignalCategory
from app.logging import get_logger
from app.taxonomy import internal_categories_to_public

logger = get_logger(__name__)

# Small, dedicated pool - visual generation is low-volume (one job per
# publish action, a human-gated, infrequent event) and each job is mostly
# waiting on network I/O, not CPU-bound.
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="visual-gen")


def _generate_visual_sync(signal_id: UUID) -> None:
    """Blocking body: real DB session + real ThreatVisualService call.
    Runs on a worker thread, never on the event loop."""
    from app.config import get_settings
    from app.intelligence.visual_service import ThreatVisualService

    session = SessionLocal()
    try:
        signal = session.query(Signal).filter_by(id=signal_id).one_or_none()
        if signal is None:
            # Signal was deleted/never existed by the time this ran - not
            # an error, just nothing left to do.
            logger.info(f"visual_generation_job_signal_missing signal_id={signal_id}")
            return

        categories = session.query(SignalCategory).filter_by(signal_id=signal_id).all()
        public_categories = internal_categories_to_public(c.category for c in categories)

        service = ThreatVisualService.from_settings(get_settings())
        visual = service.generate_for_signal(session, signal, public_categories)
        session.commit()
        logger.info(
            "visual_generation_job_completed",
            signal_id=str(signal_id), status=visual.status.value,
        )
    except Exception as e:
        session.rollback()
        logger.warning(f"visual_generation_job_failed signal_id={signal_id} error={e}")
    finally:
        session.close()


async def run_visual_generation_job(signal_id: UUID) -> None:
    """APScheduler job entry point (async, matching the existing weekly
    ingestion job's shape) - offloads the actual blocking work to a
    thread so the shared event loop stays responsive."""
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(_EXECUTOR, _generate_visual_sync, signal_id)
    except Exception as e:
        # _generate_visual_sync already catches everything it can - this
        # is only reachable for something going wrong in the executor
        # plumbing itself.
        logger.warning(f"visual_generation_job_executor_failed signal_id={signal_id} error={e}")


def submit_visual_generation_in_background(signal_id: UUID) -> None:
    """Fire-and-forget fallback for when the application's APScheduler is
    not running in this process (e.g. a one-off script that creates
    signals): hands the SAME job body the scheduler would have run to this
    module's small worker pool and returns immediately. Never blocks the
    caller (in particular never the ingestion loop) on the image provider,
    and never raises - _generate_visual_sync catches and logs everything."""
    _EXECUTOR.submit(_generate_visual_sync, signal_id)
