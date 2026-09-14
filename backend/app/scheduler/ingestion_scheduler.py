"""Weekly automated ingestion scheduler.

Uses APScheduler's AsyncIOScheduler, which runs jobs on the same asyncio
event loop FastAPI/uvicorn already use - no extra process, thread, or
message broker needed for a single weekly job. See "Celery migration path"
at the bottom of this file for when that stops being true.
"""

from datetime import datetime, timezone
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED, EVENT_JOB_MISSED
from apscheduler.job import Job

from app.db.connection import SessionLocal
from app.ingestion.orchestrator import IngestionOrchestrator
from app.logging import get_logger

logger = get_logger(__name__)

INGESTION_JOB_ID = "weekly_security_signals_ingestion"


async def run_ingestion_job() -> None:
    """The scheduled job body: run one real ingestion cycle.

    Any exception here is caught and logged, never re-raised - a failed
    ingestion run must not crash the scheduler or the application, and must
    not prevent the next scheduled run from firing. IngestionOrchestrator
    already isolates per-source failures from each other; this is the outer
    safety net for anything unexpected above that (e.g. a DB connectivity
    failure before a single source is even reached).

    Only run metadata (run id, counts, source names, non-secret error
    strings already produced by the orchestrator) is logged - never
    credentials, and article/event content is not logged at all.
    """
    logger.info("ingestion_job_started")
    session = SessionLocal()
    try:
        orchestrator = IngestionOrchestrator(session)
        results = await orchestrator.run()
        logger.info(
            "ingestion_job_completed",
            run_id=results.get("run_id"),
            total_fetched=results.get("total_fetched"),
            total_created=results.get("total_created"),
            total_duplicated=results.get("total_duplicated"),
            total_relevant=results.get("total_relevant"),
            source_count=len(results.get("sources", {})),
            failed_sources=[
                name for name, r in results.get("sources", {}).items()
                if r.get("status") != "success"
            ],
        )
    except Exception as e:
        logger.error("ingestion_job_failed", error=str(e), error_type=type(e).__name__)
    finally:
        session.close()


class IngestionScheduler:
    """Owns the AsyncIOScheduler instance and its one weekly ingestion job.

    Safe to construct, start, and shut down multiple times (e.g. across
    app restarts or in tests) - start()/shutdown() are idempotent no-ops
    when already in the target state.
    """

    def __init__(self):
        self._scheduler = AsyncIOScheduler(timezone=timezone.utc)
        self._scheduler.add_listener(
            self._on_job_event,
            EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED,
        )

    @property
    def running(self) -> bool:
        return self._scheduler.running

    def get_job(self) -> Optional[Job]:
        return self._scheduler.get_job(INGESTION_JOB_ID)

    def start(self) -> None:
        """Register the weekly ingestion job (Sunday 20:00 UTC) and start
        the scheduler. Idempotent: calling this again while already running
        does nothing."""
        if self._scheduler.running:
            logger.info("scheduler_start_skipped", reason="already_running")
            return

        self._scheduler.add_job(
            run_ingestion_job,
            trigger=CronTrigger(day_of_week="sun", hour=20, minute=0, timezone=timezone.utc),
            id=INGESTION_JOB_ID,
            name="Weekly security signals ingestion",
            # max_instances=1 is APScheduler's built-in guarantee that a new
            # run of this job is never started while a previous run of the
            # SAME job is still in flight - the "no overlapping duplicate
            # jobs" requirement.
            max_instances=1,
            # If the process was down across a scheduled fire time (e.g.
            # host restart over the weekend), coalesce collapses any missed
            # runs into a single catch-up run instead of firing repeatedly.
            coalesce=True,
            misfire_grace_time=3600,
            replace_existing=True,
        )
        self._scheduler.start()
        logger.info(
            "scheduler_started",
            job_id=INGESTION_JOB_ID,
            schedule="Sunday 20:00 UTC (weekly)",
        )

    def shutdown(self, wait: bool = True) -> None:
        """Stop the scheduler. Safe to call even if never started."""
        if not self._scheduler.running:
            return
        self._scheduler.shutdown(wait=wait)
        logger.info("scheduler_shutdown")

    def _on_job_event(self, event) -> None:
        """Log job lifecycle events. Only APScheduler's own event metadata
        (job id, scheduled run time, exception message) is logged - never
        request data, credentials, or environment variables."""
        if event.code == EVENT_JOB_ERROR:
            logger.error(
                "scheduler_job_error",
                job_id=event.job_id,
                scheduled_run_time=str(event.scheduled_run_time),
                exception=str(event.exception) if event.exception else None,
            )
        elif event.code == EVENT_JOB_MISSED:
            logger.warning(
                "scheduler_job_missed",
                job_id=event.job_id,
                scheduled_run_time=str(event.scheduled_run_time),
            )
        else:
            logger.info(
                "scheduler_job_executed",
                job_id=event.job_id,
                scheduled_run_time=str(event.scheduled_run_time),
            )


# Module-level singleton, mirroring how app/db/connection.py exposes a
# single shared SessionLocal - app/main.py starts/stops this same instance
# on FastAPI startup/shutdown.
ingestion_scheduler = IngestionScheduler()


# ---------------------------------------------------------------------------
# Celery migration path (documented, not implemented)
# ---------------------------------------------------------------------------
# APScheduler + AsyncIOScheduler is the right tool for exactly what Phase 4
# needs: one recurring in-process job, no separate broker/worker deployment,
# no new infrastructure. It is not the right tool if any of the following
# become true:
#
#   - Ingestion needs to run on a schedule finer than the process's own
#     uptime guarantees, or needs guaranteed at-least-once execution across
#     process restarts (APScheduler's in-memory job store loses track of a
#     run that was in progress when the process died; a persistent job
#     store - SQLAlchemyJobStore - helps with *scheduling* durability but
#     still can't resume a run that was mid-flight).
#   - Ingestion needs to run on a separate worker fleet from the API
#     process (e.g. to isolate its resource usage, or scale ingestion
#     independently of API traffic).
#   - Multiple ingestion (or other background) job types need retries with
#     backoff, rate limiting, priority queues, or cross-job dependencies
#     more sophisticated than APScheduler's own trigger/misfire options.
#   - More than one API process/replica runs at once: AsyncIOScheduler's
#     max_instances=1 only prevents overlap *within one process*. Running
#     N replicas each with their own IngestionScheduler would fire the job
#     N times at the same moment - fine at N=1 (the current deployment),
#     a real problem at N>1.
#
# If/when any of those apply, the migration is: introduce Celery + a
# broker (Redis is the natural choice given no other broker is deployed
# here), convert `run_ingestion_job` into a Celery task (the function body
# barely changes - it already isolates its own DB session and swallows its
# own exceptions), and register the weekly schedule via celery-beat's
# crontab schedule (the same day_of_week/hour/minute already used above).
# `IngestionScheduler` here would then be deleted rather than kept
# alongside Celery - the two are not meant to run at once.
