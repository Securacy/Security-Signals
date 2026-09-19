"""Weekly automated ingestion scheduler.

Uses APScheduler's AsyncIOScheduler, which runs jobs on the same asyncio
event loop FastAPI/uvicorn already use - no extra process, thread, or
message broker needed for a single weekly job. See "Celery migration path"
at the bottom of this file for when that stops being true.
"""

from datetime import datetime, timezone
from typing import Optional

from uuid import UUID

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED, EVENT_JOB_MISSED
from apscheduler.job import Job

from app.db.connection import SessionLocal
from app.ingestion.orchestrator import IngestionOrchestrator
from app.services.category_health_service import compute_category_health
from app.services.weekly_signal_pipeline import WeeklySignalPipeline
from app.scheduler.visual_generation_job import run_visual_generation_job
from app.logging import get_logger

logger = get_logger(__name__)

INGESTION_JOB_ID = "weekly_security_signals_ingestion"


async def run_ingestion_job() -> None:
    """The scheduled job body: run one real ingestion cycle, then select
    and generate signals for the most important newly-eligible events
    (Change 5) - every generated signal still lands as DRAFT and goes
    through the full existing human-review lifecycle; nothing here ever
    publishes automatically.

    Any exception here is caught and logged, never re-raised - a failed
    run must not crash the scheduler or the application, and must not
    prevent the next scheduled run from firing. IngestionOrchestrator and
    WeeklySignalPipeline already isolate per-source and per-event failures
    from each other; this is the outer safety net for anything unexpected
    above that (e.g. a DB connectivity failure before either stage starts).

    Only run metadata (run id, counts, source/category names, non-secret
    error strings already produced by the orchestrator/pipeline) is logged
    - never credentials, and article/event content is not logged at all.
    """
    logger.info("ingestion_job_started")
    session = SessionLocal()
    try:
        orchestrator = IngestionOrchestrator(session)
        results = await orchestrator.run()
        source_results = results.get("sources", {})
        sources_succeeded = sum(1 for r in source_results.values() if r.get("status") == "success")
        sources_failed = sum(1 for r in source_results.values() if r.get("status") != "success")
        stale_articles_skipped = sum(r.get("skipped_stale", 0) for r in source_results.values())

        logger.info(
            "ingestion_job_completed",
            run_id=results.get("run_id"),
            total_fetched=results.get("total_fetched"),
            total_created=results.get("total_created"),
            total_duplicated=results.get("total_duplicated"),
            total_relevant=results.get("total_relevant"),
            total_new_events=results.get("total_new_events"),
            source_count=len(source_results),
            failed_sources=[name for name, r in source_results.items() if r.get("status") != "success"],
        )

        pipeline = WeeklySignalPipeline(session)
        pipeline_results = pipeline.run()
        logger.info(
            "weekly_signal_generation_completed",
            candidates_considered=pipeline_results.get("candidates_considered"),
            selected_count=pipeline_results.get("selected_count"),
            generated_count=pipeline_results.get("generated_count"),
            failed_count=pipeline_results.get("failed_count"),
            category_counts=pipeline_results.get("category_counts"),
            empty_categories=pipeline_results.get("empty_categories"),
            ai_fraction=pipeline_results.get("ai_fraction"),
            priority_categories=pipeline_results.get("priority_categories"),
        )

        # Category coverage is computed once more here (after generation,
        # before human review/publish) purely for the operational summary
        # below - it never feeds back into any decision already made this
        # run, and reflects the real, already-persisted PUBLISHED+is_current
        # state, never fabricated.
        try:
            category_coverage = {
                h.category: {"has_current_coverage": h.has_current_coverage, "is_stale": h.is_stale}
                for h in compute_category_health(session)
            }
        except Exception as e:
            logger.warning("category_coverage_summary_unavailable", error=str(e))
            category_coverage = {}

        weekly_pipeline_summary = {
            "run_id": results.get("run_id"),
            "sources_attempted": len(source_results),
            "sources_succeeded": sources_succeeded,
            "sources_failed": sources_failed,
            "articles_fetched": results.get("total_fetched", 0),
            "stale_articles_skipped": stale_articles_skipped,
            "new_articles": results.get("total_created", 0),
            "new_events": results.get("total_new_events", 0),
            "new_signal_candidates": pipeline_results.get("selected_count", 0),
            "signals_generated": pipeline_results.get("generated_count", 0),
            "signals_generation_failed": pipeline_results.get("failed_count", 0),
            "category_coverage": category_coverage,
        }
        logger.info("weekly_pipeline_summary", **weekly_pipeline_summary)
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

    def schedule_visual_generation(self, signal_id: UUID) -> bool:
        """Queue a one-off, run-ASAP background job to generate one
        signal's visual (see app/scheduler/visual_generation_job.py) -
        reuses this same shared scheduler/event-loop rather than
        introducing new job infrastructure. Publishing a signal must never
        block on the real Bedrock call this job makes.

        Returns True if the job was actually queued (the scheduler is
        running), False otherwise - callers (SignalService.publish_signal)
        use this to fall back to a safe inline attempt when no background
        scheduler process is active in this deployment (e.g. tests, a
        one-off script, or a replica with SCHEDULER_ENABLED=false).

        `replace_existing=True` plus a signal-id-derived job id makes this
        idempotent at the scheduling level too: queuing the same signal
        again (e.g. a rare double-publish race) replaces rather than
        duplicates the pending job - ThreatVisualService.generate_for_signal
        itself is also idempotent once the job actually runs.
        """
        if not self._scheduler.running:
            return False

        self._scheduler.add_job(
            run_visual_generation_job,
            args=[signal_id],
            trigger=DateTrigger(),  # run once, as soon as possible
            id=f"visual_generation_{signal_id}",
            name=f"Generate visual for signal {signal_id}",
            misfire_grace_time=3600,
            replace_existing=True,
        )
        return True

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
