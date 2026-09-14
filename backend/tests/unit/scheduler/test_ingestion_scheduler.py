"""Tests for the weekly ingestion scheduler (Phase 4)."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from app.scheduler.ingestion_scheduler import (
    IngestionScheduler, run_ingestion_job, INGESTION_JOB_ID
)


class TestSchedulerJobRegistration:
    """The scheduled job must fire weekly, Sunday 20:00 UTC, and never
    overlap with a still-running instance of itself."""

    @pytest.mark.asyncio
    async def test_start_registers_weekly_sunday_2000_utc_job(self):
        scheduler = IngestionScheduler()
        try:
            scheduler.start()
            job = scheduler.get_job()

            assert job is not None
            assert job.id == INGESTION_JOB_ID
            trigger_str = str(job.trigger)
            assert "day_of_week='sun'" in trigger_str
            assert "hour='20'" in trigger_str
            assert "minute='0'" in trigger_str
        finally:
            scheduler.shutdown(wait=False)
            await asyncio.sleep(0)

    @pytest.mark.asyncio
    async def test_job_disallows_overlapping_instances(self):
        """max_instances=1 is APScheduler's built-in guarantee that a new
        run never starts while a previous run of the same job is still
        executing - the 'no overlapping duplicate jobs' requirement."""
        scheduler = IngestionScheduler()
        try:
            scheduler.start()
            job = scheduler.get_job()

            assert job.max_instances == 1
        finally:
            scheduler.shutdown(wait=False)
            await asyncio.sleep(0)

    @pytest.mark.asyncio
    async def test_job_coalesces_missed_runs(self):
        """If the process was down across a scheduled fire time, coalesce
        collapses missed runs into one catch-up run instead of firing
        repeatedly in a burst."""
        scheduler = IngestionScheduler()
        try:
            scheduler.start()
            job = scheduler.get_job()

            assert job.coalesce is True
        finally:
            scheduler.shutdown(wait=False)
            await asyncio.sleep(0)

    @pytest.mark.asyncio
    async def test_next_run_time_is_a_sunday(self):
        scheduler = IngestionScheduler()
        try:
            scheduler.start()
            job = scheduler.get_job()

            assert job.next_run_time is not None
            assert job.next_run_time.weekday() == 6  # Monday=0 ... Sunday=6
            assert job.next_run_time.hour == 20
            assert job.next_run_time.minute == 0
        finally:
            scheduler.shutdown(wait=False)
            await asyncio.sleep(0)


class TestSchedulerStartupShutdown:
    """Safe startup/shutdown: idempotent, and shutdown never requires a
    prior successful start."""

    @pytest.mark.asyncio
    async def test_start_is_idempotent(self):
        scheduler = IngestionScheduler()
        try:
            scheduler.start()
            scheduler.start()  # must not raise or duplicate the job

            assert scheduler.running is True
            assert scheduler._scheduler.get_jobs().__len__() == 1
        finally:
            scheduler.shutdown(wait=False)
            await asyncio.sleep(0)

    @pytest.mark.asyncio
    async def test_shutdown_safe_when_never_started(self):
        scheduler = IngestionScheduler()

        scheduler.shutdown(wait=False)  # must not raise

        assert scheduler.running is False

    @pytest.mark.asyncio
    async def test_shutdown_stops_the_scheduler(self):
        scheduler = IngestionScheduler()
        scheduler.start()
        assert scheduler.running is True

        scheduler.shutdown(wait=False)
        await asyncio.sleep(0.05)

        assert scheduler.running is False

    @pytest.mark.asyncio
    async def test_double_shutdown_safe(self):
        scheduler = IngestionScheduler()
        scheduler.start()

        scheduler.shutdown(wait=False)
        await asyncio.sleep(0.05)
        scheduler.shutdown(wait=False)  # must not raise on an already-stopped scheduler

        assert scheduler.running is False


class TestIngestionJobFailureIsolation:
    """A failed ingestion run must never crash the scheduler/application,
    and must always release its DB session."""

    @pytest.mark.asyncio
    async def test_orchestrator_exception_is_caught_not_raised(self):
        mock_session = MagicMock()

        with patch("app.scheduler.ingestion_scheduler.SessionLocal", return_value=mock_session), \
             patch("app.scheduler.ingestion_scheduler.IngestionOrchestrator") as MockOrchestrator:
            MockOrchestrator.return_value.run = _async_raise(RuntimeError("boom"))

            await run_ingestion_job()  # must not raise

        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_session_closed_on_success(self):
        mock_session = MagicMock()
        fake_results = {
            "run_id": "abc",
            "total_fetched": 10,
            "total_created": 2,
            "total_duplicated": 8,
            "total_relevant": 1,
            "sources": {"Test Source": {"status": "success"}},
            "errors": [],
        }

        with patch("app.scheduler.ingestion_scheduler.SessionLocal", return_value=mock_session), \
             patch("app.scheduler.ingestion_scheduler.IngestionOrchestrator") as MockOrchestrator:
            MockOrchestrator.return_value.run = _async_return(fake_results)

            await run_ingestion_job()

        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_session_closed_even_when_orchestrator_construction_fails(self):
        mock_session = MagicMock()

        with patch("app.scheduler.ingestion_scheduler.SessionLocal", return_value=mock_session), \
             patch(
                 "app.scheduler.ingestion_scheduler.IngestionOrchestrator",
                 side_effect=RuntimeError("db unavailable"),
             ):
            await run_ingestion_job()  # must not raise

        mock_session.close.assert_called_once()


def _async_return(value):
    async def _inner(*args, **kwargs):
        return value
    return _inner


def _async_raise(exc):
    async def _inner(*args, **kwargs):
        raise exc
    return _inner
