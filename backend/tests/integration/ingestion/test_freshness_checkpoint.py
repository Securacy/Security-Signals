"""Integration tests for freshness-vs-fetch-limit separation (Change 10)
and the "no new qualifying events" run outcome (Change 11), against real
PostgreSQL. The HTTP fetch itself is mocked (no real network) so these
tests are deterministic and fast; everything from parsing onward runs the
real orchestrator code.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.db.models import Article, Source, SourceType
from app.ingestion.adapters import Feed, FeedEntry
from app.ingestion.orchestrator import IngestionOrchestrator


@pytest.fixture
def source(db: Session) -> Source:
    src = Source(
        id=uuid4(), name="Freshness Test Source", source_type=SourceType.RSS,
        url="https://example.com/feed.rss", is_active=True, config={},
    )
    db.add(src)
    db.commit()
    db.refresh(src)
    return src


def _entry(title: str, published) -> FeedEntry:
    return FeedEntry(
        url=f"https://example.com/{title.replace(' ', '-')}",
        title=title,
        summary="A security-relevant summary mentioning a vulnerability.",
        published=published,
        external_id=None,
    )


class TestFreshnessCheckpoint:
    @pytest.mark.asyncio
    async def test_first_run_no_checkpoint_processes_everything(self, db: Session, source):
        """A source with no prior successful run (last_ingested_at is
        None) has no checkpoint to filter against - every entry in the
        fetch-limited page is eligible."""
        now = datetime.now(timezone.utc)
        feed = Feed(
            title="Test Feed",
            entries=[_entry("Old Item", now - timedelta(days=30)), _entry("New Item", now)],
            source_url=source.url,
        )
        orchestrator = IngestionOrchestrator(db)

        with patch.object(orchestrator.http_client, "fetch", new=AsyncMock(return_value=b"<rss/>")), \
             patch.object(orchestrator, "_adapter_for", return_value=type("A", (), {"parse": staticmethod(lambda b, u: feed)})()):
            result = await orchestrator._ingest_source(source)

        assert result["fetched"] == 2
        assert result["skipped_stale"] == 0

    @pytest.mark.asyncio
    async def test_entries_older_than_checkpoint_are_skipped(self, db: Session, source):
        """Once a source has a checkpoint, an entry published before it
        (minus the grace window) is recognized as not-new and skipped
        before dedup/storage - the fetch limit and recency are separate
        checks."""
        now = datetime.now(timezone.utc)
        source.last_ingested_at = now - timedelta(days=1)
        db.add(source)
        db.commit()

        feed = Feed(
            title="Test Feed",
            entries=[
                _entry("Very Old Item", now - timedelta(days=10)),
                _entry("Fresh Item", now),
            ],
            source_url=source.url,
        )
        orchestrator = IngestionOrchestrator(db)

        with patch.object(orchestrator.http_client, "fetch", new=AsyncMock(return_value=b"<rss/>")), \
             patch.object(orchestrator, "_adapter_for", return_value=type("A", (), {"parse": staticmethod(lambda b, u: feed)})()):
            result = await orchestrator._ingest_source(source)

        assert result["skipped_stale"] == 1
        assert result["fetched"] == 1

        stored_titles = {a.title for a in db.query(Article).filter(Article.source_id == source.id).all()}
        assert "Fresh Item" in stored_titles
        assert "Very Old Item" not in stored_titles

    @pytest.mark.asyncio
    async def test_entries_without_published_timestamp_still_processed(self, db: Session, source):
        """An entry with no published timestamp can't be freshness-filtered
        - it's still processed (dedup still protects against repeats)."""
        now = datetime.now(timezone.utc)
        source.last_ingested_at = now - timedelta(days=1)
        db.add(source)
        db.commit()

        feed = Feed(title="Test Feed", entries=[_entry("No Timestamp Item", None)], source_url=source.url)
        orchestrator = IngestionOrchestrator(db)

        with patch.object(orchestrator.http_client, "fetch", new=AsyncMock(return_value=b"<rss/>")), \
             patch.object(orchestrator, "_adapter_for", return_value=type("A", (), {"parse": staticmethod(lambda b, u: feed)})()):
            result = await orchestrator._ingest_source(source)

        assert result["skipped_stale"] == 0
        assert result["fetched"] == 1

    @pytest.mark.asyncio
    async def test_successful_run_advances_the_checkpoint(self, db: Session, source):
        assert source.last_ingested_at is None
        feed = Feed(title="Test Feed", entries=[], source_url=source.url)
        orchestrator = IngestionOrchestrator(db)

        with patch.object(orchestrator.http_client, "fetch", new=AsyncMock(return_value=b"<rss/>")), \
             patch.object(orchestrator, "_adapter_for", return_value=type("A", (), {"parse": staticmethod(lambda b, u: feed)})()):
            await orchestrator._ingest_source(source)

        db.refresh(source)
        assert source.last_ingested_at is not None


class TestNoNewDataOutcome:
    @pytest.mark.asyncio
    async def test_zero_new_events_is_a_successful_run_not_a_failure(self, db: Session, source):
        """A run that finds nothing new (e.g. everything already ingested)
        completes with status 'success', not an error - Change 11."""
        feed = Feed(title="Test Feed", entries=[], source_url=source.url)
        orchestrator = IngestionOrchestrator(db)

        with patch.object(orchestrator.http_client, "fetch", new=AsyncMock(return_value=b"<rss/>")), \
             patch.object(orchestrator, "_adapter_for", return_value=type("A", (), {"parse": staticmethod(lambda b, u: feed)})()):
            result = await orchestrator._ingest_source(source)

        assert result["status"] == "success"
        assert result["created"] == 0
