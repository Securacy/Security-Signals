"""Integration tests for source registration, including the dedicated AI
security source (Change 7) and the strict dedicated-source-per-category
requirement (every canonical category must have a real, verified Tier-1
primary source)."""

from unittest.mock import AsyncMock

import pytest
from sqlalchemy.orm import Session

from app.db.models import Source, SourceType, SecurityCategoryType
from app.ingestion.sources import SourceRegistry, VERIFIED_FEEDS, CATEGORIES_WITHOUT_DEDICATED_TIER1_SOURCE


class TestAISourceRegistration:
    def test_ai_security_source_is_in_verified_feeds(self):
        names = [f['name'] for f in VERIFIED_FEEDS]
        assert 'OWASP GenAI Security Project' in names

    def test_ai_security_source_uses_a_real_https_url(self):
        ai_feed = next(f for f in VERIFIED_FEEDS if f['name'] == 'OWASP GenAI Security Project')
        assert ai_feed['url'].startswith('https://')
        assert ai_feed['type'] == SourceType.RSS

    def test_ai_security_source_is_created_on_init(self, db: Session):
        registry = SourceRegistry(db)
        registry.init_default_sources()

        source = db.query(Source).filter_by(name='OWASP GenAI Security Project').one_or_none()
        assert source is not None
        assert source.source_type == SourceType.RSS

    def test_ai_security_source_is_tier_1(self):
        ai_feed = next(f for f in VERIFIED_FEEDS if f['name'] == 'OWASP GenAI Security Project')
        assert ai_feed.get('tier') == 1


class TestSourceRegistrySyncsExistingRows:
    def test_all_verified_feeds_created_on_init(self, db: Session):
        registry = SourceRegistry(db)
        registry.init_default_sources()

        names = {s.name for s in db.query(Source).all()}
        for feed in VERIFIED_FEEDS:
            assert feed['name'] in names

    def test_twentytwo_sources_configured(self):
        """8 original sources + 1 dedicated AI security source + 3 sources
        added for category coverage (CISA, BleepingComputer, Krebs on
        Security) + 10 sources added for strict dedicated-source-per-
        category hardening (Okta Security, Auth0 Blog, AWS Security
        Bulletins, Microsoft Security Blog, Google Online Security Blog,
        Unit 42, PortSwigger Research, Sonatype Blog, Have I Been Pwned
        Breaches, DataBreaches.Net - see app/ingestion/sources.py)."""
        assert len(VERIFIED_FEEDS) == 22

    def test_every_source_has_a_valid_https_url(self):
        for feed in VERIFIED_FEEDS:
            assert feed['url'].startswith('https://'), feed['name']

    def test_no_duplicate_source_names(self):
        names = [f['name'] for f in VERIFIED_FEEDS]
        assert len(names) == len(set(names))


class TestStrictDedicatedSourcePerCategory:
    """Every canonical category must have at least one dedicated Tier-1
    primary source - not merely "some source happens to list it" (Section
    9-13 of the hardening spec). This is computed the same way
    category_health_service does: read the real, already-verified
    VERIFIED_FEEDS registry, never a separate/duplicated list."""

    def _primary_sources_by_category(self):
        by_cat: dict = {}
        for feed in VERIFIED_FEEDS:
            if feed.get('tier', 1) != 1:
                continue
            for category in feed['categories']:
                by_cat.setdefault(category, []).append(feed['name'])
        return by_cat

    @pytest.mark.parametrize("category", [c.value for c in SecurityCategoryType])
    def test_category_has_at_least_one_dedicated_primary_source(self, category):
        primary_by_category = self._primary_sources_by_category()
        assert primary_by_category.get(category), (
            f"{category} has no Tier-1 dedicated primary source in VERIFIED_FEEDS"
        )

    def test_categories_without_dedicated_tier1_source_list_is_empty(self):
        """As of this phase, the previous IAM/Cloud Security gap is closed
        with real, verified sources (Okta Security, AWS Security
        Bulletins). This constant staying non-empty would mean a real,
        currently-undocumented coverage gap - not something to silently
        allow to pass."""
        assert CATEGORIES_WITHOUT_DEDICATED_TIER1_SOURCE == []

    def test_ai_security_has_multiple_dedicated_primary_sources(self):
        """AI Security is an explicit product priority (Section 19) and
        must have stronger-than-ordinary coverage - more than one Tier-1
        dedicated source, not just the bare minimum."""
        primary_by_category = self._primary_sources_by_category()
        assert len(primary_by_category.get('ai_security', [])) >= 2

    def test_ai_security_also_has_secondary_redundancy(self):
        secondary = [
            f['name'] for f in VERIFIED_FEEDS
            if f.get('tier', 1) != 1 and 'ai_security' in f['categories']
        ]
        assert len(secondary) >= 1


class TestOrchestratorSyncsSourcesOnEveryRun:
    """A source added to VERIFIED_FEEDS (e.g. for category coverage) must
    actually take effect on the very next scheduled run - not require
    someone to remember to call SourceRegistry.init_default_sources() by
    hand. This is a real production gap that was found by running a real
    ingestion cycle against a database whose Source table had never been
    synced past an earlier VERIFIED_FEEDS list: only 9 of the (by-then) 12
    configured feeds were ever fetched."""

    @pytest.mark.asyncio
    async def test_run_syncs_all_verified_feeds_into_source_table(self, db: Session):
        from app.common.http_client import HTTPError
        from app.ingestion.orchestrator import IngestionOrchestrator

        assert db.query(Source).count() == 0  # fresh DB, nothing synced yet

        orchestrator = IngestionOrchestrator(db)
        orchestrator.http_client.fetch = AsyncMock(side_effect=HTTPError("no real network in this test"))

        await orchestrator.run()

        names = {s.name for s in db.query(Source).all()}
        for feed in VERIFIED_FEEDS:
            assert feed['name'] in names

    @pytest.mark.asyncio
    async def test_run_syncs_a_newly_added_source_for_an_existing_db(self, db: Session):
        """Simulates the real gap: a DB that only ever saw an older,
        smaller VERIFIED_FEEDS list must pick up new entries on the next
        run, without any manual seeding step."""
        from app.common.http_client import HTTPError
        from app.ingestion.orchestrator import IngestionOrchestrator

        # Pre-seed only the first source, as if the DB predates the rest.
        first = VERIFIED_FEEDS[0]
        db.add(Source(name=first['name'], source_type=first['type'], url=first['url'], config={}))
        db.commit()
        assert db.query(Source).count() == 1

        orchestrator = IngestionOrchestrator(db)
        orchestrator.http_client.fetch = AsyncMock(side_effect=HTTPError("no real network in this test"))

        await orchestrator.run()

        assert db.query(Source).count() == len(VERIFIED_FEEDS)
