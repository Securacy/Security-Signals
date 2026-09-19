"""Main ingestion orchestration."""

import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import uuid

from sqlalchemy.orm import Session

from app.db.models import Source
from app.ingestion.sources import SourceRegistry
from app.ingestion.adapters import (
    RSSAtomAdapter, GitHubAdvisoriesJSONAdapter, ApacheHTTPDJSONAdapter
)
from app.common.http_client import HTTPClient, HTTPError, SSRFError
from app.ingestion.normalizer import ArticleNormalizer
from app.ingestion.processor import RelevanceClassifier, EventGrouper
from app.ingestion.freshness_policy import FreshnessPolicy, compute_freshness_cutoff, is_stale_entry

logger = logging.getLogger(__name__)

# Sources whose feed is JSON rather than RSS/Atom map to a dedicated adapter
# by name (see app/ingestion/sources.py for why each needed one). Any source
# not listed here uses the default RSSAtomAdapter.
_JSON_ADAPTERS_BY_SOURCE_NAME = {
    'GitHub Security Advisories': GitHubAdvisoriesJSONAdapter(),
    'Apache HTTP Server Security': ApacheHTTPDJSONAdapter(),
}


class IngestionOrchestrator:
    """Main ingestion pipeline."""

    def __init__(self, session: Session, freshness_policy: Optional[FreshnessPolicy] = None):
        self.session = session
        self.registry = SourceRegistry(session)
        self.adapter = RSSAtomAdapter()
        self.http_client = HTTPClient()
        self.classifier = RelevanceClassifier()
        self.grouper = EventGrouper(session)
        if freshness_policy is None:
            from app.config import get_settings
            freshness_policy = FreshnessPolicy.from_settings(get_settings())
        self.freshness_policy = freshness_policy

    def _adapter_for(self, source: Source):
        """Select the feed adapter for a source. Defaults to the shared
        RSSAtomAdapter; sources with a JSON-only feed use their dedicated
        adapter instead (see _JSON_ADAPTERS_BY_SOURCE_NAME)."""
        return _JSON_ADAPTERS_BY_SOURCE_NAME.get(source.name, self.adapter)
    
    async def run(self) -> Dict[str, Any]:
        """Run ingestion. Return results."""
        run_id = str(uuid.uuid4())
        start = datetime.now(timezone.utc)

        logger.info(f"Run {run_id} started")

        # Sync VERIFIED_FEEDS into the real Source table before fetching, so
        # a source added/changed in code (e.g. a new source for category
        # coverage) actually takes effect on the very next run, rather than
        # silently never being fetched until someone remembers to run this
        # by hand. Idempotent and safe to run every cycle - it only adds
        # missing sources and corrects a changed name/type, never touches
        # per-source health/failure state (SourceRegistry.record_success/
        # record_failure own that).
        self.registry.init_default_sources()

        results = {
            'run_id': run_id,
            'start_time': start.isoformat(),
            'sources': {},
            'total_fetched': 0,
            'total_created': 0,
            'total_duplicated': 0,
            'total_relevant': 0,
            'total_new_events': 0,
            'errors': [],
        }

        sources = self.registry.get_sources_to_fetch()
        logger.info(f"Fetching {len(sources)} sources")

        for source in sources:
            src_result = await self._ingest_source(source)
            results['sources'][source.name] = src_result

            results['total_fetched'] += src_result['fetched']
            results['total_created'] += src_result['created']
            results['total_duplicated'] += src_result['duplicated']
            results['total_relevant'] += src_result['relevant']
            results['total_new_events'] += src_result['new_events']

        results['end_time'] = datetime.now(timezone.utc).isoformat()

        # No-new-data is a normal, successful outcome (Change 11) - not an
        # error condition. Every source was still checked, dedup and
        # relevance still ran; there just wasn't anything new to group into
        # an event this time. Logged explicitly so it's visible in ops
        # without being conflated with a failed run.
        if results['total_new_events'] == 0:
            logger.info(f"Run {run_id} complete: no new qualifying events this cycle")
        else:
            logger.info(f"Run {run_id} complete: {results['total_new_events']} new event(s)")

        return results
    
    async def _ingest_source(self, source: Source) -> Dict[str, Any]:
        """Ingest single source."""
        result = {
            'name': source.name,
            'fetched': 0,
            'created': 0,
            'duplicated': 0,
            'relevant': 0,
            'new_events': 0,
            'skipped_stale': 0,
            'status': 'success',
            'error': None,
        }

        # Freshness checkpoint: the timestamp of this source's last
        # successful run, read BEFORE this run updates it. None on a
        # source's first-ever run (or if it has never succeeded), in which
        # case every entry in the fetch-limited page is treated as
        # eligible - there is no prior checkpoint to compare against.
        # See app/ingestion/freshness_policy.py for the centralized policy.
        cutoff = compute_freshness_cutoff(source.last_ingested_at, self.freshness_policy)

        try:
            logger.info(f"Fetching {source.name}")

            # Fetch
            try:
                feed_bytes = await self.http_client.fetch(source.url)
            except (HTTPError, SSRFError) as e:
                logger.error(f"Fetch failed {source.name}: {e}")
                self.registry.record_failure(source, str(e))
                result['status'] = 'failed'
                result['error'] = str(e)
                return result

            # Parse
            try:
                feed = self._adapter_for(source).parse(feed_bytes, source.url)
            except ValueError as e:
                logger.error(f"Parse failed {source.name}: {e}")
                self.registry.record_failure(source, f"Parse: {str(e)}")
                result['status'] = 'failed'
                result['error'] = f"Parse: {str(e)}"
                return result

            logger.info(f"Parsed {len(feed.entries)} entries from {source.name}")

            # Process
            for entry in feed.entries:
                try:
                    # Freshness vs fetch-limit: the adapter already bounded
                    # how many entries came back (the fetch limit). This is
                    # the separate recency check - an entry older than the
                    # last successful checkpoint (minus grace) is not new,
                    # so it's skipped before even touching dedup/storage.
                    # An entry with no published timestamp can't be
                    # freshness-filtered, so it's still processed (dedup
                    # still protects against reprocessing it repeatedly).
                    if is_stale_entry(entry.published, cutoff):
                        result['skipped_stale'] += 1
                        continue

                    result['fetched'] += 1

                    article, status = await ArticleNormalizer.normalize_and_store(
                        self.session, entry, source
                    )

                    if status.startswith('duplicate'):
                        result['duplicated'] += 1
                        continue

                    if not article or status.startswith('error'):
                        continue

                    result['created'] += 1

                    # Relevance
                    relevant = self.classifier.is_relevant(article.title, article.description or '')
                    article.is_relevant = relevant

                    if relevant:
                        result['relevant'] += 1

                        # Event
                        event, event_created = self.grouper.find_or_create_event(
                            article.title, article.description or ''
                        )
                        if event_created:
                            result['new_events'] += 1

                        # Link
                        if event not in article.events:
                            article.events.append(event)

                    self.session.add(article)

                except Exception as e:
                    logger.debug(f"Entry error: {e}")
            
            # Commit
            try:
                self.session.commit()
                logger.info(f"Committed {result['created']} articles from {source.name}")
            except Exception as e:
                logger.error(f"Commit failed {source.name}: {e}")
                self.session.rollback()
                result['status'] = 'failed'
                result['error'] = f"Commit: {str(e)}"
                return result
            
            # Success
            self.registry.record_success(source)
        
        except Exception as e:
            logger.error(f"Unexpected {source.name}: {e}")
            result['status'] = 'failed'
            result['error'] = str(e)
        
        return result
