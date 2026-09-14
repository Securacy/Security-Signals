"""Main ingestion orchestration."""

import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any
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

    def __init__(self, session: Session):
        self.session = session
        self.registry = SourceRegistry(session)
        self.adapter = RSSAtomAdapter()
        self.http_client = HTTPClient()
        self.classifier = RelevanceClassifier()
        self.grouper = EventGrouper(session)

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
        
        results = {
            'run_id': run_id,
            'start_time': start.isoformat(),
            'sources': {},
            'total_fetched': 0,
            'total_created': 0,
            'total_duplicated': 0,
            'total_relevant': 0,
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
        
        results['end_time'] = datetime.now(timezone.utc).isoformat()
        
        logger.info(f"Run {run_id} complete: {results['total_created']} new")
        
        return results
    
    async def _ingest_source(self, source: Source) -> Dict[str, Any]:
        """Ingest single source."""
        result = {
            'name': source.name,
            'fetched': 0,
            'created': 0,
            'duplicated': 0,
            'relevant': 0,
            'status': 'success',
            'error': None,
        }
        
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
                        event = self.grouper.find_or_create_event(
                            article.title, article.description or ''
                        )
                        
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
