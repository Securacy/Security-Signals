"""Article normalization and deduplication."""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse, urljoin
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.db.models import Article, Source
from app.ingestion.adapters import FeedEntry

logger = logging.getLogger(__name__)


class ArticleNormalizer:
    """Normalize and deduplicate articles."""
    
    @staticmethod
    def compute_hash(title: str, summary: Optional[str]) -> str:
        """Content hash."""
        content = f"{title}|{summary or ''}".encode('utf-8', errors='replace')
        return hashlib.sha256(content).hexdigest()
    
    @staticmethod
    def normalize_url(url: str, base_url: Optional[str] = None) -> str:
        """Normalize URL."""
        if not url:
            raise ValueError("Empty URL")
        
        if base_url and not url.startswith(('http://', 'https://')):
            url = urljoin(base_url, url)
        
        parsed = urlparse(url)
        normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
        if parsed.params:
            normalized += f";{parsed.params}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        
        if len(normalized) > 2048:
            raise ValueError("URL too long")
        
        return normalized
    
    @staticmethod
    async def normalize_and_store(
        session: Session,
        entry: FeedEntry,
        source: Source,
    ) -> Tuple[Optional[Article], str]:
        """Normalize and store article. Returns (article, status)."""
        try:
            # Normalize URL
            try:
                norm_url = ArticleNormalizer.normalize_url(entry.url, source.url)
            except ValueError as e:
                logger.debug(f"Bad URL: {entry.url}: {e}")
                return None, "error_invalid_url"
            
            # Check URL duplicate
            existing = session.query(Article).filter_by(url=norm_url).one_or_none()
            if existing:
                return existing, "duplicate_url"
            
            # Compute hash
            content_hash = ArticleNormalizer.compute_hash(entry.title, entry.summary)
            
            # Check hash duplicate
            existing = (
                session.query(Article)
                .filter_by(source_id=source.id, content_hash=content_hash)
                .one_or_none()
            )
            if existing:
                return existing, "duplicate_hash"
            
            # Create
            article = Article(
                source_id=source.id,
                external_id=entry.external_id,
                url=norm_url,
                canonical_url=entry.url if entry.url != norm_url else None,
                title=entry.title,
                description=entry.summary,
                published_at=entry.published,
                ingested_at=datetime.now(timezone.utc),
                content_hash=content_hash,
                is_relevant=False,
                relevance_score=0.0,
            )
            
            session.add(article)
            
            try:
                session.flush()
                return article, "created"
            except IntegrityError:
                session.rollback()
                
                # Check again
                existing = session.query(Article).filter_by(url=norm_url).one_or_none()
                if existing:
                    return existing, "duplicate_url"
                
                existing = (
                    session.query(Article)
                    .filter_by(source_id=source.id, content_hash=content_hash)
                    .one_or_none()
                )
                if existing:
                    return existing, "duplicate_hash"
                
                return None, "error_race"
        
        except Exception as e:
            logger.error(f"Normalize error: {e}")
            return None, f"error_exception"
