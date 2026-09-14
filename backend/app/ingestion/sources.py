"""Source registry and failure state machine."""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from app.db.models import Source, SourceType

logger = logging.getLogger(__name__)


class SourceConfig:
    """Source failure tracking."""
    
    def __init__(self):
        self.enabled: bool = True
        self.consecutive_failures: int = 0
        self.last_failure: Optional[datetime] = None
        self.last_success: Optional[datetime] = None
        self.next_retry: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize."""
        return {
            'enabled': self.enabled,
            'consecutive_failures': self.consecutive_failures,
            'last_failure': self.last_failure.isoformat() if self.last_failure else None,
            'last_success': self.last_success.isoformat() if self.last_success else None,
            'next_retry': self.next_retry.isoformat() if self.next_retry else None,
        }
    
    @staticmethod
    def from_dict(data: Optional[Dict]) -> 'SourceConfig':
        """Deserialize."""
        cfg = SourceConfig()
        if not data:
            return cfg
        
        cfg.enabled = data.get('enabled', True)
        cfg.consecutive_failures = data.get('consecutive_failures', 0)
        
        for field in ['last_failure', 'last_success', 'next_retry']:
            if data.get(field):
                setattr(cfg, field, datetime.fromisoformat(data[field]))
        
        return cfg


VERIFIED_FEEDS = [
    # GitHub Security Advisories: the .atom endpoint is confirmed discontinued
    # (406 on every header combination tried, re-verified 2026-09-12/09-14 -
    # the endpoint itself is gone, not a missing-header problem). GitHub's
    # only current machine-readable advisory feed is the JSON REST API
    # (https://api.github.com/advisories, confirmed 200 2026-09-14), sorted
    # by most-recently-published to behave like a live feed. Parsed by
    # GitHubAdvisoriesJSONAdapter (see app/ingestion/adapters.py) - the
    # RSS/Atom-only adapter cannot parse this, hence type=API.
    {
        'name': 'GitHub Security Advisories',
        'type': SourceType.API,
        'url': 'https://api.github.com/advisories?per_page=30&sort=published&direction=desc',
    },
    # Apache HTTP Server Security: rss.xml is confirmed gone (404,
    # re-verified 2026-09-12/09-14). Apache's only current machine-readable
    # feed is JSON (https://httpd.apache.org/security/vulnerabilities-httpd.json,
    # confirmed 200 2026-09-14, MITRE CVE format) - a full historical CVE
    # archive rather than a feed, parsed and windowed to the most recent
    # entries by ApacheHTTPDJSONAdapter (see app/ingestion/adapters.py).
    # Also checked httpd's mailing-list archive (lists.apache.org/list.html?
    # announce@httpd.apache.org) for a feed - it's a JS-rendered page with no
    # RSS/Atom autodiscovery link, so no better alternative exists.
    {
        'name': 'Apache HTTP Server Security',
        'type': SourceType.API,
        'url': 'https://httpd.apache.org/security/vulnerabilities-httpd.json',
    },
    {'name': 'Ubuntu Security Notices', 'type': SourceType.RSS, 'url': 'https://usn.ubuntu.com/usn/rss.xml'},
    # Nginx: /feed/ is gone (404). Verified working replacement is the
    # official NGINX community blog RSS feed (confirmed 200, valid RSS 2.0,
    # 2026-09). This is nginx's project blog rather than a security-only
    # feed - no dedicated security-advisories-only feed was found anywhere
    # on nginx.org or its mailing list archive. The pipeline's existing
    # RelevanceClassifier keyword filter still narrows this down to
    # security-relevant items downstream.
    {'name': 'Nginx Security Advisories', 'type': SourceType.RSS, 'url': 'https://blog.nginx.org/feed'},
    {'name': 'PHP Releases', 'type': SourceType.RSS, 'url': 'https://www.php.net/releases/feed.php'},
    # PostgreSQL: /about/news.rss is gone (404). Verified working replacement
    # at the project's current news RSS path (confirmed 200, valid RSS 2.0,
    # 2026-09).
    {'name': 'PostgreSQL News', 'type': SourceType.RSS, 'url': 'https://www.postgresql.org/news.rss'},
    # OpenSSL: the whole project site moved from openssl.org to
    # openssl-library.org; the old feed URL 404s (and the openssl.org URL
    # itself now just redirects back to the dead openssl.org path, not to
    # anything on the new site). Re-checked the new site's News page
    # directly (2026-09): it now has <link rel="alternate"> feed
    # autodiscovery for both RSS and Atom. Verified working replacement is
    # the RSS one (confirmed 200, valid RSS 2.0 with real entries incl.
    # release/vulnerability announcements, 2026-09). Same tradeoff as
    # Nginx/Kubernetes below - project news feed rather than security-only,
    # narrowed downstream by RelevanceClassifier.
    {'name': 'OpenSSL Security', 'type': SourceType.RSS, 'url': 'https://openssl-library.org/news/index.xml'},
    # Kubernetes: the classic Google Groups feed export
    # (.../feeds/msgs.xml) is gone (404 on every variant tried) - Google
    # discontinued classic Groups feed exports. The kubernetes-security-announce
    # group itself is still active, but has no working feed export anymore.
    # Verified working replacement is the official Kubernetes project blog
    # RSS feed (confirmed 200, valid RSS 2.0, 2026-09) - broader than
    # security-only announcements, same tradeoff/reasoning as Nginx above.
    {'name': 'Kubernetes Security', 'type': SourceType.RSS, 'url': 'https://kubernetes.io/feed.xml'},
]


class SourceRegistry:
    """Manage sources."""
    
    MAX_FAILURES = 5
    
    def __init__(self, session: Session):
        self.session = session
    
    def init_default_sources(self):
        """Create default sources, and sync the URL/type of existing ones to
        VERIFIED_FEEDS so a corrected feed URL actually takes effect on a
        DB that was already seeded."""
        for feed in VERIFIED_FEEDS:
            existing = self.session.query(Source).filter_by(name=feed['name']).one_or_none()
            if not existing:
                self.session.add(Source(name=feed['name'], source_type=feed['type'], url=feed['url'], config={}))
            elif existing.url != feed['url'] or existing.source_type != feed['type']:
                existing.url = feed['url']
                existing.source_type = feed['type']
                self.session.add(existing)
        
        self.session.commit()
    
    def get_config(self, source: Source) -> SourceConfig:
        """Get state."""
        return SourceConfig.from_dict(source.config or {})
    
    def record_success(self, source: Source):
        """Mark successful."""
        cfg = self.get_config(source)
        cfg.consecutive_failures = 0
        cfg.last_success = datetime.now(timezone.utc)
        cfg.enabled = True
        source.config = cfg.to_dict()
        self.session.add(source)
        self.session.commit()
    
    def record_failure(self, source: Source, reason: str) -> bool:
        """Mark failed. Return: enabled?"""
        cfg = self.get_config(source)
        cfg.consecutive_failures += 1
        cfg.last_failure = datetime.now(timezone.utc)
        
        backoff = min(60 * (2 ** (cfg.consecutive_failures - 1)), 86400)
        cfg.next_retry = datetime.now(timezone.utc) + timedelta(seconds=backoff)
        
        if cfg.consecutive_failures >= self.MAX_FAILURES:
            cfg.enabled = False
        
        source.config = cfg.to_dict()
        self.session.add(source)
        self.session.commit()
        
        return cfg.enabled
    
    def get_sources_to_fetch(self) -> List[Source]:
        """Get enabled sources."""
        sources = self.session.query(Source).all()
        ready = []
        
        for source in sources:
            cfg = self.get_config(source)
            if cfg.enabled:
                ready.append(source)
            elif cfg.next_retry and datetime.now(timezone.utc) >= cfg.next_retry:
                ready.append(source)
        
        return ready
