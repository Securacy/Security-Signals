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
    # AI Security (dedicated source - required for Security Signals as a
    # threat-modeling platform to have real AI-security coverage that
    # doesn't depend on incidentally finding AI-related items in generic
    # sources). OWASP's own Gen AI Security Project blog - confirmed 200,
    # valid RSS 2.0 with genuinely AI-security-focused content (prompt
    # injection, agent memory/context poisoning, exploit round-ups), 2026-09.
    # Chosen over the AI Incident Database's RSS feed (also verified live)
    # because that feed is a broad AI-harm-incident aggregator - mixed
    # languages, mostly non-security societal-harm reporting - which would
    # need heavy additional filtering to be a precise security source;
    # OWASP's own project blog is precision security content already.
    {
        'name': 'OWASP GenAI Security Project',
        'type': SourceType.RSS,
        'url': 'https://genai.owasp.org/feed/',
        'tier': 1,
        'categories': ['ai_security'],
    },
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
        'tier': 1,
        'categories': ['app_api', 'supply_chain', 'iam'],
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
        'tier': 1,
        'categories': ['infrastructure', 'app_api'],
    },
    {'name': 'Ubuntu Security Notices', 'type': SourceType.RSS, 'url': 'https://usn.ubuntu.com/usn/rss.xml', 'tier': 1, 'categories': ['infrastructure']},
    # Nginx: /feed/ is gone (404). Verified working replacement is the
    # official NGINX community blog RSS feed (confirmed 200, valid RSS 2.0,
    # 2026-09). This is nginx's project blog rather than a security-only
    # feed - no dedicated security-advisories-only feed was found anywhere
    # on nginx.org or its mailing list archive. The pipeline's existing
    # RelevanceClassifier keyword filter still narrows this down to
    # security-relevant items downstream.
    {'name': 'Nginx Security Advisories', 'type': SourceType.RSS, 'url': 'https://blog.nginx.org/feed', 'tier': 1, 'categories': ['infrastructure']},
    {'name': 'PHP Releases', 'type': SourceType.RSS, 'url': 'https://www.php.net/releases/feed.php', 'tier': 1, 'categories': ['app_api', 'infrastructure']},
    # PostgreSQL: /about/news.rss is gone (404). Verified working replacement
    # at the project's current news RSS path (confirmed 200, valid RSS 2.0,
    # 2026-09).
    {'name': 'PostgreSQL News', 'type': SourceType.RSS, 'url': 'https://www.postgresql.org/news.rss', 'tier': 1, 'categories': ['infrastructure']},
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
    {'name': 'OpenSSL Security', 'type': SourceType.RSS, 'url': 'https://openssl-library.org/news/index.xml', 'tier': 1, 'categories': ['infrastructure', 'insecure_design']},
    # Kubernetes: the classic Google Groups feed export
    # (.../feeds/msgs.xml) is gone (404 on every variant tried) - Google
    # discontinued classic Groups feed exports. The kubernetes-security-announce
    # group itself is still active, but has no working feed export anymore.
    # Verified working replacement is the official Kubernetes project blog
    # RSS feed (confirmed 200, valid RSS 2.0, 2026-09) - broader than
    # security-only announcements, same tradeoff/reasoning as Nginx above.
    {'name': 'Kubernetes Security', 'type': SourceType.RSS, 'url': 'https://kubernetes.io/feed.xml', 'tier': 1, 'categories': ['infrastructure', 'cloud_security']},

    # --- Added for category coverage (dedicated-source requirement) ---
    # All three verified live (200, valid feed, genuinely security-relevant
    # content) before being added here - none invented.

    # CISA Advisories: the US government's own known-exploited-vulnerability
    # and advisory feed - confirmed 200, valid RSS 2.0, 2026-09. Authoritative
    # (Tier 1) primary source for Threat Intelligence; also carries
    # infrastructure and design-relevant advisories.
    {
        'name': 'CISA Advisories',
        'type': SourceType.RSS,
        'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
        'tier': 1,
        'categories': ['threat_intel', 'infrastructure', 'insecure_design'],
    },
    # BleepingComputer: confirmed 200, valid RSS, real recent security
    # journalism spanning ransomware, malware, breaches, and threat actor
    # activity. Not a primary vendor/government advisory source, so Tier 2
    # (secondary/redundant coverage) rather than Tier 1.
    {
        'name': 'BleepingComputer',
        'type': SourceType.RSS,
        'url': 'https://www.bleepingcomputer.com/feed/',
        'tier': 2,
        'categories': ['ransomware', 'threat_intel', 'data_privacy'],
    },
    # Krebs on Security: confirmed 200, valid RSS. Established, authoritative
    # independent security journalism, frequently first to report breaches
    # and privacy incidents. Tier 2 for the same reason as BleepingComputer.
    {
        'name': 'Krebs on Security',
        'type': SourceType.RSS,
        'url': 'https://krebsonsecurity.com/feed/',
        'tier': 2,
        'categories': ['data_privacy', 'threat_intel'],
    },

    # --- Added for STRICT dedicated-source-per-category hardening ---
    # Every URL below was curl-verified live (200, correct feed content-type,
    # real recent entries, genuinely relevant to the assigned category)
    # before being added - none invented. Rejected in the same pass:
    # Google Cloud's cloud-security-bulletins.xml (404, discontinued), MSRC's
    # /blog/feed (200 but returns an HTML page, not a real feed - no working
    # MSRC feed exists), OWASP's own rss/news.xml (404).

    # Okta Security Research: the identity vendor's own dedicated security
    # research blog - confirmed 200, valid RSS, real vulnerability-research
    # content (e.g. "Hunting Vulnerabilities Using Frontier Models",
    # protocol-level DoS writeups). This is a genuinely IAM-dedicated
    # Tier-1 source, closing the gap documented in the previous phase.
    {
        'name': 'Okta Security',
        'type': SourceType.RSS,
        'url': 'https://sec.okta.com/rss.xml',
        'tier': 1,
        'categories': ['iam'],
    },
    # Auth0 Blog: confirmed 200, valid RSS. Auth0 (an Okta company) publishes
    # real, specific identity/access-token/authorization content (e.g.
    # "Why Your Auth0 Permissions Are Not in your Access Token"). Secondary
    # (Tier 2) IAM coverage alongside Okta Security above, from a different
    # editorial source so one failing doesn't remove all IAM-vendor coverage.
    {
        'name': 'Auth0 Blog',
        'type': SourceType.RSS,
        'url': 'https://auth0.com/blog/rss.xml',
        'tier': 2,
        'categories': ['iam'],
    },
    # AWS Security Bulletins: confirmed 200, valid RSS. AWS's own official
    # per-CVE bulletin feed - real, current entries (e.g. AWS Systems
    # Manager SSRF, OpenSearch authorization issues, and Bedrock AgentCore
    # input-validation issues). A genuinely Cloud-Security-dedicated Tier-1
    # source, closing the other gap documented in the previous phase. Also
    # cross-listed for ai_security since AWS's own Bedrock/AI service
    # advisories appear in this same feed - real content, not inferred.
    {
        'name': 'AWS Security Bulletins',
        'type': SourceType.RSS,
        'url': 'https://aws.amazon.com/security/security-bulletins/rss/feed/',
        'tier': 1,
        'categories': ['cloud_security', 'ai_security'],
    },
    # Microsoft Security Blog: confirmed 200, valid RSS. Official Microsoft
    # security research and threat coverage - real recent entries actually
    # spanning AI-specific threats ("AI-assisted executive impersonation",
    # "AI-themed attacks") and cloud application threat coverage. Tier 2
    # secondary source for both categories (vendor blog, not a per-CVE
    # advisory feed like AWS's above).
    {
        'name': 'Microsoft Security Blog',
        'type': SourceType.RSS,
        'url': 'https://www.microsoft.com/en-us/security/blog/feed/',
        'tier': 2,
        'categories': ['cloud_security', 'ai_security'],
    },
    # Google Online Security Blog: confirmed 200 (via its real, current feed
    # URL - the vanity security.googleblog.com path redirects here), valid
    # Atom feed, real recent entries directly on point ("AI threats in the
    # wild: prompt injections on the web"). Tier 2 secondary source,
    # deliberately a third, independent vendor for AI Security given its
    # explicit priority (Section 19).
    {
        'name': 'Google Online Security Blog',
        'type': SourceType.RSS,
        'url': 'https://feeds.feedburner.com/GoogleOnlineSecurityBlog',
        'tier': 2,
        'categories': ['ai_security', 'cloud_security'],
    },
    # Unit 42 (Palo Alto Networks): confirmed 200, valid RSS. Authoritative
    # threat-research organization - real recent entries on active
    # campaigns, malware, and (directly relevant) cloud-identity attack
    # clustering. Tier 1 dedicated Threat Intelligence source; also
    # cross-listed for ransomware (their core beat) and ai_security (they
    # publish dedicated AI-security research too).
    {
        'name': 'Unit 42',
        'type': SourceType.RSS,
        'url': 'https://unit42.paloaltonetworks.com/feed/',
        'tier': 1,
        'categories': ['threat_intel', 'ransomware', 'ai_security'],
    },
    # PortSwigger Research: confirmed 200, valid RSS. The Burp Suite team's
    # own web-security research blog - real, technical application-security
    # content (browser/JS security quirks, request-smuggling-adjacent
    # research). A genuinely dedicated Tier-1 source for App/API Security,
    # and cross-listed for Insecure Design since their research is
    # frequently about exploitable design assumptions, not just individual
    # bugs.
    {
        'name': 'PortSwigger Research',
        'type': SourceType.RSS,
        'url': 'https://portswigger.net/research/rss',
        'tier': 1,
        'categories': ['app_api', 'insecure_design'],
    },
    # Sonatype Blog: confirmed 200 (via its real current feed URL - the
    # legacy blog.sonatype.com/rss.xml path redirects here), valid RSS.
    # Sonatype is a software-supply-chain-security vendor (Nexus/OSS Index);
    # its blog mixes general content with real supply-chain-security posts.
    # Tier 2 secondary Supply Chain source alongside GitHub Security
    # Advisories (Tier 1) above.
    {
        'name': 'Sonatype Blog',
        'type': SourceType.RSS,
        'url': 'https://www.sonatype.com/blog/rss.xml',
        'tier': 2,
        'categories': ['supply_chain'],
    },
    # Have I Been Pwned - breach feed: confirmed 200 (via its real current
    # feed URL - /feed redirects here), valid RSS. A purpose-built breach-
    # notification feed (real entries: "Chess.com - 4,653,212 breached
    # accounts", "McKesson - 6,404,340 breached accounts") - about as
    # precisely dedicated to Data Privacy as a source can be. Closes the
    # previous phase's data_privacy Tier-1 gap (it had secondary coverage
    # only, via BleepingComputer/Krebs).
    {
        'name': 'Have I Been Pwned Breaches',
        'type': SourceType.RSS,
        'url': 'https://haveibeenpwned.com/feed/breaches',
        'tier': 1,
        'categories': ['data_privacy'],
    },
    # DataBreaches.Net: confirmed 200 (via its real current feed URL -
    # www.databreaches.net/feed/ redirects here), valid RSS. An
    # independent, breach-reporting-only outlet - real, current entries
    # spanning breach notifications and ransomware-caused breaches. Tier 2
    # secondary Data Privacy source alongside Have I Been Pwned above.
    {
        'name': 'DataBreaches.Net',
        'type': SourceType.RSS,
        'url': 'https://databreaches.net/feed/',
        'tier': 2,
        'categories': ['data_privacy'],
    },
]

# As of this phase, every one of the 10 canonical categories has at least
# one dedicated Tier-1 source (see the per-category comments above) - IAM
# (Okta Security) and Cloud Security (AWS Security Bulletins) were the two
# gaps from the previous phase, now closed with real, verified sources.
# Kept as an empty list (rather than removed) so category_health_service and
# any future gap can still report against it honestly if a source is later
# disabled/removed.
CATEGORIES_WITHOUT_DEDICATED_TIER1_SOURCE: list = []


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
        """Mark successful, and advance the freshness checkpoint
        (Source.last_ingested_at) used to distinguish "new since last run"
        from "within this run's fetch-limit page" (see IngestionOrchestrator
        - Change 10: freshness and fetch limit are separate concepts)."""
        cfg = self.get_config(source)
        cfg.consecutive_failures = 0
        cfg.last_success = datetime.now(timezone.utc)
        cfg.enabled = True
        source.config = cfg.to_dict()
        source.last_ingested_at = cfg.last_success
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
