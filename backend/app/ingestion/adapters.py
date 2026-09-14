"""Feed parsing adapters: RSS/Atom, plus JSON adapters for sources whose
RSS/Atom feed has been discontinued (see app/ingestion/sources.py for the
per-source verification notes). Every adapter here produces the same
Feed/FeedEntry shape, so the rest of the pipeline (ArticleNormalizer,
IngestionOrchestrator, dedup, relevance classification) is adapter-agnostic
and required no changes to support these."""

import json
import logging
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    import feedparser
except ImportError:
    raise ImportError("feedparser required: pip install feedparser")

logger = logging.getLogger(__name__)


@dataclass
class FeedEntry:
    """Parsed feed entry."""
    url: str
    title: str
    summary: Optional[str]
    published: Optional[datetime]
    external_id: Optional[str] = None


@dataclass
class Feed:
    """Parsed feed."""
    title: str
    entries: List[FeedEntry]
    source_url: str


class RSSAtomAdapter:
    """Parse RSS/Atom feeds."""
    
    def parse(self, content: bytes, source_url: str) -> Feed:
        """Parse feed from bytes."""
        if not content:
            raise ValueError("Empty content")
        
        parsed = feedparser.parse(content)
        
        if parsed.bozo and parsed.bozo_exception:
            logger.warning(f"Feed parse warning: {parsed.bozo_exception}")
        
        feed_title = parsed.feed.get('title', 'Unknown')
        entries = []
        
        for entry in parsed.entries:
            try:
                fe = self._parse_entry(entry)
                entries.append(fe)
            except ValueError as e:
                logger.debug(f"Skip entry: {e}")
        
        return Feed(title=feed_title, entries=entries, source_url=source_url)
    
    def _parse_entry(self, entry) -> FeedEntry:
        """Parse single entry."""
        url = entry.get('link') or entry.get('id')
        if not url:
            raise ValueError("No URL")
        
        title = entry.get('title')
        if not title:
            raise ValueError("No title")
        
        summary = entry.get('summary') or entry.get('description')
        
        published = None
        if hasattr(entry, 'published_parsed') and entry.published_parsed:
            try:
                published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            except (TypeError, ValueError):
                pass
        elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
            try:
                published = datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc)
            except (TypeError, ValueError):
                pass
        
        return FeedEntry(
            url=url,
            title=title,
            summary=summary,
            published=published,
            external_id=entry.get('id')
        )


class GitHubAdvisoriesJSONAdapter:
    """Parse the GitHub Security Advisories JSON REST API
    (https://api.github.com/advisories) into the same Feed/FeedEntry shape
    RSSAtomAdapter produces.

    GitHub's Atom feed (github.com/advisories.atom) returns 406 for every
    request header combination tried (verified 2026-09-12 - the endpoint is
    discontinued, not a missing-header issue; see app/ingestion/sources.py).
    This JSON API is GitHub's only current machine-readable advisory feed.
    """

    MAX_TITLE_LENGTH = 500

    def parse(self, content: bytes, source_url: str) -> Feed:
        if not content:
            raise ValueError("Empty content")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

        if not isinstance(data, list):
            raise ValueError("Expected a JSON array of advisories")

        entries = []
        for item in data:
            try:
                entries.append(self._parse_entry(item))
            except ValueError as e:
                logger.debug(f"Skip GitHub advisory entry: {e}")

        return Feed(title="GitHub Security Advisories", entries=entries, source_url=source_url)

    def _parse_entry(self, item: dict) -> FeedEntry:
        url = item.get('html_url')
        if not url:
            raise ValueError("No html_url")

        ghsa_id = item.get('ghsa_id')
        title = (item.get('summary') or '').strip() or ghsa_id
        if not title:
            raise ValueError("No title")
        if len(title) > self.MAX_TITLE_LENGTH:
            title = title[: self.MAX_TITLE_LENGTH - 1].rstrip() + "…"

        published = None
        published_at = item.get('published_at')
        if published_at:
            try:
                published = datetime.fromisoformat(published_at.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                pass

        return FeedEntry(
            url=url,
            title=title,
            summary=item.get('description'),
            published=published,
            external_id=ghsa_id,
        )


# Apache HTTP Server security advisories are published per major branch, each
# with its own page and #CVE-ID anchors - verified by fetching
# vulnerabilities_24.html and vulnerabilities_22.html directly and confirming
# a matching id="CVE-..." anchor exists on the branch(es) a given CVE
# actually affects (a 2.2-only CVE is present on the 2.2 page but absent
# from the 2.4 page, so branch must be resolved per-entry, not assumed).
_APACHE_VERSION_PRIORITY = ["2.4", "2.2", "2.0", "1.3"]
_APACHE_VERSION_PAGES = {
    "2.4": "vulnerabilities_24.html",
    "2.2": "vulnerabilities_22.html",
    "2.0": "vulnerabilities_20.html",
    "1.3": "vulnerabilities_13.html",
}


class ApacheHTTPDJSONAdapter:
    """Parse Apache HTTP Server's JSON CVE export
    (https://httpd.apache.org/security/vulnerabilities-httpd.json, MITRE CVE
    format) into the same Feed/FeedEntry shape RSSAtomAdapter produces.

    httpd's RSS feed (rss.xml) is confirmed gone (404); this JSON export is
    Apache's only current machine-readable replacement. The JSON is a full
    historical CVE archive (hundreds of entries back to the mid-2000s), not
    a feed of recent items, so only the MAX_ENTRIES most recently published
    records are returned - mirroring how a live feed naturally surfaces
    recent items instead of replaying the entire archive on every run.
    """

    BASE_URL = "https://httpd.apache.org/security/"
    MAX_TITLE_LENGTH = 500
    MAX_ENTRIES = 30

    def parse(self, content: bytes, source_url: str) -> Feed:
        if not content:
            raise ValueError("Empty content")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

        if not isinstance(data, list):
            raise ValueError("Expected a JSON array of CVE records")

        parsed = []
        for item in data:
            try:
                published, entry = self._parse_entry(item)
                parsed.append((published, entry))
            except ValueError as e:
                logger.debug(f"Skip Apache CVE entry: {e}")

        # Most recently published first; take only the most recent window.
        parsed.sort(key=lambda pair: pair[0], reverse=True)
        entries = [entry for _, entry in parsed[: self.MAX_ENTRIES]]

        return Feed(title="Apache HTTP Server Security", entries=entries, source_url=source_url)

    def _parse_entry(self, item: dict):
        meta = item.get('CVE_data_meta') or {}
        cve_id = meta.get('ID')
        if not cve_id:
            raise ValueError("No CVE ID")

        date_str = meta.get('DATE_PUBLIC')
        if not date_str:
            raise ValueError(f"No DATE_PUBLIC for {cve_id}")
        try:
            published = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            raise ValueError(f"Bad DATE_PUBLIC for {cve_id}: {date_str}")

        title = meta.get('TITLE') or cve_id
        if len(title) > self.MAX_TITLE_LENGTH:
            title = title[: self.MAX_TITLE_LENGTH - 1].rstrip() + "…"

        summary = None
        try:
            summary = item['description']['description_data'][0]['value']
        except (KeyError, IndexError, TypeError):
            pass

        url = f"{self.BASE_URL}{self._resolve_page(item)}#{cve_id}"

        return published, FeedEntry(
            url=url,
            title=title,
            summary=summary,
            published=published,
            external_id=cve_id,
        )

    def _resolve_page(self, item: dict) -> str:
        """Pick the branch-specific advisories page a CVE's #anchor actually
        lives on. Falls back to the current stable branch's page if the
        affected branch can't be determined from the record."""
        versions = set()
        try:
            for vendor in item['affects']['vendor']['vendor_data']:
                for product in vendor.get('product', {}).get('product_data', []):
                    for v in product.get('version', {}).get('version_data', []):
                        name = v.get('version_name') or ''
                        for branch in _APACHE_VERSION_PRIORITY:
                            if branch in name:
                                versions.add(branch)
        except (KeyError, TypeError, AttributeError):
            pass

        for branch in _APACHE_VERSION_PRIORITY:
            if branch in versions:
                return _APACHE_VERSION_PAGES[branch]

        return _APACHE_VERSION_PAGES["2.4"]
