"""Tests for feed adapters."""

import json
import pytest
from app.ingestion.adapters import (
    RSSAtomAdapter, GitHubAdvisoriesJSONAdapter, ApacheHTTPDJSONAdapter
)


class TestRSSAtomAdapter:
    """RSS/Atom parsing tests."""
    
    def test_parse_rss_feed(self):
        """Parse RSS 2.0 feed."""
        rss_content = b"""<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>CVE-2024-1234</title>
      <link>https://example.com/cve1</link>
      <description>Test vulnerability</description>
      <pubDate>Mon, 10 Sep 2024 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>"""
        
        adapter = RSSAtomAdapter()
        feed = adapter.parse(rss_content, "https://example.com/feed.rss")
        
        assert feed.title == "Test Feed"
        assert len(feed.entries) == 1
        
        entry = feed.entries[0]
        assert entry.title == "CVE-2024-1234"
        assert entry.url == "https://example.com/cve1"
        assert "vulnerability" in entry.summary.lower()
    
    def test_parse_atom_feed(self):
        """Parse Atom feed."""
        atom_content = b"""<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Security Feed</title>
  <entry>
    <title>Security Advisory</title>
    <link href="https://example.com/advisory1"/>
    <summary>Important security update</summary>
    <published>2024-09-10T12:00:00Z</published>
  </entry>
</feed>"""
        
        adapter = RSSAtomAdapter()
        feed = adapter.parse(atom_content, "https://example.com/feed.atom")
        
        assert feed.title == "Security Feed"
        assert len(feed.entries) == 1
        
        entry = feed.entries[0]
        assert entry.title == "Security Advisory"
        assert entry.url == "https://example.com/advisory1"
    
    def test_empty_content_rejected(self):
        """Empty feed rejected."""
        adapter = RSSAtomAdapter()
        
        with pytest.raises(ValueError):
            adapter.parse(b'', "https://example.com/feed.rss")
    
    def test_entry_without_url_skipped(self):
        """Entry without URL skipped."""
        rss = b"""<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Feed</title>
    <item>
      <title>No URL</title>
      <description>This entry has no link</description>
    </item>
  </channel>
</rss>"""
        
        adapter = RSSAtomAdapter()
        feed = adapter.parse(rss, "https://example.com/feed.rss")

        assert len(feed.entries) == 0


class TestGitHubAdvisoriesJSONAdapter:
    """Tests for the JSON adapter replacing GitHub's discontinued Atom feed.

    Fixture shape mirrors real https://api.github.com/advisories responses
    (verified live 2026-09-14), not a guessed/fabricated schema.
    """

    def _advisory(self, **overrides):
        base = {
            "ghsa_id": "GHSA-992q-9gwp-7r79",
            "cve_id": "CVE-2026-56666",
            "url": "https://api.github.com/advisories/GHSA-992q-9gwp-7r79",
            "html_url": "https://github.com/advisories/GHSA-992q-9gwp-7r79",
            "summary": "Example: IdP-side email verification is not checked",
            "description": "A flaw in the external identity provider handler...",
            "published_at": "2026-09-11T22:13:21Z",
        }
        base.update(overrides)
        return base

    def test_parse_advisories_json(self):
        content = json.dumps([self._advisory()]).encode()
        adapter = GitHubAdvisoriesJSONAdapter()

        feed = adapter.parse(content, "https://api.github.com/advisories")

        assert len(feed.entries) == 1
        entry = feed.entries[0]
        assert entry.url == "https://github.com/advisories/GHSA-992q-9gwp-7r79"
        assert entry.title == "Example: IdP-side email verification is not checked"
        assert entry.summary == "A flaw in the external identity provider handler..."
        assert entry.external_id == "GHSA-992q-9gwp-7r79"
        assert entry.published is not None
        assert entry.published.year == 2026

    def test_entry_without_html_url_skipped(self):
        content = json.dumps([self._advisory(html_url=None)]).encode()
        adapter = GitHubAdvisoriesJSONAdapter()

        feed = adapter.parse(content, "https://api.github.com/advisories")

        assert len(feed.entries) == 0

    def test_falls_back_to_ghsa_id_when_summary_blank(self):
        content = json.dumps([self._advisory(summary="")]).encode()
        adapter = GitHubAdvisoriesJSONAdapter()

        feed = adapter.parse(content, "https://api.github.com/advisories")

        assert feed.entries[0].title == "GHSA-992q-9gwp-7r79"

    def test_empty_content_rejected(self):
        adapter = GitHubAdvisoriesJSONAdapter()
        with pytest.raises(ValueError):
            adapter.parse(b"", "https://api.github.com/advisories")

    def test_invalid_json_rejected(self):
        adapter = GitHubAdvisoriesJSONAdapter()
        with pytest.raises(ValueError):
            adapter.parse(b"not json", "https://api.github.com/advisories")

    def test_non_list_json_rejected(self):
        adapter = GitHubAdvisoriesJSONAdapter()
        with pytest.raises(ValueError):
            adapter.parse(b'{"not": "a list"}', "https://api.github.com/advisories")

    def test_multiple_advisories_parsed(self):
        content = json.dumps([
            self._advisory(ghsa_id="GHSA-aaaa", html_url="https://github.com/advisories/GHSA-aaaa"),
            self._advisory(ghsa_id="GHSA-bbbb", html_url="https://github.com/advisories/GHSA-bbbb"),
        ]).encode()
        adapter = GitHubAdvisoriesJSONAdapter()

        feed = adapter.parse(content, "https://api.github.com/advisories")

        assert len(feed.entries) == 2
        assert {e.external_id for e in feed.entries} == {"GHSA-aaaa", "GHSA-bbbb"}


class TestApacheHTTPDJSONAdapter:
    """Tests for the JSON adapter replacing Apache httpd's discontinued
    rss.xml feed.

    Fixture shape mirrors real
    https://httpd.apache.org/security/vulnerabilities-httpd.json entries
    (MITRE CVE format, verified live 2026-09-14), not a guessed schema.
    """

    def _cve_record(self, cve_id="CVE-2016-2161", date="2016-12-20",
                     title="DoS vulnerability in mod_auth_digest",
                     branches=("2.4",)):
        return {
            "CVE_data_meta": {
                "ID": cve_id,
                "DATE_PUBLIC": date,
                "TITLE": title,
            },
            "description": {
                "description_data": [
                    {"lang": "eng", "value": f"{title} - full description."}
                ]
            },
            "affects": {
                "vendor": {
                    "vendor_data": [
                        {
                            "vendor_name": "Apache Software Foundation",
                            "product": {
                                "product_data": [
                                    {
                                        "product_name": "Apache HTTP Server",
                                        "version": {
                                            "version_data": [
                                                {"version_name": b} for b in branches
                                            ]
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
        }

    def test_parse_cve_json(self):
        content = json.dumps([self._cve_record()]).encode()
        adapter = ApacheHTTPDJSONAdapter()

        feed = adapter.parse(content, "https://httpd.apache.org/security/vulnerabilities-httpd.json")

        assert len(feed.entries) == 1
        entry = feed.entries[0]
        assert entry.external_id == "CVE-2016-2161"
        assert entry.title == "DoS vulnerability in mod_auth_digest"
        assert entry.url == "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2016-2161"
        assert entry.published.year == 2016

    def test_branch_specific_anchor_url(self):
        """A CVE affecting only the 2.2 branch must link to the 2.2 page,
        not the 2.4 page - the two pages don't share anchors (verified
        against the real live pages: a 2.2-only CVE's #anchor exists on
        vulnerabilities_22.html but not on vulnerabilities_24.html)."""
        content = json.dumps([
            self._cve_record(cve_id="CVE-2012-0021", branches=("2.2",))
        ]).encode()
        adapter = ApacheHTTPDJSONAdapter()

        feed = adapter.parse(content, "https://httpd.apache.org/security/vulnerabilities-httpd.json")

        assert feed.entries[0].url == (
            "https://httpd.apache.org/security/vulnerabilities_22.html#CVE-2012-0021"
        )

    def test_unrecognized_branch_falls_back_to_24_page(self):
        content = json.dumps([
            self._cve_record(cve_id="CVE-9999-0001", branches=("3.0",))
        ]).encode()
        adapter = ApacheHTTPDJSONAdapter()

        feed = adapter.parse(content, "https://httpd.apache.org/security/vulnerabilities-httpd.json")

        assert feed.entries[0].url.endswith("vulnerabilities_24.html#CVE-9999-0001")

    def test_results_windowed_to_most_recent(self):
        """The live JSON is a full historical archive (hundreds of entries),
        not a feed - only the most recent MAX_ENTRIES should be returned."""
        records = [
            self._cve_record(cve_id=f"CVE-2020-{i:04d}", date=f"2020-01-{(i % 28) + 1:02d}")
            for i in range(50)
        ]
        content = json.dumps(records).encode()
        adapter = ApacheHTTPDJSONAdapter()

        feed = adapter.parse(content, "https://httpd.apache.org/security/vulnerabilities-httpd.json")

        assert len(feed.entries) == adapter.MAX_ENTRIES

    def test_most_recent_entries_kept_when_windowed(self):
        older = self._cve_record(cve_id="CVE-2001-0001", date="2001-01-01")
        newer = self._cve_record(cve_id="CVE-2026-0001", date="2026-01-01")
        records = [older] + [
            self._cve_record(cve_id=f"CVE-2015-{i:04d}", date="2015-06-01")
            for i in range(40)
        ] + [newer]
        content = json.dumps(records).encode()
        adapter = ApacheHTTPDJSONAdapter()

        feed = adapter.parse(content, "https://httpd.apache.org/security/vulnerabilities-httpd.json")

        external_ids = {e.external_id for e in feed.entries}
        assert "CVE-2026-0001" in external_ids
        assert "CVE-2001-0001" not in external_ids

    def test_entry_missing_cve_id_skipped(self):
        record = self._cve_record()
        del record["CVE_data_meta"]["ID"]
        content = json.dumps([record]).encode()
        adapter = ApacheHTTPDJSONAdapter()

        feed = adapter.parse(content, "https://httpd.apache.org/security/vulnerabilities-httpd.json")

        assert len(feed.entries) == 0

    def test_entry_missing_date_skipped(self):
        record = self._cve_record()
        del record["CVE_data_meta"]["DATE_PUBLIC"]
        content = json.dumps([record]).encode()
        adapter = ApacheHTTPDJSONAdapter()

        feed = adapter.parse(content, "https://httpd.apache.org/security/vulnerabilities-httpd.json")

        assert len(feed.entries) == 0

    def test_empty_content_rejected(self):
        adapter = ApacheHTTPDJSONAdapter()
        with pytest.raises(ValueError):
            adapter.parse(b"", "https://httpd.apache.org/security/vulnerabilities-httpd.json")

    def test_invalid_json_rejected(self):
        adapter = ApacheHTTPDJSONAdapter()
        with pytest.raises(ValueError):
            adapter.parse(b"not json", "https://httpd.apache.org/security/vulnerabilities-httpd.json")
