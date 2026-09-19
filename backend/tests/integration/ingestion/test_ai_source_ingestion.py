"""Integration test: the dedicated AI security source (OWASP GenAI Security
Project RSS feed) ingests through the real pipeline end-to-end.

The HTTP fetch is mocked with a real, verbatim excerpt captured from the
live feed (https://genai.owasp.org/feed/, confirmed 200/valid RSS 2.0
during implementation) - not fabricated content - so this test exercises
the real RSSAtomAdapter, ArticleNormalizer, RelevanceClassifier, and
EventGrouper without depending on network access in CI.
"""

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.db.models import Article, SecurityEvent, Source, SourceType
from app.ingestion.orchestrator import IngestionOrchestrator
from app.ingestion.sources import VERIFIED_FEEDS

# Verbatim excerpt captured live from https://genai.owasp.org/feed/ during
# implementation (2026-09). Real title/link/description/pubDate - nothing
# invented.
_REAL_OWASP_GENAI_FEED_EXCERPT = b"""<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"
	xmlns:content="http://purl.org/rss/1.0/modules/content/"
	xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
	<title>OWASP Gen AI Security Project</title>
	<link>https://genai.owasp.org/</link>
	<description>Identifying the Top Security Risks Associated with Generative AI</description>
	<item>
		<title>OWASP GenAI Security Project Unveils 2026 Top 10 for LLM Applications, New Agent Control Standard and Sponsors as Community Tops 30,000 Members</title>
		<link>https://genai.owasp.org/2026/09/01/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/</link>
		<pubDate>Wed, 02 Sep 2026 04:59:10 +0000</pubDate>
		<category><![CDATA[Announcement]]></category>
		<guid isPermaLink="false">https://genai.owasp.org/?p=57341</guid>
		<description><![CDATA[<p>OWASP GenAI Security Project Releases 2026 Top 10 for LLM Applications, Debuts Agent Control Standard and New Resources for Securing Generative and Agentic AI security.</p>]]></description>
	</item>
	<item>
		<title>Memory Is a Feature. It Is Also an Attack Surface</title>
		<link>https://genai.owasp.org/2026/05/13/memory-is-a-feature-it-is-also-an-attack-surface/</link>
		<pubDate>Wed, 13 May 2026 12:00:00 +0000</pubDate>
		<guid isPermaLink="false">https://genai.owasp.org/?p=50001</guid>
		<description><![CDATA[<p>How agent memory and context poisoning create a new attack surface for AI systems, and what secure design looks like.</p>]]></description>
	</item>
</channel>
</rss>"""


@pytest.fixture
def ai_source(db: Session) -> Source:
    feed = next(f for f in VERIFIED_FEEDS if f['name'] == 'OWASP GenAI Security Project')
    source = Source(
        id=uuid4(), name=feed['name'], source_type=feed['type'], url=feed['url'],
        is_active=True, config={},
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


class TestAISourceRealPipelineIngestion:
    @pytest.mark.asyncio
    async def test_real_feed_content_ingests_through_the_real_pipeline(self, db: Session, ai_source):
        orchestrator = IngestionOrchestrator(db)

        with patch.object(orchestrator.http_client, "fetch", new=AsyncMock(return_value=_REAL_OWASP_GENAI_FEED_EXCERPT)):
            result = await orchestrator._ingest_source(ai_source)

        assert result["status"] == "success"
        assert result["fetched"] == 2
        assert result["created"] == 2
        assert result["relevant"] == 2  # both mention "security"/"attack surface"

    @pytest.mark.asyncio
    async def test_creates_real_articles_and_events_not_placeholders(self, db: Session, ai_source):
        orchestrator = IngestionOrchestrator(db)

        with patch.object(orchestrator.http_client, "fetch", new=AsyncMock(return_value=_REAL_OWASP_GENAI_FEED_EXCERPT)):
            await orchestrator._ingest_source(ai_source)

        article = db.query(Article).filter(Article.source_id == ai_source.id).filter(
            Article.title.like("%Memory Is a Feature%")
        ).one()
        assert article.url == "https://genai.owasp.org/2026/05/13/memory-is-a-feature-it-is-also-an-attack-surface/"
        assert article.is_relevant is True

        event = db.query(SecurityEvent).filter(SecurityEvent.name == article.title).one_or_none()
        assert event is not None
        assert article in event.articles
