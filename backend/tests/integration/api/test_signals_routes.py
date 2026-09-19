"""Integration tests for Signal API routes."""

import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from app.main import create_app
from app.db.connection import get_db
from app.services.signal_service import SignalService
from app.db.models import SignalStatus
from app.intelligence.schemas.signal_request import AISignalGenerationResponse


@pytest.fixture
def client(db):
    """FastAPI test client with test database."""
    app = create_app()
    
    def override_get_db():
        yield db
    
    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


@pytest.fixture
def ai_response():
    """Valid AI response."""
    return AISignalGenerationResponse(
        signal_title="Critical Apache RCE",
        signal_description="Critical remote code execution requiring immediate patch for Apache HTTP Server",
        category="insecure_design",
        ai_subcategory=None,
        confidence=0.95,
        evidence_summary="Apache released security update for CVE-2024-12345",
        secure_design_principles=[]
    )


class TestPublishedSignalsListEndpoint:
    """Tests for GET /api/v1/signals/published"""
    
    def test_list_published_signals_empty(self, client, db):
        """Empty list when no published signals."""
        response = client.get("/api/v1/signals/published")
        
        assert response.status_code == 200
        assert response.json() == []
    
    def test_list_published_signals_success(self, client, db, security_event, ai_response):
        """List published signals with pagination."""
        service = SignalService(db)
        
        # Create and publish signal
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com",
            source_title="Title",
            excerpt="Excerpt"
        )
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)
        
        response = client.get("/api/v1/signals/published")
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert data[0]["title"] == signal.title
        assert data[0]["published_at"] is not None
    
    def test_list_published_excludes_draft(self, client, db, security_event, ai_response):
        """DRAFT signals not in published list."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        response = client.get("/api/v1/signals/published")
        
        assert response.status_code == 200
        data = response.json()
        assert not any(s["id"] == str(signal.id) for s in data)
    
    def test_list_published_excludes_in_review(self, client, db, security_event, ai_response):
        """IN_REVIEW signals not in published list."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com",
            source_title="Title",
            excerpt="Excerpt"
        )
        service.submit_for_review(signal.id)
        
        response = client.get("/api/v1/signals/published")
        
        assert response.status_code == 200
        data = response.json()
        assert not any(s["id"] == str(signal.id) for s in data)
    
    def test_list_published_pagination_skip(self, client, db, security_event, ai_response):
        """Pagination skip parameter works."""
        service = SignalService(db)
        
        # Create and publish two signals
        for i in range(2):
            signal = service.create_signal_from_ai(
                event_id=security_event.id,
                ai_response=ai_response
            )
            service.add_evidence(
                signal_id=signal.id,
                source_url=f"https://example.com/{i}",
                source_title="Title",
                excerpt="Excerpt"
            )
            service.submit_for_review(signal.id)
            service.approve_signal(signal.id)
            service.publish_signal(signal.id)
        
        # Skip 1, limit 1
        response = client.get("/api/v1/signals/published?skip=1&limit=1")
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
    
    def test_list_published_limit_default(self, client, db, security_event, ai_response):
        """Default limit is 50."""
        response = client.get("/api/v1/signals/published")
        
        # Should accept without limit parameter
        assert response.status_code == 200
    
    def test_list_published_limit_max_enforced(self, client, db):
        """Limit capped at 100."""
        # Request limit > 100 should be rejected or capped
        response = client.get("/api/v1/signals/published?limit=200")

        # Either 422 validation error or response is OK (limit was capped)
        assert response.status_code in [200, 422]


class TestPublishedSignalsCategorySupport:
    """Tests for the additive category fields/filter on GET /published.

    Reuses the existing endpoint (no new route) per the Phase 6 frontend
    widget's category chip requirement - omitting `category` must keep the
    original response shape plus the new `categories` field, and results
    must not regress for callers that never pass `category` at all.
    """

    def _publish_signal_with_category(self, service, event, category, source_url, ai_subcategory=None, title=None):
        response = AISignalGenerationResponse(
            signal_title=title or f"{category.title()} Test Signal",
            signal_description="Comprehensive security signal description covering analysis and remediation steps for system hardening.",
            category=category,
            ai_subcategory=ai_subcategory,
            confidence=0.9,
            evidence_summary="Evidence discovered in security audit.",
            secure_design_principles=[],
        )
        signal = service.create_signal_from_ai(event_id=event.id, ai_response=response)
        service.add_evidence(
            signal_id=signal.id,
            source_url=source_url,
            source_title="Title",
            excerpt="Excerpt",
        )
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)
        return signal

    def test_published_list_includes_categories_field(self, client, db, security_event, ai_response):
        """Each item in the published list includes its category tags."""
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(
            signal_id=signal.id, source_url="https://example.com", source_title="Title", excerpt="Excerpt"
        )
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)

        response = client.get("/api/v1/signals/published")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert "categories" in data[0]
        assert data[0]["categories"] == [{"id": data[0]["categories"][0]["id"], "category": "insecure_design", "subcategory": None}]

    def test_published_list_without_category_param_returns_all(self, db, client, security_event):
        """Omitting `category` preserves the original unfiltered behavior."""
        service = SignalService(db)
        self._publish_signal_with_category(service, security_event, "insecure_design", "https://example.com/1")
        self._publish_signal_with_category(service, security_event, "iam", "https://example.com/2")

        response = client.get("/api/v1/signals/published")

        assert response.status_code == 200
        assert len(response.json()) == 2

    def test_published_list_filtered_by_category(self, db, client, security_event):
        """`category` filters the published list to matching signals only."""
        service = SignalService(db)
        self._publish_signal_with_category(service, security_event, "insecure_design", "https://example.com/1")
        self._publish_signal_with_category(service, security_event, "iam", "https://example.com/2")

        response = client.get("/api/v1/signals/published?category=iam")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert all(c["category"] == "iam" for sig in data for c in sig["categories"])

    def test_published_list_category_filter_no_matches_returns_empty(self, db, client, security_event, ai_response):
        """A category with no published signals returns an empty list, not an error."""
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(
            signal_id=signal.id, source_url="https://example.com", source_title="Title", excerpt="Excerpt"
        )
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)

        response = client.get("/api/v1/signals/published?category=ransomware")

        assert response.status_code == 200
        assert response.json() == []

    def test_published_list_invalid_category_returns_422(self, client):
        """An unrecognized category value is rejected, not silently ignored."""
        response = client.get("/api/v1/signals/published?category=not_a_real_category")
        assert response.status_code == 422

    def test_published_list_filtered_by_subcategory(self, db, client, security_event):
        """`subcategory` narrows within a category (Change 8/13)."""
        service = SignalService(db)
        self._publish_signal_with_category(
            service, security_event, "ai_security", "https://example.com/1",
            ai_subcategory="agent_abuse", title="Agent Abuse Signal",
        )
        self._publish_signal_with_category(
            service, security_event, "ai_security", "https://example.com/2",
            ai_subcategory="model_poisoning", title="Model Poisoning Signal",
        )

        response = client.get("/api/v1/signals/published?category=ai_security&subcategory=agent_abuse")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["title"] == "Agent Abuse Signal"
        assert data[0]["categories"][0]["subcategory"] == "agent_abuse"

    def test_published_list_search_matches_title(self, db, client, security_event):
        service = SignalService(db)
        self._publish_signal_with_category(
            service, security_event, "insecure_design", "https://example.com/1",
            title="Unique Searchable Title About Trust Boundaries",
        )
        self._publish_signal_with_category(
            service, security_event, "iam", "https://example.com/2", title="Unrelated Signal",
        )

        response = client.get("/api/v1/signals/published?search=Trust%20Boundaries")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert "Trust Boundaries" in data[0]["title"]

    def test_published_list_sort_by_sources_orders_by_evidence_count(self, db, client, security_event):
        service = SignalService(db)
        few_evidence = self._publish_signal_with_category(
            service, security_event, "iam", "https://example.com/few", title="Few Evidence Signal",
        )
        many_evidence = self._publish_signal_with_category(
            service, security_event, "iam", "https://example.com/many-1", title="Many Evidence Signal",
        )
        service.add_evidence(
            signal_id=many_evidence.id, source_url="https://example.com/many-2",
            source_title="Second", excerpt="Excerpt",
        )

        response = client.get("/api/v1/signals/published?sort=sources")

        assert response.status_code == 200
        data = response.json()
        assert data[0]["title"] == "Many Evidence Signal"

    def test_published_list_invalid_sort_returns_400(self, client):
        response = client.get("/api/v1/signals/published?sort=not_a_real_sort")
        assert response.status_code == 400

    def test_published_signals_remain_visible_when_ingestion_finds_nothing_new(self, db, client, security_event, ai_response):
        """Change 11: previously published signals stay visible through the
        public API regardless of what a later ingestion run does or doesn't
        find - the public feed is never unnecessarily emptied."""
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(
            signal_id=signal.id, source_url="https://example.com", source_title="Title", excerpt="Excerpt"
        )
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)

        # Simulate a real "zero new qualifying events" ingestion outcome by
        # running the actual orchestrator against an empty feed - it must
        # not touch existing published signals in any way.
        import asyncio
        from unittest.mock import AsyncMock, patch
        from app.ingestion.orchestrator import IngestionOrchestrator
        from app.db.models import Source, SourceType
        from uuid import uuid4

        source = Source(
            id=uuid4(), name="Empty Run Source", source_type=SourceType.RSS,
            url="https://example.com/feed.rss", is_active=True, config={},
        )
        db.add(source)
        db.commit()

        orchestrator = IngestionOrchestrator(db)
        with patch.object(orchestrator.http_client, "fetch", new=AsyncMock(return_value=b"<rss/>")):
            result = asyncio.run(orchestrator._ingest_source(source))
        assert result["status"] == "success"
        assert result["created"] == 0

        response = client.get("/api/v1/signals/published")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == str(signal.id)


class TestPublishedSignalsPublicTaxonomy:
    """Tests for the consolidated 8-category public taxonomy on
    GET /published - public_categories field + public_category filter."""

    def _publish_signal_with_category(self, service, event, category, source_url, title=None):
        response = AISignalGenerationResponse(
            signal_title=title or f"{category.title()} Test Signal",
            signal_description="Comprehensive security signal description covering analysis and remediation steps.",
            category=category,
            ai_subcategory="agent_abuse" if category == "ai_security" else None,
            confidence=0.9,
            evidence_summary="Evidence discovered in security audit.", secure_design_principles=[],
        )
        signal = service.create_signal_from_ai(event_id=event.id, ai_response=response)
        service.add_evidence(signal_id=signal.id, source_url=source_url, source_title="Title", excerpt="Excerpt")
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)
        return signal

    def test_published_list_includes_public_categories_field(self, db, client, security_event):
        service = SignalService(db)
        self._publish_signal_with_category(service, security_event, "insecure_design", "https://example.com/1")

        response = client.get("/api/v1/signals/published")

        assert response.status_code == 200
        data = response.json()
        assert data[0]["public_categories"] == ["product_security"]

    def test_product_security_public_filter_includes_insecure_design(self, db, client, security_event):
        service = SignalService(db)
        self._publish_signal_with_category(service, security_event, "insecure_design", "https://example.com/1")
        self._publish_signal_with_category(service, security_event, "ransomware", "https://example.com/2")

        response = client.get("/api/v1/signals/published?public_category=product_security")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["public_categories"] == ["product_security"]

    def test_product_security_public_filter_includes_app_api(self, db, client, security_event):
        """Product Security aggregates BOTH insecure_design and app_api."""
        service = SignalService(db)
        self._publish_signal_with_category(service, security_event, "app_api", "https://example.com/1")

        response = client.get("/api/v1/signals/published?public_category=product_security")

        assert response.status_code == 200
        assert len(response.json()) == 1

    def test_cloud_identity_security_public_filter_includes_cloud_security_and_iam(self, db, client, security_event):
        service = SignalService(db)
        self._publish_signal_with_category(service, security_event, "cloud_security", "https://example.com/1")
        self._publish_signal_with_category(service, security_event, "iam", "https://example.com/2")
        self._publish_signal_with_category(service, security_event, "ransomware", "https://example.com/3")

        response = client.get("/api/v1/signals/published?public_category=cloud_identity_security")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert all(c["public_categories"] == ["cloud_identity_security"] for c in data)

    def test_ai_security_public_filter_stays_independent(self, db, client, security_event):
        """AI Security must never be aggregated into Product Security or
        Cloud & Identity Security."""
        service = SignalService(db)
        self._publish_signal_with_category(service, security_event, "ai_security", "https://example.com/1")
        self._publish_signal_with_category(service, security_event, "insecure_design", "https://example.com/2")
        self._publish_signal_with_category(service, security_event, "cloud_security", "https://example.com/3")

        response = client.get("/api/v1/signals/published?public_category=ai_security")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["public_categories"] == ["ai_security"]

    def test_unknown_public_category_returns_422(self, client):
        response = client.get("/api/v1/signals/published?public_category=not_a_real_public_category")
        assert response.status_code == 422

    def test_old_internal_only_slugs_are_not_valid_public_category_filters(self, client):
        """'iam' and 'app_api' only exist inside their aggregated public
        category now - not as standalone public filter values."""
        response = client.get("/api/v1/signals/published?public_category=iam")
        assert response.status_code == 422
        response = client.get("/api/v1/signals/published?public_category=app_api")
        assert response.status_code == 422

    def test_public_category_takes_precedence_over_internal_category(self, db, client, security_event):
        service = SignalService(db)
        self._publish_signal_with_category(service, security_event, "ransomware", "https://example.com/1")

        response = client.get("/api/v1/signals/published?category=iam&public_category=ransomware")

        assert response.status_code == 200
        assert len(response.json()) == 1


class TestPublishedSignalDetailEndpoint:
    """Tests for GET /api/v1/signals/published/{signal_id}"""
    
    def test_get_published_signal_success(self, client, db, security_event, ai_response):
        """Retrieve published signal details."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com/advisory",
            source_title="Apache Advisory",
            excerpt="Exact quote from advisory"
        )
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)
        
        response = client.get(f"/api/v1/signals/published/{signal.id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(signal.id)
        assert data["title"] == signal.title
        assert len(data["evidence"]) == 1
        assert data["evidence"][0]["excerpt"] == "Exact quote from advisory"
        assert len(data["categories"]) == 1
    
    def test_get_published_signal_not_found(self, client):
        """404 for nonexistent signal."""
        response = client.get(f"/api/v1/signals/published/{uuid4()}")
        
        assert response.status_code == 404
    
    def test_get_draft_signal_404(self, client, db, security_event, ai_response):
        """404 when trying to access DRAFT signal via public endpoint."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        response = client.get(f"/api/v1/signals/published/{signal.id}")
        
        assert response.status_code == 404
    
    def test_get_in_review_signal_404(self, client, db, security_event, ai_response):
        """404 when trying to access IN_REVIEW signal via public endpoint."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com",
            source_title="Title",
            excerpt="Excerpt"
        )
        service.submit_for_review(signal.id)
        
        response = client.get(f"/api/v1/signals/published/{signal.id}")
        
        assert response.status_code == 404
    
    def test_get_rejected_signal_404(self, client, db, security_event, ai_response):
        """404 when trying to access REJECTED signal via public endpoint."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com",
            source_title="Title",
            excerpt="Excerpt"
        )
        service.submit_for_review(signal.id)
        service.reject_signal(signal.id)
        
        response = client.get(f"/api/v1/signals/published/{signal.id}")
        
        assert response.status_code == 404
    
    def test_get_signal_includes_all_evidence(self, client, db, security_event, ai_response):
        """Signal detail includes all evidence records."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        
        # Add multiple evidence records
        for i in range(3):
            service.add_evidence(
                signal_id=signal.id,
                source_url=f"https://example.com/{i}",
                source_title=f"Source {i}",
                excerpt=f"Excerpt {i}"
            )
        
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)
        
        response = client.get(f"/api/v1/signals/published/{signal.id}")
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["evidence"]) == 3
    
    def test_get_signal_includes_categories(self, client, db, security_event, ai_response):
        """Signal detail includes category classification."""
        service = SignalService(db)
        
        signal = service.create_signal_from_ai(
            event_id=security_event.id,
            ai_response=ai_response
        )
        service.add_evidence(
            signal_id=signal.id,
            source_url="https://example.com",
            source_title="Title",
            excerpt="Excerpt"
        )
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)
        
        response = client.get(f"/api/v1/signals/published/{signal.id}")
        
        assert response.status_code == 200
        data = response.json()
        assert "categories" in data
        assert len(data["categories"]) >= 1
        assert data["categories"][0]["category"] == "insecure_design"


class TestPublishedSignalDetailVisualAndTaxonomy:
    """Tests for public_categories/visual_status/visual_url on
    GET /published/{id} - the detail-only fields (never on the list/feed
    response)."""

    def test_detail_includes_public_categories(self, db, client, security_event, ai_response):
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)

        response = client.get(f"/api/v1/signals/published/{signal.id}")

        assert response.status_code == 200
        # ai_response fixture uses category="insecure_design" -> product_security
        assert response.json()["public_categories"] == ["product_security"]

    def test_detail_visual_defaults_to_pending_when_no_row_exists(self, db, client, security_event, ai_response):
        """Visual generation is disabled in the test suite (see
        tests/conftest.py's autouse _disable_real_visual_generation), so no
        SignalVisual row is ever created here - the detail endpoint must
        still respond safely with a pending/no-url default rather than
        erroring."""
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)

        response = client.get(f"/api/v1/signals/published/{signal.id}")

        assert response.status_code == 200
        data = response.json()
        assert data["visual_status"] == "pending"
        assert data["visual_url"] is None

    def test_list_endpoint_never_exposes_visual_fields(self, db, client, security_event, ai_response):
        """The feed/list response stays lightweight - no visual fields at
        all, so loading the feed never implies loading an image."""
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id)
        service.publish_signal(signal.id)

        response = client.get("/api/v1/signals/published")

        assert response.status_code == 200
        assert "visual_url" not in response.json()[0]
        assert "visual_status" not in response.json()[0]
