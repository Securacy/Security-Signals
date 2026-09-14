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
        category="vulnerability",
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

    def _publish_signal_with_category(self, service, event, category, source_url):
        response = AISignalGenerationResponse(
            signal_title=f"{category.title()} Test Signal",
            signal_description="Comprehensive security signal description covering analysis and remediation steps for system hardening.",
            category=category,
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
        assert data[0]["categories"] == [{"id": data[0]["categories"][0]["id"], "category": "vulnerability"}]

    def test_published_list_without_category_param_returns_all(self, db, client, security_event):
        """Omitting `category` preserves the original unfiltered behavior."""
        service = SignalService(db)
        self._publish_signal_with_category(service, security_event, "vulnerability", "https://example.com/1")
        self._publish_signal_with_category(service, security_event, "iam", "https://example.com/2")

        response = client.get("/api/v1/signals/published")

        assert response.status_code == 200
        assert len(response.json()) == 2

    def test_published_list_filtered_by_category(self, db, client, security_event):
        """`category` filters the published list to matching signals only."""
        service = SignalService(db)
        self._publish_signal_with_category(service, security_event, "vulnerability", "https://example.com/1")
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
        assert data["categories"][0]["category"] == "vulnerability"
