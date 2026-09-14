"""Regression tests for baseline security response headers (Phase 6)."""


class TestSecurityHeaders:
    def test_content_type_options_nosniff(self, client):
        response = client.get("/health/")
        assert response.headers.get("x-content-type-options") == "nosniff"

    def test_referrer_policy_no_referrer(self, client):
        response = client.get("/health/")
        assert response.headers.get("referrer-policy") == "no-referrer"

    def test_frame_options_deny(self, client):
        response = client.get("/health/")
        assert response.headers.get("x-frame-options") == "DENY"

    def test_hsts_present(self, client):
        response = client.get("/health/")
        assert "max-age=31536000" in response.headers.get("strict-transport-security", "")

    def test_headers_present_on_error_responses_too(self, client):
        """Security headers must apply uniformly, including on 404s -
        middleware order matters here (headers added after call_next, so
        they apply regardless of which handler produced the response)."""
        response = client.get("/api/v1/signals/nonexistent-path-xyz")
        assert response.headers.get("x-content-type-options") == "nosniff"

    def test_headers_present_on_public_analytics(self, client):
        response = client.get("/api/v1/analytics/public")
        assert response.headers.get("x-frame-options") == "DENY"
