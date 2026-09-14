"""
Integration tests for health check endpoints.
"""
import pytest


def test_health_check(test_client):
    """Test basic health endpoint."""
    response = test_client.get("/health/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_readiness_check(test_client):
    """Test readiness endpoint when database is available."""
    response = test_client.get("/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
