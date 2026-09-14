"""
Test error handling and response formats.
"""

import pytest


def test_404_not_found(test_client):
    """Test 404 on non-existent endpoint."""
    response = test_client.get("/nonexistent")
    assert response.status_code == 404


def test_health_endpoint_exists(test_client):
    """Verify health endpoint is accessible."""
    response = test_client.get("/health/")
    assert response.status_code == 200
