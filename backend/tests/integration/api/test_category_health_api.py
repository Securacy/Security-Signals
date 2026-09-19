"""HTTP tests for GET /api/v1/admin/category-health (Feature 2) - admin-only,
never publicly exposed since it reveals internal source health details."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import User, UserRole
from app.auth.password import hash_password
from app.auth.tokens import create_access_token


def _auth(user: User) -> dict:
    token = create_access_token(user_id=user.id, username=user.username, role=user.role.value)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_user(db: Session) -> User:
    user = User(username="cat_health_admin", email="cat_health_admin@test.local",
                role=UserRole.ADMIN, password_hash=hash_password("AdminPassword123!"), is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def reviewer_user(db: Session) -> User:
    user = User(username="cat_health_reviewer", email="cat_health_reviewer@test.local",
                role=UserRole.REVIEWER, password_hash=hash_password("ReviewerPassword123!"), is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


class TestCategoryHealthAccessControl:
    def test_unauthenticated_request_rejected(self, client: TestClient):
        response = client.get("/api/v1/admin/category-health")
        assert response.status_code in (401, 403)

    def test_reviewer_role_rejected(self, client: TestClient, reviewer_user):
        response = client.get("/api/v1/admin/category-health", headers=_auth(reviewer_user))
        assert response.status_code == 403

    def test_admin_role_allowed(self, client: TestClient, admin_user):
        response = client.get("/api/v1/admin/category-health", headers=_auth(admin_user))
        assert response.status_code == 200


class TestCategoryHealthContent:
    def test_response_covers_all_ten_canonical_categories(self, client: TestClient, admin_user):
        response = client.get("/api/v1/admin/category-health", headers=_auth(admin_user))
        body = response.json()
        categories = {row["category"] for row in body}
        expected = {
            "insecure_design", "cloud_security", "iam", "app_api", "supply_chain",
            "data_privacy", "ransomware", "threat_intel", "ai_security", "infrastructure",
        }
        assert expected <= categories

    def test_each_row_has_source_and_coverage_fields(self, client: TestClient, admin_user):
        response = client.get("/api/v1/admin/category-health", headers=_auth(admin_user))
        for row in response.json():
            assert "primary_sources" in row
            assert "secondary_sources" in row
            assert "source_health" in row
            assert "has_current_coverage" in row
            assert "is_stale" in row
            assert "coverage_status" in row

    def test_no_categories_falsely_claim_coverage_without_evidence(self, client: TestClient, admin_user):
        """With no published signals in the DB at all, no category should
        claim has_current_coverage=True - never fabricated."""
        response = client.get("/api/v1/admin/category-health", headers=_auth(admin_user))
        for row in response.json():
            assert row["has_current_coverage"] is False
            assert row["current_signal_count"] == 0

    def test_coverage_status_is_source_failure_when_no_sources_synced_yet(self, client: TestClient, admin_user):
        """A fresh DB with no Source rows synced yet is an honest
        SOURCE_FAILURE, not a silent HEALTHY/NO_QUALIFYING_EVENT - nothing
        is actually being fetched for any category yet."""
        response = client.get("/api/v1/admin/category-health", headers=_auth(admin_user))
        for row in response.json():
            assert row["coverage_status"] == "source_failure"
