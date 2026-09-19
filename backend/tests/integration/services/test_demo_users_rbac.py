"""End-to-end RBAC verification using the actual seeded demo accounts
(admin-demo / reviewer-demo), over real HTTP requests - this is the exact
scenario the demo accounts exist to support: authenticate via JWT, then
demonstrate the human-in-the-loop review workflow through the API.
"""

from uuid import uuid4

import pytest
from pydantic import SecretStr
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import Settings
from app.services.demo_seed_service import (
    seed_demo_users, DEMO_ADMIN_USERNAME, DEMO_REVIEWER_USERNAME,
)
from app.services.signal_service import SignalService
from app.intelligence.schemas.signal_request import AISignalGenerationResponse

_ADMIN_PW = "Str0ng!DemoAdminPw"
_REVIEWER_PW = "Str0ng!DemoReviewerPw"


@pytest.fixture
def demo_users(db: Session):
    settings = Settings(
        environment="development",
        DEMO_ADMIN_PASSWORD=SecretStr(_ADMIN_PW),
        DEMO_REVIEWER_PASSWORD=SecretStr(_REVIEWER_PW),
    )
    seed_demo_users(db, settings)


def _login(client: TestClient, username: str, password: str) -> str:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture
def draft_signal(db: Session, security_event):
    ai_response = AISignalGenerationResponse(
        signal_title="Demo RBAC Test Signal",
        signal_description="A sufficiently long description of a design-level security concern for RBAC testing.",
        category="insecure_design",
        confidence=0.8,
        evidence_summary="Evidence discovered in security audit.",
        secure_design_principles=[],
    )
    service = SignalService(db)
    signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
    service.add_evidence(
        signal_id=signal.id, source_url="https://example.com/advisory",
        source_title="Advisory", excerpt="Evidence",
    )
    db.commit()
    db.refresh(signal)
    return signal


class TestDemoAdminAuthenticationAndPermissions:
    def test_demo_admin_can_authenticate_and_receive_jwt(self, client: TestClient, demo_users):
        token = _login(client, DEMO_ADMIN_USERNAME, _ADMIN_PW)
        assert token
        assert len(token.split(".")) == 3  # JWT has 3 dot-separated segments

    def test_demo_admin_can_create_users(self, client: TestClient, demo_users):
        token = _login(client, DEMO_ADMIN_USERNAME, _ADMIN_PW)

        r = client.post(
            "/api/v1/users",
            json={
                "username": "created-by-demo-admin",
                "email": "created-by-demo-admin@test.local",
                "role": "viewer",
                "password": "Str0ng!AnotherPassword1",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 201

    def test_demo_admin_can_list_users(self, client: TestClient, demo_users):
        token = _login(client, DEMO_ADMIN_USERNAME, _ADMIN_PW)

        r = client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_demo_admin_can_publish_a_signal(self, client: TestClient, demo_users, draft_signal):
        token = _login(client, DEMO_ADMIN_USERNAME, _ADMIN_PW)
        headers = {"Authorization": f"Bearer {token}"}
        client.post(f"/api/v1/signals/{draft_signal.id}/submit-for-review", headers=headers)
        client.post(f"/api/v1/signals/{draft_signal.id}/approve", headers=headers)

        r = client.post(f"/api/v1/signals/{draft_signal.id}/publish", headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "published"


class TestDemoReviewerAuthenticationAndPermissions:
    def test_demo_reviewer_can_authenticate_and_receive_jwt(self, client: TestClient, demo_users):
        token = _login(client, DEMO_REVIEWER_USERNAME, _REVIEWER_PW)
        assert token
        assert len(token.split(".")) == 3

    def test_demo_reviewer_can_submit_and_approve_signals(self, client: TestClient, demo_users, draft_signal):
        token = _login(client, DEMO_REVIEWER_USERNAME, _REVIEWER_PW)
        headers = {"Authorization": f"Bearer {token}"}

        r = client.post(f"/api/v1/signals/{draft_signal.id}/submit-for-review", headers=headers)
        assert r.status_code == 200

        r = client.post(f"/api/v1/signals/{draft_signal.id}/approve", headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "approved"

    def test_demo_reviewer_cannot_publish(self, client: TestClient, demo_users, draft_signal):
        """Publishing is the ADMIN-only final gate - a REVIEWER who
        legitimately approved the same signal still cannot publish it."""
        token = _login(client, DEMO_REVIEWER_USERNAME, _REVIEWER_PW)
        headers = {"Authorization": f"Bearer {token}"}
        client.post(f"/api/v1/signals/{draft_signal.id}/submit-for-review", headers=headers)
        client.post(f"/api/v1/signals/{draft_signal.id}/approve", headers=headers)

        r = client.post(f"/api/v1/signals/{draft_signal.id}/publish", headers=headers)
        assert r.status_code == 403

    def test_demo_reviewer_cannot_create_users(self, client: TestClient, demo_users):
        token = _login(client, DEMO_REVIEWER_USERNAME, _REVIEWER_PW)

        r = client.post(
            "/api/v1/users",
            json={
                "username": "reviewer-attempted-create",
                "email": "reviewer-attempted-create@test.local",
                "role": "viewer",
                "password": "Str0ng!AnotherPassword1",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_demo_reviewer_cannot_promote_self_to_admin(self, client: TestClient, demo_users, db: Session):
        from app.db.models import User

        token = _login(client, DEMO_REVIEWER_USERNAME, _REVIEWER_PW)
        reviewer = db.query(User).filter_by(username=DEMO_REVIEWER_USERNAME).one()

        r = client.patch(
            f"/api/v1/users/{reviewer.id}",
            json={"role": "admin"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

        db.refresh(reviewer)
        assert reviewer.role.value == "reviewer"

    def test_demo_reviewer_cannot_promote_another_user(self, client: TestClient, demo_users, db: Session):
        from app.db.models import User

        token = _login(client, DEMO_REVIEWER_USERNAME, _REVIEWER_PW)
        admin = db.query(User).filter_by(username="admin-demo").one()

        r = client.patch(
            f"/api/v1/users/{admin.id}",
            json={"role": "viewer"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_demo_reviewer_cannot_deactivate_users(self, client: TestClient, demo_users, db: Session):
        from app.db.models import User

        token = _login(client, DEMO_REVIEWER_USERNAME, _REVIEWER_PW)
        admin = db.query(User).filter_by(username="admin-demo").one()

        r = client.post(
            f"/api/v1/users/{admin.id}/deactivate",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403


class TestUnauthenticatedAccessRejected:
    def test_protected_endpoint_rejects_missing_token(self, client: TestClient, demo_users):
        r = client.get("/api/v1/users")
        assert r.status_code == 401

    def test_protected_endpoint_rejects_invalid_token(self, client: TestClient, demo_users):
        r = client.get("/api/v1/users", headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401
