"""Integration tests for the Phase 6 admin-only audit log API.

Covers auth/RBAC gating, filtering/pagination, sensitive-data leakage, and
that no update/delete surface exists for audit records.
"""
import pytest
from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import User, UserRole
from app.auth.password import hash_password
from app.auth.tokens import create_access_token
from app.repositories import UserRepository
from app.services.signal_service import SignalService
from app.intelligence.schemas.signal_request import AISignalGenerationResponse


def _token(user: User) -> str:
    return create_access_token(user_id=user.id, username=user.username, role=user.role.value)


def _auth(user: User) -> dict:
    return {"Authorization": f"Bearer {_token(user)}"}


@pytest.fixture
def admin_user(db: Session) -> User:
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="audit_api_admin",
        email="audit_api_admin@test.local",
        role=UserRole.ADMIN,
        password_hash=hash_password("AdminPassword123!"),
        is_active=True,
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def reviewer_user(db: Session) -> User:
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="audit_api_reviewer",
        email="audit_api_reviewer@test.local",
        role=UserRole.REVIEWER,
        password_hash=hash_password("ReviewerPassword123!"),
        is_active=True,
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def viewer_user(db: Session) -> User:
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="audit_api_viewer",
        email="audit_api_viewer@test.local",
        role=UserRole.VIEWER,
        password_hash=hash_password("ViewerPassword123!"),
        is_active=True,
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def ai_response() -> AISignalGenerationResponse:
    return AISignalGenerationResponse(
        signal_title="Audit API Test Signal",
        signal_description="Comprehensive security signal description covering vulnerability analysis and remediation steps for system hardening.",
        category="vulnerability",
        confidence=0.8,
        evidence_summary="Evidence discovered in security audit.",
        secure_design_principles=[],
    )


@pytest.fixture
def audited_signal(db: Session, security_event, ai_response, admin_user):
    """A signal put through submit-for-review so at least one SIGNAL audit
    entry exists to query against."""
    service = SignalService(db)
    signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
    service.add_evidence(
        signal_id=signal.id,
        source_url="https://example.com/advisory",
        source_title="Security Advisory",
        excerpt="Evidence of vulnerability",
    )
    db.commit()
    service.submit_for_review(signal.id)
    db.commit()
    db.refresh(signal)
    return signal


class TestAuditApiAuth:
    def test_list_audit_without_token_401(self, client: TestClient):
        r = client.get("/api/v1/audit")
        assert r.status_code == 401

    def test_reviewer_cannot_list_audit_403(self, client: TestClient, reviewer_user):
        r = client.get("/api/v1/audit", headers=_auth(reviewer_user))
        assert r.status_code == 403

    def test_viewer_cannot_list_audit_403(self, client: TestClient, viewer_user):
        r = client.get("/api/v1/audit", headers=_auth(viewer_user))
        assert r.status_code == 403

    def test_reviewer_cannot_get_audit_entry_403(self, client: TestClient, reviewer_user):
        r = client.get(f"/api/v1/audit/{uuid4()}", headers=_auth(reviewer_user))
        assert r.status_code == 403


class TestAuditApiListing:
    def test_admin_can_list_audit_entries(self, client: TestClient, admin_user, audited_signal):
        r = client.get("/api/v1/audit", headers=_auth(admin_user))
        assert r.status_code == 200
        assert isinstance(r.json(), list)
        assert len(r.json()) > 0

    def test_filter_by_resource_type_and_id(self, client: TestClient, admin_user, audited_signal):
        r = client.get(
            f"/api/v1/audit?resource_type=SIGNAL&resource_id={audited_signal.id}",
            headers=_auth(admin_user),
        )
        assert r.status_code == 200
        entries = r.json()
        assert len(entries) > 0
        assert all(e["resource_type"] == "SIGNAL" for e in entries)
        assert all(e["resource_id"] == str(audited_signal.id) for e in entries)

    def test_filter_by_action(self, client: TestClient, admin_user, audited_signal):
        r = client.get(
            "/api/v1/audit?action=SIGNAL_SUBMITTED_FOR_REVIEW",
            headers=_auth(admin_user),
        )
        assert r.status_code == 200
        entries = r.json()
        assert all(e["action"] == "SIGNAL_SUBMITTED_FOR_REVIEW" for e in entries)

    def test_pagination_limit_respected(self, client: TestClient, admin_user, audited_signal):
        r = client.get("/api/v1/audit?limit=1", headers=_auth(admin_user))
        assert r.status_code == 200
        assert len(r.json()) <= 1


class TestAuditApiDetail:
    def test_get_audit_entry_by_id(self, client: TestClient, admin_user, audited_signal):
        listing = client.get(
            f"/api/v1/audit?resource_type=SIGNAL&resource_id={audited_signal.id}",
            headers=_auth(admin_user),
        ).json()
        entry_id = listing[0]["id"]

        r = client.get(f"/api/v1/audit/{entry_id}", headers=_auth(admin_user))
        assert r.status_code == 200
        assert r.json()["id"] == entry_id

    def test_get_nonexistent_audit_entry_404(self, client: TestClient, admin_user):
        r = client.get(f"/api/v1/audit/{uuid4()}", headers=_auth(admin_user))
        assert r.status_code == 404

    def test_get_audit_entry_invalid_id_format_400(self, client: TestClient, admin_user):
        r = client.get("/api/v1/audit/not-a-uuid", headers=_auth(admin_user))
        assert r.status_code == 400


class TestAuditApiNoMutationSurface:
    """AuditLog is append-only: no update/delete endpoints exist for it."""

    def test_no_delete_endpoint(self, client: TestClient, admin_user, audited_signal):
        listing = client.get(
            f"/api/v1/audit?resource_type=SIGNAL&resource_id={audited_signal.id}",
            headers=_auth(admin_user),
        ).json()
        entry_id = listing[0]["id"]

        r = client.delete(f"/api/v1/audit/{entry_id}", headers=_auth(admin_user))
        assert r.status_code in (404, 405)

    def test_no_update_endpoint(self, client: TestClient, admin_user, audited_signal):
        listing = client.get(
            f"/api/v1/audit?resource_type=SIGNAL&resource_id={audited_signal.id}",
            headers=_auth(admin_user),
        ).json()
        entry_id = listing[0]["id"]

        r = client.put(f"/api/v1/audit/{entry_id}", json={"action": "TAMPERED"}, headers=_auth(admin_user))
        assert r.status_code in (404, 405)

        r = client.patch(f"/api/v1/audit/{entry_id}", json={"action": "TAMPERED"}, headers=_auth(admin_user))
        assert r.status_code in (404, 405)


class TestAuditApiSensitiveDataLeakage:
    """AuditLog.changes is populated exclusively by our own service code and
    must never carry a password, password hash, or JWT."""

    def test_audit_listing_never_contains_password_or_secrets(self, client: TestClient, admin_user):
        plaintext_password = "TotallySecretPassword123!"
        create_resp = client.post(
            "/api/v1/users",
            json={
                "username": "leak_check_user",
                "email": "leak_check_user@test.local",
                "role": "viewer",
                "password": plaintext_password,
            },
            headers=_auth(admin_user),
        )
        assert create_resp.status_code == 201

        login_resp = client.post(
            "/api/v1/auth/login",
            json={"username": "leak_check_user", "password": plaintext_password},
        )
        token = login_resp.json()["access_token"]

        listing_resp = client.get("/api/v1/audit?limit=200", headers=_auth(admin_user))
        assert listing_resp.status_code == 200

        raw_body = listing_resp.text
        assert plaintext_password not in raw_body
        assert token not in raw_body
        assert "password_hash" not in raw_body
        assert "password" not in raw_body.lower()

