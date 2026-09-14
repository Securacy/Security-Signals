"""Integration tests for the Phase 6 review workflow HTTP endpoints.

Exercises submit-for-review/approve/reject/publish over real HTTP requests
(not just the SignalService layer directly, which test_signals_audit.py
already covers), including authentication, RBAC, invalid transitions, and
not-found handling.
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
        username="review_admin",
        email="review_admin@test.local",
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
        username="review_reviewer",
        email="review_reviewer@test.local",
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
        username="review_viewer",
        email="review_viewer@test.local",
        role=UserRole.VIEWER,
        password_hash=hash_password("ViewerPassword123!"),
        is_active=True,
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def inactive_reviewer(db: Session) -> User:
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="review_inactive",
        email="review_inactive@test.local",
        role=UserRole.REVIEWER,
        password_hash=hash_password("InactivePassword123!"),
        is_active=False,
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def ai_response() -> AISignalGenerationResponse:
    return AISignalGenerationResponse(
        signal_title="Test Signal",
        signal_description="Comprehensive security signal description covering vulnerability analysis and remediation steps for system hardening.",
        category="vulnerability",
        confidence=0.8,
        evidence_summary="Evidence discovered in security audit.",
        secure_design_principles=[],
    )


@pytest.fixture
def draft_signal(db: Session, security_event, ai_response):
    """A DRAFT signal with the evidence required to enter review."""
    service = SignalService(db)
    signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
    service.add_evidence(
        signal_id=signal.id,
        source_url="https://example.com/advisory",
        source_title="Security Advisory",
        excerpt="Evidence of vulnerability",
    )
    db.commit()
    db.refresh(signal)
    return signal


class TestReviewWorkflowAuthRequired:
    """Unauthenticated requests to any lifecycle endpoint are rejected."""

    def test_submit_without_token_401(self, client: TestClient, draft_signal):
        r = client.post(f"/api/v1/signals/{draft_signal.id}/submit-for-review")
        assert r.status_code == 401

    def test_approve_without_token_401(self, client: TestClient, draft_signal):
        r = client.post(f"/api/v1/signals/{draft_signal.id}/approve")
        assert r.status_code == 401

    def test_reject_without_token_401(self, client: TestClient, draft_signal):
        r = client.post(f"/api/v1/signals/{draft_signal.id}/reject")
        assert r.status_code == 401

    def test_publish_without_token_401(self, client: TestClient, draft_signal):
        r = client.post(f"/api/v1/signals/{draft_signal.id}/publish")
        assert r.status_code == 401


class TestReviewWorkflowRoleEnforcement:
    """RBAC on the lifecycle endpoints."""

    def test_viewer_cannot_submit_403(self, client: TestClient, draft_signal, viewer_user):
        r = client.post(
            f"/api/v1/signals/{draft_signal.id}/submit-for-review",
            headers=_auth(viewer_user),
        )
        assert r.status_code == 403

    def test_viewer_cannot_approve_403(self, client: TestClient, draft_signal, viewer_user):
        r = client.post(
            f"/api/v1/signals/{draft_signal.id}/approve",
            headers=_auth(viewer_user),
        )
        assert r.status_code == 403

    def test_reviewer_cannot_publish_403(self, client: TestClient, draft_signal, reviewer_user):
        """Publishing is the final public-facing gate - ADMIN only, even for
        a REVIEWER who legitimately approved the same signal."""
        headers = _auth(reviewer_user)
        client.post(f"/api/v1/signals/{draft_signal.id}/submit-for-review", headers=headers)
        client.post(f"/api/v1/signals/{draft_signal.id}/approve", headers=headers)

        r = client.post(f"/api/v1/signals/{draft_signal.id}/publish", headers=headers)
        assert r.status_code == 403

    def test_admin_can_use_reviewer_endpoints(self, client: TestClient, draft_signal, admin_user):
        """ADMIN has REVIEWER privileges too (require_reviewer accepts admin)."""
        r = client.post(
            f"/api/v1/signals/{draft_signal.id}/submit-for-review",
            headers=_auth(admin_user),
        )
        assert r.status_code == 200

    def test_inactive_reviewer_cannot_access(self, client: TestClient, draft_signal, inactive_reviewer):
        r = client.post(
            f"/api/v1/signals/{draft_signal.id}/submit-for-review",
            headers=_auth(inactive_reviewer),
        )
        assert r.status_code == 403


class TestReviewWorkflowLifecycle:
    """End-to-end lifecycle transitions over HTTP."""

    def test_full_lifecycle_admin(self, client: TestClient, draft_signal, admin_user):
        headers = _auth(admin_user)

        r = client.post(f"/api/v1/signals/{draft_signal.id}/submit-for-review", headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "in_review"

        r = client.post(f"/api/v1/signals/{draft_signal.id}/approve", headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "approved"
        assert r.json()["reviewed_by"] == str(admin_user.id)

        r = client.post(f"/api/v1/signals/{draft_signal.id}/publish", headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "published"

        # Now visible through the public API too
        r = client.get(f"/api/v1/signals/published/{draft_signal.id}")
        assert r.status_code == 200

    def test_reviewer_can_reject(self, client: TestClient, draft_signal, reviewer_user):
        headers = _auth(reviewer_user)
        client.post(f"/api/v1/signals/{draft_signal.id}/submit-for-review", headers=headers)

        r = client.post(f"/api/v1/signals/{draft_signal.id}/reject", headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "rejected"
        assert r.json()["reviewed_by"] == str(reviewer_user.id)


class TestReviewWorkflowAuditActorId:
    """Regression tests: SIGNAL_SUBMITTED_FOR_REVIEW and SIGNAL_PUBLISHED
    audit entries must record the authenticated actor, not user_id=None.

    Previously these two routes called SignalService.submit_for_review()/
    publish_signal() without any actor, so their audit rows always had
    user_id=None even though the authenticated user was available on the
    request - unlike approve/reject, which already threaded reviewer_id
    through correctly.
    """

    def test_submit_for_review_records_authenticated_actor(
        self, client: TestClient, draft_signal, admin_user, db: Session
    ):
        from app.repositories import AuditLogRepository

        client.post(
            f"/api/v1/signals/{draft_signal.id}/submit-for-review",
            headers=_auth(admin_user),
        )

        audit_repo = AuditLogRepository(db)
        logs = audit_repo.get_by_resource("SIGNAL", draft_signal.id)
        submitted = [l for l in logs if l.action == "SIGNAL_SUBMITTED_FOR_REVIEW"]
        assert len(submitted) == 1
        assert submitted[0].user_id == admin_user.id

    def test_publish_records_authenticated_actor(
        self, client: TestClient, draft_signal, admin_user, db: Session
    ):
        from app.repositories import AuditLogRepository

        headers = _auth(admin_user)
        client.post(f"/api/v1/signals/{draft_signal.id}/submit-for-review", headers=headers)
        client.post(f"/api/v1/signals/{draft_signal.id}/approve", headers=headers)
        client.post(f"/api/v1/signals/{draft_signal.id}/publish", headers=headers)

        audit_repo = AuditLogRepository(db)
        logs = audit_repo.get_by_resource("SIGNAL", draft_signal.id)
        published = [l for l in logs if l.action == "SIGNAL_PUBLISHED"]
        assert len(published) == 1
        assert published[0].user_id == admin_user.id

    def test_submit_and_publish_actors_can_differ_from_reviewer(
        self, client: TestClient, draft_signal, admin_user, reviewer_user, db: Session
    ):
        """The submitter, reviewer, and publisher are recorded independently
        on their respective audit rows, even when different users perform
        each step."""
        from app.repositories import AuditLogRepository

        client.post(
            f"/api/v1/signals/{draft_signal.id}/submit-for-review",
            headers=_auth(reviewer_user),
        )
        client.post(f"/api/v1/signals/{draft_signal.id}/approve", headers=_auth(reviewer_user))
        client.post(f"/api/v1/signals/{draft_signal.id}/publish", headers=_auth(admin_user))

        audit_repo = AuditLogRepository(db)
        logs = {l.action: l for l in audit_repo.get_by_resource("SIGNAL", draft_signal.id)}

        assert logs["SIGNAL_SUBMITTED_FOR_REVIEW"].user_id == reviewer_user.id
        assert logs["SIGNAL_APPROVED"].user_id == reviewer_user.id
        assert logs["SIGNAL_PUBLISHED"].user_id == admin_user.id


class TestReviewWorkflowInvalidTransitions:
    """Lifecycle transitions attempted out of order are rejected with 400."""

    def test_approve_draft_signal_returns_400(self, client: TestClient, draft_signal, admin_user):
        r = client.post(f"/api/v1/signals/{draft_signal.id}/approve", headers=_auth(admin_user))
        assert r.status_code == 400

    def test_reject_draft_signal_returns_400(self, client: TestClient, draft_signal, admin_user):
        r = client.post(f"/api/v1/signals/{draft_signal.id}/reject", headers=_auth(admin_user))
        assert r.status_code == 400

    def test_publish_non_approved_signal_returns_400(self, client: TestClient, draft_signal, admin_user):
        r = client.post(f"/api/v1/signals/{draft_signal.id}/publish", headers=_auth(admin_user))
        assert r.status_code == 400

    def test_submit_twice_returns_400(self, client: TestClient, draft_signal, admin_user):
        headers = _auth(admin_user)
        client.post(f"/api/v1/signals/{draft_signal.id}/submit-for-review", headers=headers)

        r = client.post(f"/api/v1/signals/{draft_signal.id}/submit-for-review", headers=headers)
        assert r.status_code == 400


class TestReviewWorkflowNotFoundAndValidation:
    """Not-found and malformed-ID handling."""

    def test_submit_nonexistent_signal_404(self, client: TestClient, admin_user):
        r = client.post(f"/api/v1/signals/{uuid4()}/submit-for-review", headers=_auth(admin_user))
        assert r.status_code == 404

    def test_invalid_signal_id_format_400(self, client: TestClient, admin_user):
        r = client.post("/api/v1/signals/not-a-uuid/submit-for-review", headers=_auth(admin_user))
        assert r.status_code == 400
