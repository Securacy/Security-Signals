"""Integration tests for the Phase 6 admin-only user management API."""
import pytest
from uuid import uuid4, UUID
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import User, UserRole
from app.auth.password import hash_password
from app.auth.tokens import create_access_token
from app.repositories import UserRepository, AuditLogRepository


def _token(user: User) -> str:
    return create_access_token(user_id=user.id, username=user.username, role=user.role.value)


def _auth(user: User) -> dict:
    return {"Authorization": f"Bearer {_token(user)}"}


@pytest.fixture
def admin_user(db: Session) -> User:
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="users_admin",
        email="users_admin@test.local",
        role=UserRole.ADMIN,
        password_hash=hash_password("AdminPassword123!"),
        is_active=True,
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def second_admin(db: Session) -> User:
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="users_admin_2",
        email="users_admin_2@test.local",
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
        username="users_reviewer",
        email="users_reviewer@test.local",
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
        username="users_viewer",
        email="users_viewer@test.local",
        role=UserRole.VIEWER,
        password_hash=hash_password("ViewerPassword123!"),
        is_active=True,
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def target_user(db: Session) -> User:
    """A plain user for admins to act on (update/deactivate)."""
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="target_user",
        email="target_user@test.local",
        role=UserRole.VIEWER,
        password_hash=hash_password("TargetPassword123!"),
        is_active=True,
    )
    db.commit()
    db.refresh(user)
    return user


class TestUserCreationAuth:
    """Authentication/authorization gating on user creation."""

    def test_create_user_without_token_401(self, client: TestClient):
        r = client.post(
            "/api/v1/users",
            json={"username": "nobody", "email": "nobody@test.local", "role": "viewer", "password": "Password123!"},
        )
        assert r.status_code == 401

    def test_reviewer_cannot_create_user_403(self, client: TestClient, reviewer_user):
        r = client.post(
            "/api/v1/users",
            json={"username": "nobody", "email": "nobody@test.local", "role": "viewer", "password": "Password123!"},
            headers=_auth(reviewer_user),
        )
        assert r.status_code == 403

    def test_viewer_cannot_create_user_403(self, client: TestClient, viewer_user):
        r = client.post(
            "/api/v1/users",
            json={"username": "nobody", "email": "nobody@test.local", "role": "viewer", "password": "Password123!"},
            headers=_auth(viewer_user),
        )
        assert r.status_code == 403

    def test_privilege_escalation_attempt_blocked(self, client: TestClient, viewer_user):
        """A non-admin cannot create a new ADMIN account - blocked by the
        endpoint's require_admin gate before any business logic runs."""
        r = client.post(
            "/api/v1/users",
            json={"username": "escalated", "email": "escalated@test.local", "role": "admin", "password": "Password123!"},
            headers=_auth(viewer_user),
        )
        assert r.status_code == 403


class TestUserCreationSuccess:
    def test_admin_can_create_user(self, client: TestClient, admin_user, db: Session):
        r = client.post(
            "/api/v1/users",
            json={
                "username": "newuser",
                "email": "newuser@test.local",
                "role": "reviewer",
                "password": "NewUserPassword123!",
            },
            headers=_auth(admin_user),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["username"] == "newuser"
        assert body["role"] == "reviewer"
        assert body["is_active"] is True
        assert "password" not in body
        assert "password_hash" not in body

        # Audit entry recorded
        audit_repo = AuditLogRepository(db)
        logs = audit_repo.query(resource_type="USER", resource_id=UUID(body["id"]))
        actions = [log.action for log in logs]
        assert "USER_CREATED" in actions

    def test_create_user_response_never_leaks_password(self, client: TestClient, admin_user):
        r = client.post(
            "/api/v1/users",
            json={
                "username": "leaktest",
                "email": "leaktest@test.local",
                "role": "viewer",
                "password": "SuperSecretPassword123!",
            },
            headers=_auth(admin_user),
        )
        assert r.status_code == 201
        assert "SuperSecretPassword123!" not in r.text
        assert "password" not in r.text.lower()


class TestUserCreationValidation:
    def test_duplicate_username_returns_409(self, client: TestClient, admin_user, target_user):
        r = client.post(
            "/api/v1/users",
            json={
                "username": target_user.username,
                "email": "different@test.local",
                "role": "viewer",
                "password": "Password123!",
            },
            headers=_auth(admin_user),
        )
        assert r.status_code == 409

    def test_duplicate_email_returns_409(self, client: TestClient, admin_user, target_user):
        r = client.post(
            "/api/v1/users",
            json={
                "username": "differentname",
                "email": target_user.email,
                "role": "viewer",
                "password": "Password123!",
            },
            headers=_auth(admin_user),
        )
        assert r.status_code == 409

    def test_short_password_rejected(self, client: TestClient, admin_user):
        r = client.post(
            "/api/v1/users",
            json={"username": "shortpw", "email": "shortpw@test.local", "role": "viewer", "password": "short"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 422

    def test_invalid_email_rejected(self, client: TestClient, admin_user):
        r = client.post(
            "/api/v1/users",
            json={"username": "bademail", "email": "not-an-email", "role": "viewer", "password": "Password123!"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 422

    def test_invalid_role_rejected(self, client: TestClient, admin_user):
        r = client.post(
            "/api/v1/users",
            json={"username": "badrole", "email": "badrole@test.local", "role": "superuser", "password": "Password123!"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 422

    def test_invalid_username_rejected(self, client: TestClient, admin_user):
        r = client.post(
            "/api/v1/users",
            json={"username": "a", "email": "shortname@test.local", "role": "viewer", "password": "Password123!"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 422


class TestUserListAndGet:
    def test_list_users_requires_admin(self, client: TestClient, reviewer_user):
        r = client.get("/api/v1/users", headers=_auth(reviewer_user))
        assert r.status_code == 403

    def test_admin_can_list_users(self, client: TestClient, admin_user, target_user):
        r = client.get("/api/v1/users", headers=_auth(admin_user))
        assert r.status_code == 200
        usernames = [u["username"] for u in r.json()]
        assert target_user.username in usernames
        assert all("password" not in u and "password_hash" not in u for u in r.json())

    def test_list_users_pagination(self, client: TestClient, admin_user, target_user):
        r = client.get("/api/v1/users?skip=0&limit=1", headers=_auth(admin_user))
        assert r.status_code == 200
        assert len(r.json()) <= 1

    def test_get_user_by_id(self, client: TestClient, admin_user, target_user):
        r = client.get(f"/api/v1/users/{target_user.id}", headers=_auth(admin_user))
        assert r.status_code == 200
        assert r.json()["id"] == str(target_user.id)

    def test_get_nonexistent_user_404(self, client: TestClient, admin_user):
        r = client.get(f"/api/v1/users/{uuid4()}", headers=_auth(admin_user))
        assert r.status_code == 404

    def test_get_user_invalid_id_format_400(self, client: TestClient, admin_user):
        r = client.get("/api/v1/users/not-a-uuid", headers=_auth(admin_user))
        assert r.status_code == 400

    def test_idor_non_admin_cannot_fetch_any_user_by_id(self, client: TestClient, viewer_user, target_user):
        """A non-admin cannot read another user's record by guessing/knowing
        its ID - the role gate blocks access regardless of which ID is
        requested, so IDs can't be enumerated via this endpoint either."""
        r = client.get(f"/api/v1/users/{target_user.id}", headers=_auth(viewer_user))
        assert r.status_code == 403


class TestUserUpdate:
    def test_update_requires_admin(self, client: TestClient, reviewer_user, target_user):
        r = client.patch(
            f"/api/v1/users/{target_user.id}",
            json={"role": "admin"},
            headers=_auth(reviewer_user),
        )
        assert r.status_code == 403

    def test_admin_can_update_role(self, client: TestClient, admin_user, target_user, db: Session):
        r = client.patch(
            f"/api/v1/users/{target_user.id}",
            json={"role": "reviewer"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 200
        assert r.json()["role"] == "reviewer"

        audit_repo = AuditLogRepository(db)
        logs = audit_repo.query(resource_type="USER", resource_id=target_user.id)
        assert any(log.action == "USER_UPDATED" for log in logs)

    def test_admin_can_update_email(self, client: TestClient, admin_user, target_user):
        r = client.patch(
            f"/api/v1/users/{target_user.id}",
            json={"email": "updated@test.local"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 200
        assert r.json()["email"] == "updated@test.local"

    def test_update_to_duplicate_email_returns_409(self, client: TestClient, admin_user, target_user, second_admin):
        r = client.patch(
            f"/api/v1/users/{target_user.id}",
            json={"email": second_admin.email},
            headers=_auth(admin_user),
        )
        assert r.status_code == 409

    def test_update_nonexistent_user_404(self, client: TestClient, admin_user):
        r = client.patch(f"/api/v1/users/{uuid4()}", json={"email": "x@test.local"}, headers=_auth(admin_user))
        assert r.status_code == 404

    def test_update_invalid_email_rejected(self, client: TestClient, admin_user, target_user):
        r = client.patch(
            f"/api/v1/users/{target_user.id}",
            json={"email": "not-an-email"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 422

    def test_update_with_no_fields_returns_400(self, client: TestClient, admin_user, target_user):
        r = client.patch(f"/api/v1/users/{target_user.id}", json={}, headers=_auth(admin_user))
        assert r.status_code == 400


class TestUserDeactivation:
    def test_deactivate_requires_admin(self, client: TestClient, reviewer_user, target_user):
        r = client.post(f"/api/v1/users/{target_user.id}/deactivate", headers=_auth(reviewer_user))
        assert r.status_code == 403

    def test_admin_can_deactivate_user(self, client: TestClient, admin_user, target_user, db: Session):
        r = client.post(f"/api/v1/users/{target_user.id}/deactivate", headers=_auth(admin_user))
        assert r.status_code == 200
        assert r.json()["is_active"] is False

        audit_repo = AuditLogRepository(db)
        logs = audit_repo.query(resource_type="USER", resource_id=target_user.id)
        assert any(log.action == "USER_DEACTIVATED" for log in logs)

    def test_deactivating_already_inactive_user_returns_400(self, client: TestClient, admin_user, target_user):
        client.post(f"/api/v1/users/{target_user.id}/deactivate", headers=_auth(admin_user))
        r = client.post(f"/api/v1/users/{target_user.id}/deactivate", headers=_auth(admin_user))
        assert r.status_code == 400

    def test_admin_cannot_deactivate_own_account(self, client: TestClient, admin_user):
        """Self-lockout prevention: an admin cannot deactivate themselves."""
        r = client.post(f"/api/v1/users/{admin_user.id}/deactivate", headers=_auth(admin_user))
        assert r.status_code == 400

    def test_deactivate_nonexistent_user_404(self, client: TestClient, admin_user):
        r = client.post(f"/api/v1/users/{uuid4()}/deactivate", headers=_auth(admin_user))
        assert r.status_code == 404

    def test_deactivated_user_cannot_log_in(self, client: TestClient, admin_user, target_user):
        client.post(f"/api/v1/users/{target_user.id}/deactivate", headers=_auth(admin_user))

        r = client.post(
            "/api/v1/auth/login",
            json={"username": target_user.username, "password": "TargetPassword123!"},
        )
        assert r.status_code == 403
