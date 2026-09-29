"""Integration tests for the Phase 6 admin-only user management API."""
import pytest
from uuid import uuid4, UUID
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import AuditLog, User, UserRole
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


@pytest.fixture
def inactive_user(db: Session) -> User:
    """A deactivated user with real audit/review history attached, to
    exercise the FK-safe permanent-removal path."""
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="already_inactive",
        email="already_inactive@test.local",
        role=UserRole.REVIEWER,
        password_hash=hash_password("InactivePassword123!"),
        is_active=False,
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def entra_only_user(db: Session) -> User:
    """No local password at all - signs in exclusively through Entra."""
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="entra_only_person",
        email="entra_only_person@example.test",
        role=UserRole.VIEWER,
        password_hash=None,
        entra_object_id="11111111-2222-3333-4444-555555555555",
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


class TestUserUniquenessEnforcedByPostgres:
    """Confirms username/email uniqueness is a real database constraint,
    not just an application-layer check - a raw insert that bypasses the
    service layer entirely must still be rejected by PostgreSQL itself."""

    def test_duplicate_username_rejected_at_db_level(self, db: Session, target_user):
        from sqlalchemy.exc import IntegrityError

        dupe = User(
            username=target_user.username,  # same username, different email
            email="a-different-email@test.local",
            role=UserRole.VIEWER,
            password_hash=hash_password("Str0ng!AnotherPassword"),
            is_active=True,
        )
        db.add(dupe)
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()

        count = db.query(User).filter_by(username=target_user.username).count()
        assert count == 1

    def test_duplicate_email_rejected_at_db_level(self, db: Session, target_user):
        from sqlalchemy.exc import IntegrityError

        dupe = User(
            username="a-different-username",
            email=target_user.email,  # same email, different username
            role=UserRole.VIEWER,
            password_hash=hash_password("Str0ng!AnotherPassword"),
            is_active=True,
        )
        db.add(dupe)
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()

        count = db.query(User).filter_by(email=target_user.email).count()
        assert count == 1

    def test_duplicate_via_api_does_not_expose_raw_db_error(self, client: TestClient, admin_user, target_user):
        """The 409 response must carry a clean, generic message - never the
        raw PostgreSQL/SQLAlchemy IntegrityError text (constraint name,
        table name, driver internals)."""
        r = client.post(
            "/api/v1/users",
            json={
                "username": target_user.username,
                "email": "another-new-email@test.local",
                "role": "viewer",
                "password": "Str0ng!AnotherPassword",
            },
            headers=_auth(admin_user),
        )
        assert r.status_code == 409
        body_text = r.text.lower()
        assert "integrityerror" not in body_text
        assert "psycopg2" not in body_text
        assert "constraint" not in body_text
        assert "traceback" not in body_text


class TestUserSerializationExposesAuthMethod:
    def test_local_only_user_reports_local_credential_and_no_entra_link(self, client: TestClient, admin_user, target_user):
        r = client.get(f"/api/v1/users/{target_user.id}", headers=_auth(admin_user))
        assert r.status_code == 200
        assert r.json()["has_local_credential"] is True
        assert r.json()["entra_linked"] is False

    def test_entra_only_user_reports_no_local_credential(self, client: TestClient, admin_user, entra_only_user):
        r = client.get(f"/api/v1/users/{entra_only_user.id}", headers=_auth(admin_user))
        assert r.status_code == 200
        assert r.json()["has_local_credential"] is False
        assert r.json()["entra_linked"] is True


class TestInactiveUserPurge:
    """Permanent removal of an already-deactivated account. Never touches
    an active user, and is safe by construction: signal.reviewed_by and
    audit_log.user_id are ON DELETE SET NULL, and the audit_log
    immutability trigger explicitly allows that exact cascade."""

    def test_purge_requires_admin(self, client: TestClient, reviewer_user, inactive_user):
        r = client.delete(f"/api/v1/users/{inactive_user.id}", headers=_auth(reviewer_user))
        assert r.status_code == 403

    def test_purge_without_token_401(self, client: TestClient, inactive_user):
        r = client.delete(f"/api/v1/users/{inactive_user.id}")
        assert r.status_code == 401

    def test_admin_can_purge_an_inactive_user(self, client: TestClient, admin_user, inactive_user, db: Session):
        user_id = inactive_user.id
        r = client.delete(f"/api/v1/users/{user_id}", headers=_auth(admin_user))
        assert r.status_code == 204

        assert db.query(User).filter_by(id=user_id).one_or_none() is None

    def test_an_active_user_can_never_be_purged(self, client: TestClient, admin_user, target_user, db: Session):
        """The core safety guarantee: only is_active=False accounts may
        ever be permanently removed."""
        assert target_user.is_active is True
        r = client.delete(f"/api/v1/users/{target_user.id}", headers=_auth(admin_user))
        assert r.status_code == 400

        assert db.query(User).filter_by(id=target_user.id).one_or_none() is not None

    def test_the_currently_active_admin_cannot_be_purged(self, client: TestClient, admin_user, db: Session):
        r = client.delete(f"/api/v1/users/{admin_user.id}", headers=_auth(admin_user))
        assert r.status_code == 400
        assert db.query(User).filter_by(id=admin_user.id).one_or_none() is not None

    def test_purge_nonexistent_user_404(self, client: TestClient, admin_user):
        r = client.delete(f"/api/v1/users/{uuid4()}", headers=_auth(admin_user))
        assert r.status_code == 404

    def test_purge_is_audited_with_an_identity_snapshot(self, client: TestClient, admin_user, inactive_user, db: Session):
        user_id = inactive_user.id
        username, email, role = inactive_user.username, inactive_user.email, inactive_user.role.value

        r = client.delete(f"/api/v1/users/{user_id}", headers=_auth(admin_user))
        assert r.status_code == 204

        audit_repo = AuditLogRepository(db)
        logs = audit_repo.query(resource_type="USER", resource_id=user_id)
        purge_entries = [log for log in logs if log.action == "USER_PURGED"]
        assert len(purge_entries) == 1
        assert purge_entries[0].changes["username"] == username
        assert purge_entries[0].changes["email"] == email
        assert purge_entries[0].changes["role"] == role
        assert purge_entries[0].user_id == admin_user.id  # actor = the admin who purged, not the purged user

    def test_purging_a_user_preserves_their_prior_audit_history_with_user_id_nulled(
        self, client: TestClient, admin_user, inactive_user, db: Session,
    ):
        """The FK ON DELETE SET NULL cascade (and the audit_log
        immutability trigger's explicit allowance for it) is exercised for
        real here, against a real prior audit record - not just against the
        purge's own new entry."""
        user_id = inactive_user.id
        AuditLogRepository(db).create(
            user_id=user_id, action="LOGIN_SUCCESS", resource_type="user", resource_id=user_id,
            changes={"username": inactive_user.username},
        )
        db.commit()
        prior_log_id = (
            db.query(AuditLog)
            .filter_by(user_id=user_id, action="LOGIN_SUCCESS")
            .one()
            .id
        )

        r = client.delete(f"/api/v1/users/{user_id}", headers=_auth(admin_user))
        assert r.status_code == 204

        db.expire_all()
        prior_log = db.query(AuditLog).filter_by(id=prior_log_id).one()
        assert prior_log.user_id is None  # cascaded to NULL, row itself untouched
        assert prior_log.changes == {"username": inactive_user.username}  # substance preserved

    def test_purging_a_reviewer_preserves_their_reviewed_signals_with_reviewed_by_nulled(
        self, client: TestClient, admin_user, db: Session,
    ):
        """Signal content is never modified by a purge - only the
        reviewer-attribution FK is nulled, exactly like audit_log.user_id."""
        from app.db.models import EventSeverity, EventType, Signal, SignalStatus, SecurityEvent

        user_repo = UserRepository(db)
        reviewer = user_repo.create(
            username="soon_inactive_reviewer", email="soon_inactive_reviewer@test.local",
            role=UserRole.REVIEWER, password_hash=hash_password("ReviewerPassword123!"), is_active=False,
        )
        event = SecurityEvent(
            name="Event for purge test", description="D",
            event_type=EventType.VULNERABILITY, severity=EventSeverity.HIGH,
        )
        db.add(event)
        db.flush()
        signal = Signal(
            event_id=event.id, reviewed_by=reviewer.id, status=SignalStatus.APPROVED,
            title="Signal reviewed by soon-purged user", summary="s", security_impact="i",
            principle="p", recommended_action="a",
        )
        db.add(signal)
        db.commit()
        signal_id, signal_title = signal.id, signal.title

        r = client.delete(f"/api/v1/users/{reviewer.id}", headers=_auth(admin_user))
        assert r.status_code == 204

        db.expire_all()
        kept_signal = db.query(Signal).filter_by(id=signal_id).one()
        assert kept_signal.reviewed_by is None  # cascaded to NULL
        assert kept_signal.title == signal_title  # signal content untouched
        assert kept_signal.status == SignalStatus.APPROVED

    def test_purged_users_credentials_can_never_authenticate_again(
        self, client: TestClient, admin_user, inactive_user,
    ):
        client.delete(f"/api/v1/users/{inactive_user.id}", headers=_auth(admin_user))

        r = client.post(
            "/api/v1/auth/login",
            json={"username": "already_inactive", "password": "InactivePassword123!"},
        )
        assert r.status_code == 401


class TestPurgeInactiveUserService:
    """Unit-level coverage of the service method itself, independent of
    the HTTP layer."""

    def test_purge_all_inactive_users_removes_every_inactive_and_no_active_ones(self, db: Session, admin_user):
        from app.services.user_service import UserService

        user_repo = UserRepository(db)
        inactive_ids = []
        for i in range(3):
            u = user_repo.create(
                username=f"bulk_inactive_{i}", email=f"bulk_inactive_{i}@test.local",
                role=UserRole.VIEWER, password_hash=hash_password("Password123!Aa"), is_active=False,
            )
            inactive_ids.append(u.id)
        db.commit()

        service = UserService(db)
        results = service.purge_all_inactive_users(actor_id=admin_user.id)
        db.commit()

        purged_ids = {r["id"] for r in results}
        assert {str(i) for i in inactive_ids} <= purged_ids
        for uid in inactive_ids:
            assert db.query(User).filter_by(id=uid).one_or_none() is None
        # The active admin used as the actor is untouched.
        assert db.query(User).filter_by(id=admin_user.id).one_or_none() is not None


class TestAdminPasswordReset:
    """ADMIN sets a fresh password for another LOCAL user. The admin never
    views or submits the existing password - only ever a brand new one."""

    def test_reset_requires_admin(self, client: TestClient, reviewer_user, target_user):
        r = client.post(
            f"/api/v1/users/{target_user.id}/reset-password",
            json={"new_password": "NewStr0ng!Passw0rd", "confirm_password": "NewStr0ng!Passw0rd"},
            headers=_auth(reviewer_user),
        )
        assert r.status_code == 403

    def test_reset_without_token_401(self, client: TestClient, target_user):
        r = client.post(
            f"/api/v1/users/{target_user.id}/reset-password",
            json={"new_password": "NewStr0ng!Passw0rd", "confirm_password": "NewStr0ng!Passw0rd"},
        )
        assert r.status_code == 401

    def test_admin_can_reset_a_local_users_password(self, client: TestClient, admin_user, target_user):
        r = client.post(
            f"/api/v1/users/{target_user.id}/reset-password",
            json={"new_password": "Br4nd!NewPassword", "confirm_password": "Br4nd!NewPassword"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 200
        assert "Br4nd!NewPassword" not in r.text
        assert "$2b$" not in r.text  # no bcrypt hash in the response

        login = client.post(
            "/api/v1/auth/login", json={"username": target_user.username, "password": "Br4nd!NewPassword"},
        )
        assert login.status_code == 200

        old_login = client.post(
            "/api/v1/auth/login", json={"username": target_user.username, "password": "TargetPassword123!"},
        )
        assert old_login.status_code == 401

    def test_reset_confirmation_mismatch_rejected(self, client: TestClient, admin_user, target_user):
        r = client.post(
            f"/api/v1/users/{target_user.id}/reset-password",
            json={"new_password": "Br4nd!NewPassword", "confirm_password": "Different!Passw0rd"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 400

    def test_reset_weak_password_rejected(self, client: TestClient, admin_user, target_user):
        r = client.post(
            f"/api/v1/users/{target_user.id}/reset-password",
            json={"new_password": "weak", "confirm_password": "weak"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 400

    def test_reset_nonexistent_user_404(self, client: TestClient, admin_user):
        r = client.post(
            f"/api/v1/users/{uuid4()}/reset-password",
            json={"new_password": "Br4nd!NewPassword", "confirm_password": "Br4nd!NewPassword"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 404

    def test_entra_only_user_cannot_have_a_local_password_reset(self, client: TestClient, admin_user, entra_only_user):
        """An admin can never manage an Entra identity's credential as if
        it were a local password - this account has none to reset."""
        r = client.post(
            f"/api/v1/users/{entra_only_user.id}/reset-password",
            json={"new_password": "Br4nd!NewPassword", "confirm_password": "Br4nd!NewPassword"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 400

    def test_reset_is_audited_without_the_password_and_attributes_the_admin_as_actor(
        self, client: TestClient, admin_user, target_user, db: Session,
    ):
        r = client.post(
            f"/api/v1/users/{target_user.id}/reset-password",
            json={"new_password": "Br4nd!NewPassword", "confirm_password": "Br4nd!NewPassword"},
            headers=_auth(admin_user),
        )
        assert r.status_code == 200

        audit_repo = AuditLogRepository(db)
        logs = audit_repo.query(resource_type="USER", resource_id=target_user.id)
        reset_entries = [log for log in logs if log.action == "PASSWORD_RESET_BY_ADMIN"]
        assert len(reset_entries) == 1
        assert reset_entries[0].user_id == admin_user.id
        assert "Br4nd!NewPassword" not in str(reset_entries[0].changes)

    def test_reset_invalidates_the_targets_existing_session(self, client: TestClient, admin_user, target_user):
        """The whole point of tracking password_changed_at: a token issued
        before the reset stops working immediately afterward. Uses logout
        (auth-only, no role requirement) so this isolates the pwd_ver check
        from target_user's (VIEWER) role-based access separately."""
        stale_token = _token(target_user)
        assert client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {stale_token}"}).status_code == 204

        stale_token = _token(target_user)  # a second, equally-stale token
        client.post(
            f"/api/v1/users/{target_user.id}/reset-password",
            json={"new_password": "Br4nd!NewPassword", "confirm_password": "Br4nd!NewPassword"},
            headers=_auth(admin_user),
        )

        r = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {stale_token}"})
        assert r.status_code == 401


class TestSelfServicePasswordChange:
    """The currently authenticated user changes their own password."""

    def test_change_password_without_token_401(self, client: TestClient):
        r = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "x", "new_password": "NewStr0ng!Passw0rd", "confirm_password": "NewStr0ng!Passw0rd"},
        )
        assert r.status_code == 401

    def test_successful_change(self, client: TestClient, target_user):
        r = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "TargetPassword123!",
                "new_password": "Br4nd!NewOwnPassword",
                "confirm_password": "Br4nd!NewOwnPassword",
            },
            headers=_auth(target_user),
        )
        assert r.status_code == 204

        login = client.post(
            "/api/v1/auth/login", json={"username": target_user.username, "password": "Br4nd!NewOwnPassword"},
        )
        assert login.status_code == 200

    def test_incorrect_current_password_rejected(self, client: TestClient, target_user):
        r = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "WrongCurrentPassword!",
                "new_password": "Br4nd!NewOwnPassword",
                "confirm_password": "Br4nd!NewOwnPassword",
            },
            headers=_auth(target_user),
        )
        # 400, not 401: the caller IS authenticated - a wrong current
        # password is a validation failure, never treated as a session
        # problem (the frontend maps any 401 to "session expired, sign
        # out", which would be wrong here).
        assert r.status_code == 400

        # The password must NOT have changed - old credentials still work.
        login = client.post(
            "/api/v1/auth/login", json={"username": target_user.username, "password": "TargetPassword123!"},
        )
        assert login.status_code == 200

    def test_confirmation_mismatch_rejected(self, client: TestClient, target_user):
        r = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "TargetPassword123!",
                "new_password": "Br4nd!NewOwnPassword",
                "confirm_password": "SomethingElse!Pw",
            },
            headers=_auth(target_user),
        )
        assert r.status_code == 400

    def test_weak_new_password_rejected(self, client: TestClient, target_user):
        r = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "TargetPassword123!", "new_password": "weak", "confirm_password": "weak"},
            headers=_auth(target_user),
        )
        assert r.status_code == 400

    def test_new_password_identical_to_username_rejected(self, client: TestClient, target_user):
        r = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "TargetPassword123!",
                "new_password": target_user.username,
                "confirm_password": target_user.username,
            },
            headers=_auth(target_user),
        )
        assert r.status_code == 400

    def test_entra_only_user_cannot_change_a_local_password_that_does_not_exist(
        self, client: TestClient, entra_only_user,
    ):
        r = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "anything",
                "new_password": "Br4nd!NewOwnPassword",
                "confirm_password": "Br4nd!NewOwnPassword",
            },
            headers=_auth(entra_only_user),
        )
        assert r.status_code == 400

    def test_a_user_cannot_change_another_users_password_via_this_endpoint(self, client: TestClient, target_user, second_admin):
        """This endpoint only ever acts on the CALLER's own account - there
        is no user_id in the request, so there's nothing for a caller to
        redirect at someone else's account."""
        r = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "AdminPassword123!",
                "new_password": "Br4nd!NewOwnPassword",
                "confirm_password": "Br4nd!NewOwnPassword",
            },
            headers=_auth(target_user),  # target_user's OWN token
        )
        # Succeeds or fails based on target_user's own current password
        # only - second_admin's password is untouched either way.
        assert r.status_code in (204, 400)
        login = client.post(
            "/api/v1/auth/login", json={"username": second_admin.username, "password": "AdminPassword123!"},
        )
        assert login.status_code == 200

    def test_change_is_audited_without_the_password_and_self_attributed(
        self, client: TestClient, target_user, db: Session,
    ):
        r = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "TargetPassword123!",
                "new_password": "Br4nd!NewOwnPassword",
                "confirm_password": "Br4nd!NewOwnPassword",
            },
            headers=_auth(target_user),
        )
        assert r.status_code == 204

        audit_repo = AuditLogRepository(db)
        logs = audit_repo.query(resource_type="USER", resource_id=target_user.id)
        change_entries = [log for log in logs if log.action == "PASSWORD_CHANGED"]
        assert len(change_entries) == 1
        assert change_entries[0].user_id == target_user.id
        assert "Br4nd!NewOwnPassword" not in str(change_entries[0].changes)
        assert "TargetPassword123!" not in str(change_entries[0].changes)

    def test_change_never_returns_or_leaks_a_password_hash(self, client: TestClient, target_user, db: Session):
        r = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "TargetPassword123!",
                "new_password": "Br4nd!NewOwnPassword",
                "confirm_password": "Br4nd!NewOwnPassword",
            },
            headers=_auth(target_user),
        )
        assert "$2b$" not in r.text  # bcrypt hash prefix never appears

        db.refresh(target_user)
        assert target_user.password_hash != "Br4nd!NewOwnPassword"  # stored hashed, not plaintext
        from app.auth.password import verify_password
        assert verify_password("Br4nd!NewOwnPassword", target_user.password_hash) is True

    def test_change_invalidates_every_previously_issued_token_including_the_one_just_used(
        self, client: TestClient, target_user,
    ):
        """Uses logout (auth-only, no role requirement) to check the token
        post-change, isolating the pwd_ver check from target_user's
        (VIEWER) role-based access. The change-password call itself
        succeeding with this exact token already proves it worked
        beforehand."""
        stale_token = _token(target_user)

        r = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "TargetPassword123!",
                "new_password": "Br4nd!NewOwnPassword",
                "confirm_password": "Br4nd!NewOwnPassword",
            },
            headers={"Authorization": f"Bearer {stale_token}"},
        )
        assert r.status_code == 204

        r = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {stale_token}"})
        assert r.status_code == 401

    def test_password_change_never_appears_in_response_body(self, client: TestClient, target_user):
        r = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "TargetPassword123!",
                "new_password": "Br4nd!NewOwnPassword",
                "confirm_password": "Br4nd!NewOwnPassword",
            },
            headers=_auth(target_user),
        )
        assert r.status_code == 204
        assert r.text == ""  # no body at all on success - nothing to leak
