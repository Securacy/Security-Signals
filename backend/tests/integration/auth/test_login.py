"""Integration tests for login endpoint and authentication flow."""

import pytest
from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import User, UserRole
from app.auth.password import hash_password
from app.repositories import UserRepository, AuditLogRepository


@pytest.fixture
def admin_user(db: Session) -> User:
    """Create test admin user."""
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="admin_test",
        email="admin@test.local",
        role=UserRole.ADMIN,
        password_hash=hash_password("AdminPassword123!"),
        is_active=True
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def reviewer_user(db: Session) -> User:
    """Create test reviewer user."""
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="reviewer_test",
        email="reviewer@test.local",
        role=UserRole.REVIEWER,
        password_hash=hash_password("ReviewerPassword123!"),
        is_active=True
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def inactive_user(db: Session) -> User:
    """Create inactive test user."""
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="inactive_test",
        email="inactive@test.local",
        role=UserRole.REVIEWER,
        password_hash=hash_password("InactivePassword123!"),
        is_active=False
    )
    db.commit()
    db.refresh(user)
    return user


class TestLoginSuccess:
    """Test successful login scenarios."""
    
    def test_login_admin_success(self, db: Session, admin_user: User, client: TestClient):
        """Admin user login with correct credentials."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin_test", "password": "AdminPassword123!"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["username"] == "admin_test"
        assert data["user"]["role"] == "admin"
        assert data["user"]["is_active"] is True
        # Lets the frontend profile menu show "Password managed" vs
        # "Microsoft Entra managed" without a second, admin-only API call.
        assert data["user"]["has_local_credential"] is True
        assert data["user"]["entra_linked"] is False

        # Verify audit log created
        audit_repo = AuditLogRepository(db)
        logs = audit_repo.get_by_resource("user", admin_user.id)
        login_logs = [log for log in logs if log.action == "LOGIN_SUCCESS"]
        assert len(login_logs) > 0
    
    def test_login_reviewer_success(self, db: Session, reviewer_user: User, client: TestClient):
        """Reviewer user login with correct credentials."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "reviewer_test", "password": "ReviewerPassword123!"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["role"] == "reviewer"
    
    def test_token_format_valid(self, admin_user: User, client: TestClient):
        """Token returned is a valid JWT string."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin_test", "password": "AdminPassword123!"}
        )
        
        token = response.json()["access_token"]
        parts = token.split(".")
        assert len(parts) == 3  # JWT has 3 parts: header.payload.signature


class TestLoginFailure:
    """Test failed login scenarios."""
    
    def test_login_wrong_password(self, admin_user: User, client: TestClient):
        """Login fails with incorrect password."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin_test", "password": "WrongPassword123!"}
        )
        
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"
    
    def test_login_nonexistent_user(self, client: TestClient):
        """Login fails for nonexistent user."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "nonexistent", "password": "AnyPassword123!"}
        )
        
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"
    
    def test_login_inactive_user(self, inactive_user: User, client: TestClient):
        """Login fails for inactive user."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "inactive_test", "password": "InactivePassword123!"}
        )
        
        assert response.status_code == 403
        assert "inactive" in response.json()["detail"].lower()
    
    def test_login_empty_username(self, client: TestClient):
        """Login fails with empty username."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "", "password": "AnyPassword123!"}
        )
        
        assert response.status_code in [401, 422]  # Unauthorized or validation error
    
    def test_login_empty_password(self, admin_user: User, client: TestClient):
        """Login fails with empty password."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin_test", "password": ""}
        )
        
        assert response.status_code == 401
    
    def test_login_missing_fields(self, client: TestClient):
        """Login fails when required fields missing."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin_test"}  # Missing password
        )
        
        assert response.status_code == 422  # Validation error


class TestAuthenticationDependency:
    """Test JWT validation and protected endpoints.
    
    These tests verify that protected endpoints enforce authentication.
    The /api/v1/signals/draft endpoint is protected by require_reviewer dependency.
    """
    
    def test_protected_endpoint_without_token(self, client: TestClient):
        """Protected endpoint returns 401 without Authorization header."""
        response = client.get("/api/v1/signals/draft")
        assert response.status_code == 401
        assert "Authorization" in response.json()["detail"] or "Missing" in response.json()["detail"]
    
    def test_protected_endpoint_with_invalid_token(self, client: TestClient):
        """Protected endpoint returns 401 with invalid JWT."""
        response = client.get(
            "/api/v1/signals/draft",
            headers={"Authorization": "Bearer invalid.token.here"}
        )
        assert response.status_code == 401
        assert "Invalid" in response.json()["detail"] or "expired" in response.json()["detail"].lower()
    
    def test_authorization_header_missing_bearer(self, admin_user: User, client: TestClient):
        """Request with Authorization header but no Bearer prefix returns 401."""
        # Login to get a valid token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin_test", "password": "AdminPassword123!"}
        )
        token = login_response.json()["access_token"]
        
        # Use token without Bearer prefix
        response = client.get(
            "/api/v1/signals/draft",
            headers={"Authorization": token}  # Missing "Bearer" prefix
        )
        assert response.status_code == 401
        assert "Invalid" in response.json()["detail"] or "format" in response.json()["detail"].lower()
class TestTokenValidation:
    """Test JWT token validation on protected endpoints."""
    
    def test_expired_token_rejected(self, db: Session, admin_user: User):
        """Expired JWT token rejected on protected endpoint."""
        from app.auth.tokens import create_access_token
        from app.auth.tokens import decode_access_token
        from app.common.errors import AuthenticationError
        
        # Create token that expires immediately
        expired_token = create_access_token(
            user_id=admin_user.id,
            username=admin_user.username,
            role=admin_user.role.value,
            expires_in_hours=-1  # Already expired
        )
        
        # Attempt to decode expired token
        with pytest.raises(AuthenticationError) as exc:
            decode_access_token(expired_token)
        assert "expired" in str(exc.value).lower()
    
    def test_token_with_wrong_secret_rejected(self, admin_user: User):
        """Token signed with wrong secret rejected."""
        import jwt
        from app.auth.tokens import decode_access_token
        from app.common.errors import AuthenticationError
        
        # Create token with wrong secret (use a sufficiently long test secret to avoid warnings)
        wrong_secret_payload = {
            "sub": str(admin_user.id),
            "username": admin_user.username,
            "role": admin_user.role.value,
            "exp": 9999999999,
            "iat": 0
        }
        # Use 32-byte test secret to avoid InsecureKeyLengthWarning
        test_wrong_secret = "this_is_a_32_byte_test_secret!!"
        wrong_token = jwt.encode(wrong_secret_payload, test_wrong_secret, algorithm="HS256")
        
        with pytest.raises(AuthenticationError):
            decode_access_token(wrong_token)


class TestAuditLogging:
    """Test audit log entries for authentication events."""
    
    def test_successful_login_audit_logged(self, db: Session, admin_user: User, client: TestClient):
        """Successful login creates audit log entry."""
        client.post(
            "/api/v1/auth/login",
            json={"username": "admin_test", "password": "AdminPassword123!"}
        )
        
        audit_repo = AuditLogRepository(db)
        logs = audit_repo.get_by_resource("user", admin_user.id)
        
        # Should have LOGIN_SUCCESS audit entry
        login_logs = [log for log in logs if log.action == "LOGIN_SUCCESS"]
        assert len(login_logs) > 0
        
        latest_log = login_logs[-1]
        assert latest_log.user_id == admin_user.id
        assert latest_log.action == "LOGIN_SUCCESS"
        assert latest_log.changes is not None
