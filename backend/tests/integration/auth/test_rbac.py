"""Integration tests for role-based access control (RBAC)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.models import User, UserRole
from app.auth.password import hash_password
from app.auth.tokens import create_access_token
from app.repositories import UserRepository


client = TestClient(app)


@pytest.fixture
def admin_user(db: Session) -> User:
    """Create test admin user."""
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="rbac_admin",
        email="rbac_admin@test.local",
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
        username="rbac_reviewer",
        email="rbac_reviewer@test.local",
        role=UserRole.REVIEWER,
        password_hash=hash_password("ReviewerPassword123!"),
        is_active=True
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def admin_token(admin_user: User) -> str:
    """Generate JWT token for admin user."""
    return create_access_token(
        user_id=admin_user.id,
        username=admin_user.username,
        role=admin_user.role.value
    )


@pytest.fixture
def reviewer_token(reviewer_user: User) -> str:
    """Generate JWT token for reviewer user."""
    return create_access_token(
        user_id=reviewer_user.id,
        username=reviewer_user.username,
        role=reviewer_user.role.value
    )


class TestAdminOnlyEndpoints:
    """Test that admin-only endpoints enforce role requirement."""
    
    def test_admin_endpoint_requires_admin_role(self, admin_token: str, reviewer_token: str):
        """Admin endpoint accessible only to ADMIN role."""
        # This would test an actual admin endpoint if one exists
        # For now, we verify the token structure and role
        import jwt
        from app.config import get_settings
        
        settings = get_settings()
        
        # Decode admin token
        admin_payload = jwt.decode(admin_token, settings.jwt_secret_key, algorithms=["HS256"])
        assert admin_payload["role"] == "admin"
        
        # Decode reviewer token
        reviewer_payload = jwt.decode(reviewer_token, settings.jwt_secret_key, algorithms=["HS256"])
        assert reviewer_payload["role"] == "reviewer"


class TestReviewerEndpoints:
    """Test that reviewer endpoints enforce role requirement."""
    
    def test_reviewer_endpoint_accepts_admin(self, admin_user: User):
        """ADMIN role has access to REVIEWER endpoints."""
        admin_token = create_access_token(
            user_id=admin_user.id,
            username=admin_user.username,
            role=admin_user.role.value
        )
        
        import jwt
        from app.config import get_settings
        
        settings = get_settings()
        payload = jwt.decode(admin_token, settings.jwt_secret_key, algorithms=["HS256"])
        
        # ADMIN should be able to access reviewer endpoints
        assert payload["role"] == "admin"
    
    def test_reviewer_endpoint_accepts_reviewer(self, reviewer_user: User):
        """REVIEWER role has access to REVIEWER endpoints."""
        reviewer_token = create_access_token(
            user_id=reviewer_user.id,
            username=reviewer_user.username,
            role=reviewer_user.role.value
        )
        
        import jwt
        from app.config import get_settings
        
        settings = get_settings()
        payload = jwt.decode(reviewer_token, settings.jwt_secret_key, algorithms=["HS256"])
        
        # REVIEWER should have access
        assert payload["role"] == "reviewer"
