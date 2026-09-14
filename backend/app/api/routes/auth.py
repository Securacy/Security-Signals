"""
FastAPI authentication routes.

Phase 6: Login endpoint for JWT token generation.
- Accept username and password
- Validate credentials
- Return JWT access token
- Log authentication events for audit
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
import logging

from app.config import get_settings
from app.db.connection import get_db
from app.auth.password import verify_password
from app.auth.tokens import create_access_token
from app.api.rate_limit import limiter
from app.repositories import UserRepository, AuditLogRepository
from app.common.errors import AuthenticationError, DatabaseError
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    """Login request schema."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response schema."""
    access_token: str
    token_type: str = "bearer"
    user: dict


@router.post("/login", response_model=LoginResponse)
@limiter.limit(settings.login_rate_limit)
def login(
    request: Request,
    credentials: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticate user and issue JWT access token.

    SECURITY:
    - Password verified against bcrypt hash
    - Token expires after configured hours
    - Failed attempts logged for audit
    - Successful login logged for audit
    - Rate limited per client to slow brute-force password guessing

    Args:
        request: Starlette request (required by the rate limiter)
        credentials: Login credentials (username, password)
        db: Database session

    Returns:
        JWT access token and user info

    Raises:
        HTTPException 401: If credentials invalid
        HTTPException 500: If server error during authentication
    """
    try:
        # Validate input
        if not credentials.username or not credentials.password:
            logger.warning("login_failed: empty_credentials")
            raise HTTPException(status_code=401, detail="Invalid username or password")

        # Lookup user
        try:
            user_repo = UserRepository(db)
            user = user_repo.get_by_username(credentials.username)
        except DatabaseError as e:
            logger.error(f"login_db_error: {str(e)}")
            raise HTTPException(status_code=500, detail="Database error during login")

        if not user:
            logger.warning(f"login_failed: user_not_found username={credentials.username}")
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if not user.is_active:
            logger.warning(f"login_failed: user_inactive username={credentials.username}")
            raise HTTPException(status_code=403, detail="Account is inactive")

        # Verify password (never log plaintext password)
        if not verify_password(credentials.password, user.password_hash):
            logger.warning(f"login_failed: invalid_password username={credentials.username}")
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        # Create JWT token
        try:
            token = create_access_token(
                user_id=user.id,
                username=user.username,
                role=user.role.value
            )
        except Exception as e:
            logger.error(f"token_creation_failed: {type(e).__name__}")
            raise HTTPException(status_code=500, detail="Failed to create token")
        
        # Update last login timestamp and write the audit entry in the same
        # transaction as the rest of the login. A failure here must not be
        # silently swallowed - it means the auditable record of this login
        # did not land, so the request should fail rather than report success.
        user_repo.update(user.id, last_login_at=datetime.now(timezone.utc))

        audit_repo = AuditLogRepository(db)
        audit_repo.create(
            user_id=user.id,
            action="LOGIN_SUCCESS",
            resource_type="user",
            resource_id=user.id,
            changes={"username": user.username, "role": user.role.value}
        )

        logger.info(f"login_success: username={user.username}, role={user.role.value}")
        
        return LoginResponse(
            access_token=token,
            token_type="bearer",
            user={
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
                "is_active": user.is_active
            }
        )
    
    except HTTPException:
        raise
    except AuthenticationError as e:
        logger.warning(f"auth_error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    except Exception as e:
        logger.error(f"login_unexpected_error: {type(e).__name__} - {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication failed")
