"""
FastAPI authentication routes.

Phase 6: Login endpoint for JWT token generation.
- Accept username and password
- Validate credentials
- Return JWT access token
- Log authentication events for audit
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
import logging

from app.config import get_settings
from app.db.connection import get_db
from app.auth.password import verify_password
from app.auth.session_payload import session_user_payload
from app.auth.tokens import create_access_token
from app.api.dependencies import get_current_user
from app.api.rate_limit import limiter
from app.db.models import User
from app.repositories import UserRepository, AuditLogRepository
from app.services.user_service import UserService
from app.common.errors import AuthenticationError, DatabaseError, ValidationError
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
    # Entra-only deployments switch the temporary password login off.
    if not get_settings().local_login_enabled:
        raise HTTPException(status_code=403, detail="Password sign-in is disabled")

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
                role=user.role.value,
                password_changed_at=user.password_changed_at,
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
            user=session_user_payload(user),
        )
    
    except HTTPException:
        raise
    except AuthenticationError as e:
        logger.warning(f"auth_error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    except Exception as e:
        logger.error(f"login_unexpected_error: {type(e).__name__} - {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication failed")


@router.get("/providers")
def get_auth_providers():
    """Which sign-in methods the login page should offer. Public, and
    deliberately just two booleans - no tenant, client ID, secret, or any
    other configuration detail."""
    current = get_settings()
    return {"local": current.local_login_enabled, "entra": current.entra_enabled}


@router.post("/logout", status_code=204)
def logout(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Record a sign-out in the audit log and clear any pending Entra
    cookies. Access tokens are stateless JWTs: this cannot revoke one
    (it expires on its own schedule), it makes the sign-out auditable and
    lets the client discard its copy."""
    AuditLogRepository(db).create(
        user_id=current_user.id,
        action="LOGOUT",
        resource_type="user",
        resource_id=current_user.id,
        changes={"username": current_user.username},
    )
    response = Response(status_code=204)
    for cookie_name in ("ss_entra_oauth", "ss_entra_handoff"):
        response.delete_cookie(cookie_name, path="/api/v1/auth/entra")
    response.headers["Cache-Control"] = "no-store"
    return response


class ChangePasswordRequest(BaseModel):
    """Plaintext in transit over HTTPS only, like the login request - never
    accepted or stored pre-hashed."""
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=1, max_length=128)
    confirm_password: str = Field(..., min_length=1, max_length=128)


@router.post("/change-password", status_code=204)
@limiter.limit(settings.login_rate_limit)
def change_password(
    request: Request,
    body: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Self-service password change for the currently authenticated LOCAL
    user. Requires the correct current password. Rate-limited the same as
    login, since this also verifies a password and is a plausible brute-force
    target. On success, every access token issued before this moment
    (including the one used to make this request) is invalidated - the
    client must sign in again with the new password."""
    service = UserService(db)
    try:
        service.change_own_password(
            current_user.id,
            current_password=body.current_password,
            new_password=body.new_password,
            confirm_password=body.confirm_password,
        )
    except AuthenticationError:
        db.rollback()
        logger.warning(f"password_change_failed: wrong_current_password username={current_user.username}")
        # 400, deliberately not 401: the caller IS authenticated (this
        # dependency already required a valid bearer token) - a wrong
        # current password is a request-validation failure, not a session
        # problem. The frontend treats any 401 as "session expired, sign
        # out", which would be actively wrong here.
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    except (ValueError, ValidationError) as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    logger.info(f"password_changed: username={current_user.username}")
    return Response(status_code=204)
