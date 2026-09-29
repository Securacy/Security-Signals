"""FastAPI dependency injection for authentication and authorization."""

from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session
from uuid import UUID
import logging

from app.db.connection import get_db
from app.auth.tokens import decode_access_token
from app.repositories import UserRepository
from app.db.models import User, UserRole
from app.common.errors import AuthenticationError

logger = logging.getLogger(__name__)


def get_authorization_header(authorization: str = Header(None)) -> str:
    """Extract Bearer token from Authorization header.
    
    Args:
        authorization: Authorization header value
    
    Returns:
        JWT token string
    
    Raises:
        HTTPException 401: If header missing or malformed
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")
    
    return parts[1]


def get_current_user(
    token: str = Depends(get_authorization_header),
    db: Session = Depends(get_db)
) -> User:
    """Validate JWT token and return current authenticated user.
    
    Args:
        token: JWT access token from Authorization header
        db: Database session
    
    Returns:
        Authenticated User object
    
    Raises:
        HTTPException 401: If token invalid or user not found
        HTTPException 403: If user inactive
    """
    try:
        payload = decode_access_token(token)
    except AuthenticationError as e:
        logger.warning(f"token_validation_failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    # Extract user_id from token
    user_id_str = payload.get("sub")
    if not user_id_str:
        logger.warning("token_missing_user_id")
        raise HTTPException(status_code=401, detail="Invalid token: missing user ID")
    
    try:
        user_id = UUID(user_id_str)
    except (ValueError, TypeError):
        logger.warning(f"token_invalid_user_id: {user_id_str}")
        raise HTTPException(status_code=401, detail="Invalid token: malformed user ID")
    
    # Lookup user
    try:
        user_repo = UserRepository(db)
        user = user_repo.get_by_id(user_id)
    except Exception as e:
        logger.error(f"user_lookup_failed: {type(e).__name__}")
        raise HTTPException(status_code=401, detail="User lookup failed")
    
    if not user:
        logger.warning(f"user_not_found: {user_id}")
        raise HTTPException(status_code=401, detail="User not found")
    
    if not user.is_active:
        logger.warning(f"user_inactive: {user.username}")
        raise HTTPException(status_code=403, detail="User account is inactive")

    # Session invalidation on password change: a token issued before the
    # user's password was last changed carries a stale (or absent, for
    # tokens issued before this check existed) pwd_ver and is rejected here
    # - see create_access_token for how pwd_ver is derived.
    current_pwd_ver = int(user.password_changed_at.timestamp()) if user.password_changed_at else 0
    if payload.get("pwd_ver", 0) != current_pwd_ver:
        logger.warning(f"token_stale_password_version: {user.username}")
        raise HTTPException(status_code=401, detail="Session expired due to a password change. Please sign in again.")

    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to enforce ADMIN role.
    
    Args:
        current_user: Authenticated user from get_current_user
    
    Returns:
        User if authorized
    
    Raises:
        HTTPException 403: If user does not have ADMIN role
    """
    if current_user.role != UserRole.ADMIN:
        logger.warning(f"admin_required: user={current_user.username}, role={current_user.role.value}")
        raise HTTPException(status_code=403, detail="Admin role required")
    
    return current_user


def require_reviewer(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to enforce REVIEWER or ADMIN role.
    
    Args:
        current_user: Authenticated user from get_current_user
    
    Returns:
        User if authorized
    
    Raises:
        HTTPException 403: If user does not have REVIEWER or ADMIN role
    """
    if current_user.role not in [UserRole.REVIEWER, UserRole.ADMIN]:
        logger.warning(f"reviewer_required: user={current_user.username}, role={current_user.role.value}")
        raise HTTPException(status_code=403, detail="Reviewer role required")
    
    return current_user
