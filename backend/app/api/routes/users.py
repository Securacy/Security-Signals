"""Admin-only user management API routes.

Phase 6: User account lifecycle for authenticated administrators.
Routes are thin wrappers around UserService; all business logic and
transactional audit logging live in the service layer.
"""

import re
import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.db.connection import get_db
from app.db.models import User, UserRole
from app.api.dependencies import require_admin
from app.services.user_service import UserService
from app.common.errors import NotFoundError, UniqueConstraintError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/users", tags=["users"])

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class UserCreateRequest(BaseModel):
    """Request body for creating a user. Password is plaintext in transit
    over HTTPS and hashed server-side before storage - never accepted
    pre-hashed."""
    username: str
    email: str
    role: UserRole
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not _USERNAME_RE.match(v):
            raise ValueError(
                "username must be 3-64 characters: letters, digits, '.', '_', '-'"
            )
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("invalid email format")
        return v


class UserUpdateRequest(BaseModel):
    """Request body for updating a user's identity/role fields.

    Active-state changes go through the dedicated /deactivate endpoint, not
    this one.
    """
    email: Optional[str] = None
    role: Optional[UserRole] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _EMAIL_RE.match(v):
            raise ValueError("invalid email format")
        return v


def _serialize_user(user: User) -> dict:
    """Serialize a User for API responses. Never includes password_hash."""
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def _parse_user_id(user_id: str) -> UUID:
    try:
        return UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format")


@router.post("", response_model=dict, status_code=201)
def create_user(
    body: UserCreateRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Create a new user account - ADMIN only."""
    service = UserService(db)
    try:
        user = service.create_user(
            username=body.username,
            email=body.email,
            role=body.role,
            password=body.password,
            actor_id=current_user.id,
        )
    except UniqueConstraintError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username or email already exists")
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    logger.info(f"user_created: actor={current_user.username}, new_user={user.username}")
    return _serialize_user(user)


@router.get("", response_model=list)
def list_users(
    skip: int = 0,
    limit: int = Query(default=50, le=200),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """List users, paginated - ADMIN only."""
    service = UserService(db)
    users = service.list_users(skip=skip, limit=limit)
    return [_serialize_user(u) for u in users]


@router.get("/{user_id}", response_model=dict)
def get_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Get a single user by ID - ADMIN only."""
    uid = _parse_user_id(user_id)
    service = UserService(db)
    user = service.get_user(uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _serialize_user(user)


@router.patch("/{user_id}", response_model=dict)
def update_user(
    user_id: str,
    body: UserUpdateRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Update a user's email and/or role - ADMIN only."""
    uid = _parse_user_id(user_id)
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    service = UserService(db)
    try:
        user = service.update_user(uid, actor_id=current_user.id, **updates)
    except NotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="User not found")
    except UniqueConstraintError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already in use")

    logger.info(f"user_updated: actor={current_user.username}, user={uid}")
    return _serialize_user(user)


@router.post("/{user_id}/deactivate", response_model=dict)
def deactivate_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Soft-deactivate a user account - ADMIN only. Never hard-deletes."""
    uid = _parse_user_id(user_id)
    service = UserService(db)
    try:
        user = service.deactivate_user(uid, actor_id=current_user.id)
    except NotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="User not found")
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    logger.info(f"user_deactivated: actor={current_user.username}, user={uid}")
    return _serialize_user(user)
