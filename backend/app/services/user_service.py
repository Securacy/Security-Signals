"""User management service layer - admin-driven user account lifecycle.

Mirrors the audit pattern already established in SignalService: every
mutation writes an AuditLog entry in the same transaction as the state
change, and a failure to write that entry fails the whole operation rather
than being silently dropped.
"""
from typing import Optional, List
from uuid import UUID
import logging

from sqlalchemy.orm import Session

from app.db.models import User, UserRole
from app.repositories import UserRepository, AuditLogRepository
from app.auth.password import hash_password, validate_password_strength
from app.common.errors import NotFoundError, DatabaseError

logger = logging.getLogger(__name__)


class UserService:
    """Service for admin-driven user account management."""

    def __init__(self, session: Session):
        self.session = session
        self.user_repo = UserRepository(session)
        self.audit_repo = AuditLogRepository(session)

    def _audit_user_action(
        self,
        user_id: UUID,
        action: str,
        actor_id: Optional[UUID],
        changes: dict,
    ) -> None:
        """
        Create an audit log entry for a user management action.

        Created in the same transaction as the user state change. If audit
        creation fails, the exception propagates so the caller's transaction
        rolls back - state changes and their audit trail must stay atomic.
        """
        try:
            self.audit_repo.create(
                user_id=actor_id,
                action=action,
                resource_type="USER",
                resource_id=user_id,
                changes=changes,
            )
            self.session.flush()
        except Exception as e:
            logger.error(f"Failed to create audit entry for {action}: {e}")
            raise DatabaseError(f"Failed to create audit log for {action}: {e}")

    def create_user(
        self,
        username: str,
        email: str,
        role: UserRole,
        password: str,
        actor_id: Optional[UUID],
    ) -> User:
        """
        Create a new user account.

        The plaintext password is hashed before storage and never audited.

        Raises:
            ValueError: If the password fails policy (length, complexity,
                whitespace, or matches the username).
            UniqueConstraintError: If username or email already exists.
            DatabaseError: If the database operation fails.
        """
        validate_password_strength(password, username=username)
        password_hash = hash_password(password)

        user = self.user_repo.create(
            username=username,
            email=email,
            role=role,
            password_hash=password_hash,
            is_active=True,
        )

        role_value = role.value if hasattr(role, "value") else role
        self._audit_user_action(
            user_id=user.id,
            action="USER_CREATED",
            actor_id=actor_id,
            changes={"username": username, "email": email, "role": role_value},
        )
        self.session.flush()
        logger.info(f"Created user {user.username} with role {role_value}")
        return user

    def list_users(self, skip: int = 0, limit: int = 50) -> List[User]:
        """List users, paginated."""
        return self.user_repo.get_all(skip=skip, limit=limit)

    def get_user(self, user_id: UUID) -> Optional[User]:
        """Get a single user by ID."""
        return self.user_repo.get_by_id(user_id)

    def update_user(
        self,
        user_id: UUID,
        actor_id: Optional[UUID],
        email: Optional[str] = None,
        role: Optional[UserRole] = None,
    ) -> User:
        """
        Update identity/role fields on an existing user.

        Active-state transitions are handled by deactivate_user, not here,
        so lifecycle changes always get their dedicated guardrails and a
        distinct audit action (mirrors Signal: field edits vs status
        transitions are different operations).

        Raises:
            NotFoundError: If user_id doesn't exist.
            UniqueConstraintError: If the new email is already taken.
        """
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError(f"User {user_id} not found")

        changes = {}
        updates = {}

        if email is not None and email != user.email:
            changes["email"] = {"from": user.email, "to": email}
            updates["email"] = email

        if role is not None and role != user.role:
            old_role = user.role.value if hasattr(user.role, "value") else user.role
            new_role = role.value if hasattr(role, "value") else role
            changes["role"] = {"from": old_role, "to": new_role}
            updates["role"] = role

        if not updates:
            return user

        updated = self.user_repo.update(user_id, **updates)

        self._audit_user_action(
            user_id=user_id,
            action="USER_UPDATED",
            actor_id=actor_id,
            changes=changes,
        )
        self.session.flush()
        logger.info(f"Updated user {user_id}: {list(changes.keys())}")
        return updated

    def deactivate_user(self, user_id: UUID, actor_id: UUID) -> User:
        """
        Soft-deactivate a user account (is_active=False). Never hard-deletes.

        Raises:
            NotFoundError: If user_id doesn't exist.
            ValueError: If the user is already inactive, or is the acting
                admin's own account (self-lockout prevention).
        """
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError(f"User {user_id} not found")

        if user_id == actor_id:
            raise ValueError("Cannot deactivate your own account")

        if not user.is_active:
            raise ValueError(f"User {user_id} is already inactive")

        updated = self.user_repo.update(user_id, is_active=False)

        self._audit_user_action(
            user_id=user_id,
            action="USER_DEACTIVATED",
            actor_id=actor_id,
            changes={"is_active": {"from": True, "to": False}},
        )
        self.session.flush()
        logger.info(f"Deactivated user {user_id}")
        return updated
