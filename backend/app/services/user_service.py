"""User management service layer - admin-driven user account lifecycle.

Mirrors the audit pattern already established in SignalService: every
mutation writes an AuditLog entry in the same transaction as the state
change, and a failure to write that entry fails the whole operation rather
than being silently dropped.
"""
from datetime import datetime, timezone
from typing import Optional, List
from uuid import UUID
import logging

from sqlalchemy.orm import Session

from app.db.models import User, UserRole
from app.repositories import UserRepository, AuditLogRepository
from app.auth.password import hash_password, verify_password, validate_password_strength
from app.common.errors import AuthenticationError, DatabaseError, NotFoundError, ValidationError

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
        validate_password_strength(password, username=username, email=email)
        password_hash = hash_password(password)

        user = self.user_repo.create(
            username=username,
            email=email,
            role=role,
            password_hash=password_hash,
            is_active=True,
            password_changed_at=datetime.now(timezone.utc),
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

    def change_own_password(
        self, user_id: UUID, current_password: str, new_password: str, confirm_password: str,
    ) -> User:
        """
        Self-service password change: the acting user changes their own
        password. Requires the correct current password.

        Setting password_changed_at invalidates every access token issued
        before this moment on its next use (see app/auth/tokens.py and
        app/api/dependencies.py) - a real, if coarse, session invalidation.

        Raises:
            NotFoundError: If user_id doesn't exist.
            ValidationError: If the account has no local password to change
                (Entra-only) - never treat an Entra identity as a local one.
            AuthenticationError: If current_password is wrong. Message is
                deliberately generic (never "no such account" vs "wrong
                password") - this endpoint is only reachable already
                authenticated as user_id, so there's no username-enumeration
                surface here, but the message still gives no extra detail.
            ValueError: If confirm_password doesn't match new_password, or
                new_password fails the password policy.
        """
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError(f"User {user_id} not found")

        if user.password_hash is None:
            raise ValidationError(
                "This account signs in with Microsoft Entra ID and has no local password to change."
            )

        if new_password != confirm_password:
            raise ValueError("New password and confirmation do not match")

        if not verify_password(current_password, user.password_hash):
            raise AuthenticationError("Current password is incorrect")

        validate_password_strength(new_password, username=user.username, email=user.email)

        now = datetime.now(timezone.utc)
        updated = self.user_repo.update(
            user_id, password_hash=hash_password(new_password), password_changed_at=now,
        )

        self._audit_user_action(
            user_id=user_id,
            action="PASSWORD_CHANGED",
            actor_id=user_id,
            changes={"self_service": True},
        )
        self.session.flush()
        logger.info(f"Password changed (self-service) for user {user_id}")
        return updated

    def admin_reset_password(self, user_id: UUID, actor_id: UUID, new_password: str) -> User:
        """
        ADMIN sets a new (temporary) password for another local/password
        user. The admin never sees or chooses to view the existing
        password - this only ever sets a fresh one.

        Raises:
            NotFoundError: If user_id doesn't exist.
            ValidationError: If the account is Entra-only (no local password
                to reset) - an admin can never manage an Entra identity's
                credential as if it were a local password.
            ValueError: If new_password fails the password policy.
        """
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError(f"User {user_id} not found")

        if user.password_hash is None:
            raise ValidationError(
                "This account is managed by Microsoft Entra ID and has no local password to reset."
            )

        validate_password_strength(new_password, username=user.username, email=user.email)

        now = datetime.now(timezone.utc)
        updated = self.user_repo.update(
            user_id, password_hash=hash_password(new_password), password_changed_at=now,
        )

        self._audit_user_action(
            user_id=user_id,
            action="PASSWORD_RESET_BY_ADMIN",
            actor_id=actor_id,
            changes={"reset_by_admin": True},
        )
        self.session.flush()
        logger.info(f"Password reset by admin {actor_id} for user {user_id}")
        return updated

    def purge_inactive_user(self, user_id: UUID, actor_id: Optional[UUID]) -> dict:
        """
        Permanently remove an INACTIVE user account.

        Safe by construction: the only two foreign keys referencing user.id
        (signal.reviewed_by, audit_log.user_id) are ON DELETE SET NULL at
        the database level, and the audit_log immutability trigger
        explicitly allows exactly that cascade - so this can never destroy
        an audit record or a signal's content, only null out the "who"
        pointer on rows that referenced this user. The audit entry for the
        purge itself is written FIRST, with a snapshot of the user's
        identity in `changes`, so there's a human-readable record of who
        was removed even after their row is gone.

        Raises:
            NotFoundError: If user_id doesn't exist.
            ValueError: If the user is still active - only is_active=False
                accounts may ever be permanently removed by this method.
        """
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundError(f"User {user_id} not found")

        if user.is_active:
            raise ValueError("Only inactive users may be permanently removed")

        snapshot = {
            "username": user.username,
            "email": user.email,
            "role": user.role.value if hasattr(user.role, "value") else user.role,
            "was_entra_linked": user.entra_object_id is not None,
        }

        self._audit_user_action(
            user_id=user_id,
            action="USER_PURGED",
            actor_id=actor_id,
            changes=snapshot,
        )
        self.user_repo.delete(user_id)
        self.session.flush()
        logger.info(f"Purged inactive user {user_id} ({snapshot['username']})")
        return {"id": str(user_id), **snapshot}

    def purge_all_inactive_users(self, actor_id: Optional[UUID]) -> List[dict]:
        """Purge every currently-inactive user, one at a time in this same
        transaction. Never touches an active user - get_inactive_users only
        ever returns is_active=False rows."""
        purged = []
        for user in self.user_repo.get_inactive_users(limit=10_000):
            purged.append(self.purge_inactive_user(user.id, actor_id))
        return purged
