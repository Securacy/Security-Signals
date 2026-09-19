"""Development/demo-only seed for two initial accounts (ADMIN and REVIEWER)
so the human-in-the-loop review workflow can be demonstrated through the
API/Swagger UI without manually provisioning accounts first.

Uses the real User model, UserService, password hashing, and RBAC role
definitions - no separate mock-user table, no plaintext password storage,
no bypass of the normal account-creation policy (password strength is
still enforced by UserService.create_user).

SAFETY:
  - Refuses outright when settings.environment == "production".
  - Never falls back to a built-in default password - both
    DEMO_ADMIN_PASSWORD and DEMO_REVIEWER_PASSWORD must be set via the
    environment, or seeding raises before touching the database.
  - Idempotent: an existing demo user (matched by username) is left
    completely untouched - password and role are never overwritten by a
    re-run.
  - Never logs, returns, or otherwise exposes the actual password value.
"""

from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import UserRole
from app.repositories import UserRepository
from app.services.user_service import UserService
from app.common.errors import UniqueConstraintError

DEMO_ADMIN_USERNAME = "admin-demo"
DEMO_ADMIN_EMAIL = "admin-demo@demo.local"
DEMO_REVIEWER_USERNAME = "reviewer-demo"
DEMO_REVIEWER_EMAIL = "reviewer-demo@demo.local"


class DemoSeedingRefused(RuntimeError):
    """Raised when demo seeding is attempted outside a development/demo
    environment. Never caught silently - the caller (CLI script or test)
    is expected to surface this clearly."""
    pass


@dataclass
class DemoUserSeedResult:
    username: str
    role: str
    created: bool  # False means "already existed, left untouched"


def seed_demo_users(session: Session, settings: Settings) -> list[DemoUserSeedResult]:
    """Create the two demo accounts (admin-demo / reviewer-demo) if they
    don't already exist. Safe to call repeatedly.

    Raises:
        DemoSeedingRefused: if settings.environment == "production".
        ValueError: if DEMO_ADMIN_PASSWORD or DEMO_REVIEWER_PASSWORD is not
            set, or if a configured password fails the account-creation
            password policy.
    """
    if settings.environment == "production":
        raise DemoSeedingRefused(
            "Demo user seeding is disabled when ENVIRONMENT=production. "
            "This mechanism exists for development/demo use only."
        )

    if settings.demo_admin_password is None:
        raise ValueError("DEMO_ADMIN_PASSWORD is not set - refusing to seed with no password")
    if settings.demo_reviewer_password is None:
        raise ValueError("DEMO_REVIEWER_PASSWORD is not set - refusing to seed with no password")

    results = []
    results.append(
        _seed_one(
            session,
            username=DEMO_ADMIN_USERNAME,
            email=DEMO_ADMIN_EMAIL,
            role=UserRole.ADMIN,
            password=settings.demo_admin_password.get_secret_value(),
        )
    )
    results.append(
        _seed_one(
            session,
            username=DEMO_REVIEWER_USERNAME,
            email=DEMO_REVIEWER_EMAIL,
            role=UserRole.REVIEWER,
            password=settings.demo_reviewer_password.get_secret_value(),
        )
    )
    return results


def _seed_one(session: Session, username: str, email: str, role: UserRole, password: str) -> DemoUserSeedResult:
    user_repo = UserRepository(session)

    existing = user_repo.get_by_username(username)
    if existing is not None:
        # Idempotent: never touch password or role on an existing demo user.
        return DemoUserSeedResult(username=username, role=existing.role.value, created=False)

    service = UserService(session)
    try:
        user = service.create_user(
            username=username,
            email=email,
            role=role,
            password=password,
            actor_id=None,  # system-seeded, not attributable to an admin
        )
        session.commit()
        return DemoUserSeedResult(username=user.username, role=user.role.value, created=True)
    except UniqueConstraintError:
        # Lost a race, or the email is already taken under a different
        # username - either way, treat as "already exists" rather than
        # failing the whole seed run.
        session.rollback()
        existing = user_repo.get_by_username(username)
        if existing is not None:
            return DemoUserSeedResult(username=username, role=existing.role.value, created=False)
        raise
