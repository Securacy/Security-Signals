"""Permanently remove every currently-inactive (is_active=False) User row.

Safe by construction, not by convention: the only two foreign keys that
reference user.id (signal.reviewed_by, audit_log.user_id) are ON DELETE
SET NULL at the database level, and the audit_log immutability trigger
(migration 006) explicitly allows exactly that cascade. Deleting a user
therefore never destroys an audit record or a signal's content - it only
nulls out the "who" pointer on rows that referenced them. See
UserService.purge_inactive_user for the full reasoning.

Never touches an active user. Each user is purged in its own transaction
(audit entry + delete, atomic), so a failure partway through leaves
already-purged users purged and leaves the rest untouched rather than
leaving a half-applied bulk change.

Usage:
    export DATABASE_URL=postgresql://...
    python purge_inactive_users.py            # purges every inactive user
    python purge_inactive_users.py --dry-run   # lists them, changes nothing
"""
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import get_settings
from app.repositories import UserRepository
from app.services.user_service import UserService

settings = get_settings()
engine = create_engine(settings.database_url)

dry_run = "--dry-run" in sys.argv[1:]

with Session(engine) as session:
    inactive = UserRepository(session).get_inactive_users(limit=10_000)

    if not inactive:
        print("No inactive users found. Nothing to do.")
        sys.exit(0)

    print(f"Found {len(inactive)} inactive user(s):")
    for user in inactive:
        print(f"  - {user.username} <{user.email}> role={user.role.value} id={user.id}")

    if dry_run:
        print("\n--dry-run: no changes made.")
        sys.exit(0)

    print()
    purged = 0
    for user in inactive:
        with Session(engine) as tx:
            service = UserService(tx)
            try:
                result = service.purge_inactive_user(user.id, actor_id=None)
                tx.commit()
                purged += 1
                print(f"✓ purged {result['username']}")
            except ValueError as e:
                tx.rollback()
                print(f"✗ skipped {user.username}: {e}")

    print(f"\nPurged {purged} of {len(inactive)} inactive user(s).")
