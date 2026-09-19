"""Seed the two development/demo accounts (admin-demo, reviewer-demo).

Usage:
    export DATABASE_URL=postgresql://...
    export DEMO_ADMIN_PASSWORD='...'      # must meet the account password policy
    export DEMO_REVIEWER_PASSWORD='...'   # must meet the account password policy
    python seed_demo_users.py

Refuses to run when ENVIRONMENT=production. Safe to run repeatedly - an
existing demo user's password and role are never overwritten.
"""
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import get_settings
from app.services.demo_seed_service import seed_demo_users, DemoSeedingRefused

settings = get_settings()
engine = create_engine(settings.database_url)
session = Session(engine)

try:
    results = seed_demo_users(session, settings)
except DemoSeedingRefused as e:
    print(f"REFUSED: {e}")
    sys.exit(1)
except ValueError as e:
    print(f"ERROR: {e}")
    sys.exit(1)
finally:
    session.close()

for result in results:
    status = "created" if result.created else "already existed (unchanged)"
    print(f"✓ {result.username} ({result.role}): {status}")
