"""Permanently remove old DRAFT signals - development/QA data-reset tooling.

Clears the Draft page's backlog so it can be repopulated by a fresh
ingestion run, without touching anything in IN_REVIEW/APPROVED/REJECTED/
PUBLISHED, without touching users or audit history, and without touching
any SecurityEvent/Article row (those can be shared by other signals/
events and are never deleted here - see SignalService.purge_draft_signal's
docstring for the full cascade/safety reasoning).

Safe by construction: SignalCategory, Evidence, and SignalVisual are all
exclusively owned by their one Signal (DB-level ON DELETE CASCADE AND the
ORM's own cascade="all, delete-orphan"), so deleting a DRAFT signal removes
exactly those three rows and nothing else. audit_log is append-only at the
DB level (migration 006's trigger blocks DELETE unconditionally) - this
script only ever ADDS a new SIGNAL_DRAFT_PURGED entry per signal, with a
snapshot of what was removed, exactly like the existing USER_PURGED
pattern in purge_inactive_users.py / UserService.purge_inactive_user.

Two signals are always preserved regardless of status/age (see the PR/task
that asked for this script for why - one is a known-good OAuth signal with
a real generated visual, used as a visual-pipeline regression check; the
other was the originally-given ID, kept out of caution in case it matters
for a reason not stated here):
  - 28722993-b57a-4909-8536-a53960ee892c
  - 65294270-b3bf-40a0-9b1d-1a16e7f94e53

Usage:
    export DATABASE_URL=postgresql://...
    python purge_old_draft_signals.py            # dry run (default) - lists what would be removed, changes nothing
    python purge_old_draft_signals.py --confirm   # actually deletes
"""
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import Signal, SignalStatus
from app.services.signal_service import SignalService

PRESERVED_IDS = {
    "28722993-b57a-4909-8536-a53960ee892c",
    "65294270-b3bf-40a0-9b1d-1a16e7f94e53",
}

settings = get_settings()
engine = create_engine(settings.database_url)

confirm = "--confirm" in sys.argv[1:]

with Session(engine) as session:
    drafts = (
        session.query(Signal)
        .filter(Signal.status == SignalStatus.DRAFT)
        .order_by(Signal.created_at)
        .all()
    )
    preserved_found = [s for s in drafts if str(s.id) in PRESERVED_IDS]
    candidates = [s for s in drafts if str(s.id) not in PRESERVED_IDS]

    print(f"Found {len(drafts)} total DRAFT signal(s).\n")

    print(f"Preserving {len(preserved_found)} (never touched by this script):")
    for s in preserved_found:
        vis = s.visual
        print(f"  [KEEP] {s.id} | {s.created_at} | visual={vis.status.value if vis else 'none'} | {s.title}")
    for missing_id in PRESERVED_IDS - {str(s.id) for s in preserved_found}:
        print(f"  [KEEP] {missing_id} | NOT FOUND in database - nothing to preserve or delete for this id")
    print()

    print(f"{len(candidates)} DRAFT signal(s) would be removed:")
    total_cats = total_ev = total_vis = 0
    for s in candidates:
        cat_n = len(s.categories)
        ev_n = len(s.evidence)
        vis = s.visual
        total_cats += cat_n
        total_ev += ev_n
        total_vis += 1 if vis else 0
        print(f"  - {s.id} | {s.created_at} | cats={cat_n} evidence={ev_n} visual={vis.status.value if vis else 'none'} | {s.title}")

    print()
    print(
        f"Dependent rows that would cascade-delete: "
        f"{total_cats} SignalCategory, {total_ev} Evidence, {total_vis} SignalVisual."
    )
    print("SecurityEvent, Article, User, and AuditLog rows are never deleted or modified by this script.")
    print(f"Each deletion adds one new SIGNAL_DRAFT_PURGED audit entry ({len(candidates)} total if confirmed).")

    if not candidates:
        print("\nNothing to do.")
        sys.exit(0)

    if not confirm:
        print("\nDry run only - no changes made. Re-run with --confirm to actually delete.")
        sys.exit(0)

    print()
    purged = 0
    for s in candidates:
        with Session(engine) as tx:
            service = SignalService(tx)
            try:
                result = service.purge_draft_signal(s.id, actor_id=None)
                tx.commit()
                purged += 1
                print(f"✓ purged {result['title']} ({s.id})")
            except ValueError as e:
                tx.rollback()
                print(f"✗ skipped {s.id}: {e}")

    print(f"\nPurged {purged} of {len(candidates)} DRAFT signal(s).")
