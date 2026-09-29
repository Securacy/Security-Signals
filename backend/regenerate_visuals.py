"""Explicitly regenerate stale SignalVisual rows (prompt_version older
than the current PROMPT_VERSION - e.g. v1 rows generated before signal-
specific visual concepts existed) using the current prompt architecture.

Usage:
    export DATABASE_URL=postgresql://...
    python regenerate_visuals.py [--limit N]

Never runs automatically (no scheduler job, no publish-time trigger, no
page-view trigger) - this is a deliberate, human-invoked, one-time
migration pass. Safe to run repeatedly: it reuses the existing
SignalVisual row per signal (never creates a duplicate - the DB's unique
constraint on signal_id would reject one anyway), and a row is only
updated when regeneration actually succeeds. A row whose regeneration
attempt fails is left completely untouched, so a working-but-generic old
image is never replaced with nothing.
"""
import argparse
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import get_settings
from app.intelligence.visual_service import ThreatVisualService, regenerate_stale_visuals

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--limit", type=int, default=None, help="Regenerate at most N stale rows this run.")
args = parser.parse_args()

settings = get_settings()
engine = create_engine(settings.database_url)
session = Session(engine)

try:
    service = ThreatVisualService.from_settings(settings)
    summary = regenerate_stale_visuals(session, service, limit=args.limit)
finally:
    session.close()

print(f"Considered:  {summary.considered}")
print(f"Regenerated: {summary.regenerated}")
print(f"Unchanged (attempt failed, left as-is): {summary.unchanged}")
print(f"Signal missing (visual row orphaned):    {summary.signal_missing}")

if summary.unchanged > 0:
    print(
        "\nSome rows could not be regenerated this run (see logs for the "
        "specific provider/concept error per signal_id) - they remain "
        "exactly as they were and can be retried by running this script "
        "again.",
        file=sys.stderr,
    )
