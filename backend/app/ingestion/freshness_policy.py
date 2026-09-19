"""Centralized freshness policy.

Freshness (is this entry actually new since we last checked) and the fetch
limit (how many entries one adapter call returns, e.g. 30) are different
concepts (see IngestionOrchestrator) - this module owns the freshness side
so the grace window and current-feed retention size live in exactly one
place (app/config.py) instead of being copied as magic numbers wherever
they're used.

Source-aware, not wall-clock-aware: freshness is judged against each
source's OWN last successful checkpoint (Source.last_ingested_at), never
against a single global "now - N days" cutoff - a source that is currently
down keeps its last checkpoint untouched, so it resumes exactly where it
left off once it recovers, and a healthy source's cadence never penalizes a
separate, slower-moving source.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional


@dataclass(frozen=True)
class FreshnessPolicy:
    """Snapshot of the configured freshness/current-feed policy. Built from
    Settings once per use rather than read as scattered `settings.x`
    lookups, so call sites take one object instead of the whole Settings."""
    grace_period: timedelta
    max_current_signals_per_category: int

    @classmethod
    def from_settings(cls, settings) -> "FreshnessPolicy":
        return cls(
            grace_period=timedelta(hours=settings.freshness_grace_hours),
            max_current_signals_per_category=settings.max_current_signals_per_category,
        )


def compute_freshness_cutoff(
    checkpoint: Optional[datetime], policy: FreshnessPolicy
) -> Optional[datetime]:
    """The timestamp below which an entry is considered stale (not new)
    for a source, or None if the source has no checkpoint yet (first-ever
    run - nothing to compare against, so nothing is filtered).

    Subtracting the grace period absorbs:
      - clock differences between this client and the source
      - delayed RSS publication (an entry whose <pubDate> lags when it was
        actually made available)
      - jitter around the exact moment the previous run's checkpoint was
        recorded
    """
    if checkpoint is None:
        return None
    return checkpoint - policy.grace_period


def is_stale_entry(published: Optional[datetime], cutoff: Optional[datetime]) -> bool:
    """Whether an entry counts as stale (not new) against a freshness
    cutoff.

    An entry with no publication timestamp (missing or - already handled
    upstream in the adapters - unparseable) can never be judged stale by
    time alone; it is conservatively treated as not-stale here (still
    processed) rather than either assumed-fresh or discarded, and
    deduplication is what actually prevents the same old item from being
    reprocessed as if new on every run.
    """
    if cutoff is None or published is None:
        return False
    return published < cutoff
