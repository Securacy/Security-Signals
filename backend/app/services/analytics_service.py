"""Analytics service: monthly signal trends, category/principle counts, and
dominant theme.

Two access tiers, matching the public/internal split in the spec:
- get_public_analytics: PUBLISHED signals only, bucketed by publish month.
  Safe to expose with no authentication - it can never reveal that a DRAFT
  or IN_REVIEW signal exists, only what has already gone through the full
  review/publish workflow and is already visible via the public signals API.
- get_internal_analytics: all signals regardless of status, bucketed by
  creation month, with a per-status breakdown. Reveals pipeline volume
  (including unpublished work), so it is exposed only behind an
  authenticated, protected route (see app/api/routes/analytics.py).
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.db.models import Signal, SignalCategory, SignalStatus

# Signal.principle has no dedicated normalized table - it is a single
# "; "-joined string of each AI-validated principle name (see
# SignalService._map_principle_and_recommended_action). Splitting on the
# same separator is the only way to count individual principles with the
# current data model; this is an approximation (a principle name containing
# "; " itself would split incorrectly) rather than a precise join, and is
# documented here rather than silently presented as exact.
_PRINCIPLE_SEPARATOR = "; "


def _month_key(dt: datetime) -> str:
    """UTC "YYYY-MM" bucket key. Requires a timezone-aware datetime (every
    Signal timestamp column is TIMESTAMP WITH TIME ZONE) so naive-datetime
    bucketing mistakes can't silently shift a signal into the wrong month."""
    if dt.tzinfo is None:
        raise ValueError("Naive datetime cannot be bucketed - timezone is required")
    return dt.astimezone(timezone.utc).strftime("%Y-%m")


def _subtract_months(year: int, month: int, n: int) -> tuple[int, int]:
    """(year, month) shifted back n months, no external dependency needed
    for such simple calendar arithmetic (1-indexed months: Jan=1, Dec=12)."""
    zero_indexed = (month - 1) - n
    return year + zero_indexed // 12, zero_indexed % 12 + 1


def _month_range(months: int, now: Optional[datetime] = None) -> list[str]:
    """The last `months` UTC "YYYY-MM" keys, oldest first, including the
    current month. Ensures months with zero signals still appear in the
    output instead of being silently absent."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    keys = []
    for i in range(months - 1, -1, -1):
        y, m = _subtract_months(now.year, now.month, i)
        keys.append(f"{y:04d}-{m:02d}")
    return keys


def _dominant_theme(category_counts: dict) -> Optional[dict]:
    """The single most common category in the window. Ties are broken by
    category name for deterministic output."""
    if not category_counts:
        return None
    category, count = min(category_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return {"category": category, "count": count}


class AnalyticsService:
    """Computes signal analytics directly from Signal/SignalCategory - no
    separate analytics table or precomputation; correct for this dataset's
    current scale and always consistent with live signal state."""

    def __init__(self, session: Session):
        self.session = session

    def get_public_analytics(self, months: int = 12) -> dict:
        """Analytics over PUBLISHED signals only, bucketed by publish month.
        Never includes DRAFT/IN_REVIEW/APPROVED/REJECTED signals or any
        count derived from them."""
        month_keys = _month_range(months)
        earliest = datetime.strptime(month_keys[0], "%Y-%m").replace(tzinfo=timezone.utc)

        signals = (
            self.session.query(Signal)
            .filter(Signal.status == SignalStatus.PUBLISHED)
            .filter(Signal.published_at.isnot(None))
            .filter(Signal.published_at >= earliest)
            .all()
        )

        monthly_counts = {k: 0 for k in month_keys}
        category_counts: dict = defaultdict(int)
        principle_counts: dict = defaultdict(int)

        signal_ids = [s.id for s in signals]
        categories_by_signal: dict = defaultdict(list)
        if signal_ids:
            for cat in (
                self.session.query(SignalCategory)
                .filter(SignalCategory.signal_id.in_(signal_ids))
                .all()
            ):
                categories_by_signal[cat.signal_id].append(cat.category)

        for signal in signals:
            key = _month_key(signal.published_at)
            if key in monthly_counts:
                monthly_counts[key] += 1

            for category in categories_by_signal.get(signal.id, []):
                value = category.value if hasattr(category, "value") else category
                category_counts[value] += 1

            for principle in _split_principles(signal.principle):
                principle_counts[principle] += 1

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "window_months": months,
            "total_published": len(signals),
            "monthly_counts": [{"month": k, "count": monthly_counts[k]} for k in month_keys],
            "category_counts": dict(category_counts),
            "principle_counts": dict(principle_counts),
            "dominant_theme": _dominant_theme(category_counts),
        }

    def get_internal_analytics(self, months: int = 12) -> dict:
        """Analytics over ALL signals regardless of status, bucketed by
        creation month, with a per-status breakdown. Protected endpoint
        only - reveals unpublished pipeline volume."""
        month_keys = _month_range(months)
        earliest = datetime.strptime(month_keys[0], "%Y-%m").replace(tzinfo=timezone.utc)

        signals = (
            self.session.query(Signal)
            .filter(Signal.created_at >= earliest)
            .all()
        )

        monthly_counts = {k: 0 for k in month_keys}
        monthly_counts_by_status = {k: defaultdict(int) for k in month_keys}
        status_totals: dict = defaultdict(int)

        for signal in signals:
            key = _month_key(signal.created_at)
            status_value = signal.status.value if hasattr(signal.status, "value") else signal.status
            status_totals[status_value] += 1
            if key in monthly_counts:
                monthly_counts[key] += 1
                monthly_counts_by_status[key][status_value] += 1

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "window_months": months,
            "total_signals": len(signals),
            "status_totals": dict(status_totals),
            "monthly_counts": [{"month": k, "count": monthly_counts[k]} for k in month_keys],
            "monthly_counts_by_status": {
                k: dict(v) for k, v in monthly_counts_by_status.items()
            },
        }


def _split_principles(principle_field: str) -> list[str]:
    """Split Signal.principle's "; "-joined string back into individual
    principle names. See module docstring for why this is an
    approximation, not an exact join, given the current data model."""
    if not principle_field:
        return []
    return [p.strip() for p in principle_field.split(_PRINCIPLE_SEPARATOR) if p.strip()]
