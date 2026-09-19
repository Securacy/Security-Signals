"""Category coverage/health derivation (Feature 2).

Answers "is every advertised category currently being maintained?" purely
by reading real, already-persisted state (Source failure-tracking config,
Article/Signal/SignalCategory rows) - never fabricates or infers data that
isn't actually there. A category with no real current signal is reported
as such (has_current_coverage=False), not hidden or backfilled.

Source-to-category mapping comes from VERIFIED_FEEDS['categories'] (see
app/ingestion/sources.py) - the same real, verified sources the ingestion
pipeline actually uses, not a separate/duplicated list.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.db.models import (
    Article, Signal, SignalCategory, SignalStatus, SecurityCategoryType, Source,
)
from app.ingestion.sources import VERIFIED_FEEDS
from app.ingestion.sources import SourceRegistry

# Purely informational threshold for flagging a category's current coverage
# as stale in the health report - does NOT trigger any deletion or
# retirement by itself (see SignalService._retire_superseded_current_signals
# for the only mechanism that ever changes is_current, and that only runs
# as a side effect of a NEW signal being published).
STALE_AFTER_DAYS = 30


class CoverageStatus(str, Enum):
    """Answers "are the dedicated sources for this category actually
    producing usable security information?" - never "does a source row
    exist?" Every value here is derived purely from real, already-persisted
    Source/Signal/Article state (see _compute_coverage_status) - nothing
    here is inferred, guessed, or fabricated.

    Checked in this priority order (first match wins):
      SOURCE_FAILURE     - every dedicated source for this category is
                            currently disabled or hasn't been synced yet -
                            the most operationally urgent state, reported
                            regardless of whether old coverage still exists.
      STALE              - a current signal exists but has aged past
                            STALE_AFTER_DAYS.
      NEW_CONTENT         - a real article has arrived (from one of this
                            category's dedicated sources) more recently
                            than the current signal was published (or no
                            current signal exists at all) - genuinely new
                            raw material is available, whether or not it
                            has produced a new signal yet.
      UNCHANGED          - current coverage exists, isn't stale, and no
                            newer article has arrived since it was
                            published - a stable, unremarkable steady state.
      NO_QUALIFYING_EVENT - no current coverage, and no new article has
                            arrived either - sources are presumably fine,
                            nothing has qualified into a signal.
      HEALTHY            - fallback for any other combination (should not
                            normally be reached given the above).
    """
    SOURCE_FAILURE = "source_failure"
    STALE = "stale"
    NEW_CONTENT = "new_content"
    UNCHANGED = "unchanged"
    NO_QUALIFYING_EVENT = "no_qualifying_event"
    HEALTHY = "healthy"


@dataclass
class SourceHealth:
    name: str
    tier: int
    enabled: bool
    consecutive_failures: int
    last_success: Optional[str]
    last_failure: Optional[str]


@dataclass
class CategoryHealth:
    category: str
    primary_sources: List[str]
    secondary_sources: List[str]
    source_health: List[SourceHealth] = field(default_factory=list)
    has_current_coverage: bool = False
    current_signal_count: int = 0
    last_current_signal_at: Optional[str] = None
    coverage_age_days: Optional[float] = None
    is_stale: bool = False
    last_new_article_at: Optional[str] = None
    coverage_status: str = CoverageStatus.NO_QUALIFYING_EVENT.value


def _compute_coverage_status(
    *,
    source_health: List[SourceHealth],
    has_current_coverage: bool,
    is_stale: bool,
    last_current_signal_at: Optional[datetime],
    last_new_article_at: Optional[datetime],
) -> CoverageStatus:
    """Pure function over already-computed real fields - see
    CoverageStatus's docstring for the exact priority order and meaning of
    each state."""
    if not source_health or all(not s.enabled for s in source_health):
        return CoverageStatus.SOURCE_FAILURE

    if has_current_coverage and is_stale:
        return CoverageStatus.STALE

    has_newer_article = last_new_article_at is not None and (
        last_current_signal_at is None or last_new_article_at > last_current_signal_at
    )
    if has_newer_article:
        return CoverageStatus.NEW_CONTENT

    if has_current_coverage:
        return CoverageStatus.UNCHANGED

    return CoverageStatus.NO_QUALIFYING_EVENT


def _category_to_source_feeds() -> Dict[str, List[dict]]:
    mapping: Dict[str, List[dict]] = {}
    for feed in VERIFIED_FEEDS:
        for category in feed.get('categories', []):
            mapping.setdefault(category, []).append(feed)
    return mapping


def compute_category_health(session: Session) -> List[CategoryHealth]:
    """Compute a CategoryHealth entry for every advertised
    SecurityCategoryType value, in canonical enum order."""
    now = datetime.now(timezone.utc)
    category_to_feeds = _category_to_source_feeds()

    registry = SourceRegistry(session)
    sources_by_name = {s.name: s for s in session.query(Source).all()}

    results = []
    for category in SecurityCategoryType:
        cat_value = category.value
        feeds = category_to_feeds.get(cat_value, [])
        primary = [f['name'] for f in feeds if f.get('tier', 1) == 1]
        secondary = [f['name'] for f in feeds if f.get('tier', 1) != 1]

        source_health = []
        source_ids_for_category = []
        for feed in feeds:
            src = sources_by_name.get(feed['name'])
            if not src:
                continue
            source_ids_for_category.append(src.id)
            cfg = registry.get_config(src)
            source_health.append(SourceHealth(
                name=feed['name'],
                tier=feed.get('tier', 1),
                enabled=cfg.enabled,
                consecutive_failures=cfg.consecutive_failures,
                last_success=cfg.last_success.isoformat() if cfg.last_success else None,
                last_failure=cfg.last_failure.isoformat() if cfg.last_failure else None,
            ))

        current_signals = (
            session.query(Signal)
            .join(SignalCategory, SignalCategory.signal_id == Signal.id)
            .filter(
                SignalCategory.category == category,
                Signal.status == SignalStatus.PUBLISHED,
                Signal.is_current.is_(True),
            )
            .order_by(Signal.published_at.desc())
            .all()
        )
        last_current = current_signals[0] if current_signals else None
        age_days = None
        is_stale = False
        if last_current and last_current.published_at:
            age_days = (now - last_current.published_at).total_seconds() / 86400.0
            is_stale = age_days > STALE_AFTER_DAYS

        last_article = None
        if source_ids_for_category:
            last_article = (
                session.query(Article)
                .filter(Article.source_id.in_(source_ids_for_category))
                .order_by(Article.created_at.desc())
                .first()
            )

        has_current_coverage = len(current_signals) > 0
        coverage_status = _compute_coverage_status(
            source_health=source_health,
            has_current_coverage=has_current_coverage,
            is_stale=is_stale,
            last_current_signal_at=last_current.published_at if last_current else None,
            last_new_article_at=last_article.created_at if last_article else None,
        )

        results.append(CategoryHealth(
            category=cat_value,
            primary_sources=primary,
            secondary_sources=secondary,
            source_health=source_health,
            has_current_coverage=has_current_coverage,
            current_signal_count=len(current_signals),
            last_current_signal_at=last_current.published_at.isoformat() if last_current and last_current.published_at else None,
            coverage_age_days=round(age_days, 1) if age_days is not None else None,
            is_stale=is_stale,
            last_new_article_at=last_article.created_at.isoformat() if last_article and last_article.created_at else None,
            coverage_status=coverage_status.value,
        ))
    return results
