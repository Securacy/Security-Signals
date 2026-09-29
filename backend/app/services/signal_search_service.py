"""Natural-language search orchestration (Feature 3).

    User query
        -> (length/rate limits already enforced at the API layer)
        -> AI query understanding (optional, falls back safely)
        -> validated SearchQueryUnderstanding (strict Pydantic schema)
        -> application builds a bounded SQL filter from validated fields
        -> PostgreSQL retrieves candidate PUBLISHED+current signals
        -> results returned (no further AI ranking call in this version -
           deterministic DB filtering is sufficient per the product's own
           "start simple" guidance; see SignalSearchResult.ai_understood)

The AI never touches the database, never sees unpublished data, and never
produces anything except filter values that go through the exact same
SignalRepository.get_published() path (and its is_current/status
constraints) the plain published-signals endpoint already uses.
"""

import re
import time
from dataclasses import dataclass
from typing import List, Optional

from sqlalchemy.orm import Session

from app.db.models import SecurityCategoryType, Signal
from app.repositories import SignalRepository
from app.intelligence.search_service import NaturalLanguageSearchService, SearchUnderstandingError
from app.taxonomy import internal_categories_to_public, public_category_to_internal
from app.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SignalSearchResult:
    signals: List[Signal]
    ai_understood: bool  # False means deterministic keyword fallback was used
    understood_categories: List[str]


def _coerce_categories(values: List[str]) -> List[SecurityCategoryType]:
    """Already-validated-by-Pydantic category strings -> real enum members.
    Anything that doesn't map (shouldn't happen post-validation, but never
    trust twice) is silently skipped rather than raised."""
    result = []
    for v in values:
        try:
            result.append(SecurityCategoryType(v))
        except ValueError:
            continue
    return result


def _expand_to_public_siblings(categories: List[SecurityCategoryType]) -> List[SecurityCategoryType]:
    """Widen AI-understood internal categories to every internal category
    that shares the same PUBLIC category (e.g. understanding just
    "app_api" -> also include "insecure_design", since both collapse into
    the single public "Product Security" the user actually means).

    The search AI picks ONE plausible internal category per its own
    judgment, but a signal's REAL internal category is decided separately,
    at generation time, by app/intelligence/ai_service.py's own
    threat-modeling-first classification (which favors insecure_design/
    cloud_security/iam quite differently from how a search query might
    phrase the same topic - see app/taxonomy.py, the single source of
    truth for this grouping, already used by the public `public_category`
    filter). Without this, a query like "security problems affecting
    APIs" (understood as app_api only) misses a real, relevant signal
    that generation classified as insecure_design instead, even though
    both are the same public category to an end user."""
    seen_public = set()
    expanded: List[SecurityCategoryType] = []
    for public in internal_categories_to_public(categories):
        if public in seen_public:
            continue
        seen_public.add(public)
        expanded.extend(public_category_to_internal(public))
    return list(dict.fromkeys(expanded))


def search_published_signals(
    session: Session,
    query: str,
    category: Optional[SecurityCategoryType] = None,
    explicit_categories: Optional[List[SecurityCategoryType]] = None,
    subcategory: Optional[str] = None,
    sort: str = "recent",
    limit: int = 20,
    ai_service: Optional[NaturalLanguageSearchService] = None,
    ai_enabled: bool = True,
) -> SignalSearchResult:
    """Search PUBLISHED, current signals using natural language.

    Falls back to deterministic keyword search (query treated as one
    substring/OR'd term set) whenever AI understanding is disabled,
    unconfigured, times out, or returns invalid output - the public feed
    is never dependent on the AI search service being available.

    `category` (single internal value) / `explicit_categories` (an OR-list
    of internal values - used to translate a public category filter, see
    app/api/routes/search.py) / `subcategory` are explicit filters from the
    caller and are ALWAYS applied in addition to whatever the AI or
    fallback path determines - natural-language search works alongside
    existing filters, never instead of them. Either explicit filter
    suppresses the AI's own (broader) category understanding from being
    used as a filter, matching the pre-existing `category` behavior.
    """
    repo = SignalRepository(session)
    understood_categories: List[str] = []
    ai_understood = False
    has_explicit_category_filter = category is not None or bool(explicit_categories)

    keywords: List[str] = [query] if query else []
    ai_categories: Optional[List[SecurityCategoryType]] = None
    ai_subcategory: Optional[str] = None
    ai_entities: List[str] = []

    # Per-stage wall-clock timing, logged (never returned in the response
    # body - internal observability only) so the slowest stage of the
    # documented USER QUERY -> AI UNDERSTANDING -> DETERMINISTIC DB SEARCH
    # -> RESULTS pipeline is always identifiable from logs rather than
    # guessed at.
    search_started = time.monotonic()
    ai_duration_ms: Optional[float] = None

    if ai_enabled and ai_service is not None and query:
        ai_started = time.monotonic()
        try:
            understanding = ai_service.understand_query(query)
            ai_duration_ms = (time.monotonic() - ai_started) * 1000
            ai_understood = True
            understood_categories = understanding.categories
            keyword_terms = list(dict.fromkeys(
                understanding.keywords + understanding.search_terms + understanding.entities
            ))
            keywords = keyword_terms or [understanding.semantic_query]
            ai_categories = _coerce_categories(understanding.categories) or None
            if ai_categories:
                ai_categories = _expand_to_public_siblings(ai_categories)
            ai_entities = understanding.entities
            # Only meaningful for AI Security (the one category with real
            # subcategories - see app/db/models.AISecuritySubcategory);
            # e.g. "recent AI agent attacks" -> ai_security + agent_abuse.
            # Applied only in Tier 1 below - it's a narrow, exact-match
            # refinement, dropped (like keywords) rather than treated as a
            # hard requirement if it over-narrows the result to nothing.
            ai_subcategory = understanding.subcategories[0] if understanding.subcategories else None
            logger.info(
                "search_ai_understood",
                intent=understanding.intent[:100],
                category_count=len(understanding.categories),
                confidence=understanding.confidence,
                duration_ms=round(ai_duration_ms, 1),
            )
        except SearchUnderstandingError as e:
            ai_duration_ms = (time.monotonic() - ai_started) * 1000
            logger.warning("search_ai_fallback", reason=str(e), duration_ms=round(ai_duration_ms, 1))
            ai_understood = False
            keywords = [query]

    effective_category = category if not explicit_categories else None
    effective_categories = explicit_categories if explicit_categories else (
        ai_categories if not has_explicit_category_filter else None
    )
    effective_subcategory_tier1 = subcategory if subcategory is not None else ai_subcategory

    db_started = time.monotonic()

    # Tier 1: category (explicit or AI-understood) narrowed further by a
    # literal keyword/text match and, if the AI identified one, an exact
    # AI Security subcategory match.
    signals = repo.get_published(
        limit=limit,
        category=effective_category,
        subcategory=effective_subcategory_tier1,
        categories=effective_categories,
        keywords=keywords or None,
        sort=sort,
    )

    # Tier 2: a category was identified (explicitly by the caller, or by
    # the AI's real query understanding) but no signal's title/summary/
    # security_impact happens to literally contain any expanded keyword
    # term - trust the category classification alone rather than return
    # nothing. AI-GENERATED signal text deliberately avoids generic
    # wording like "vulnerability" in favor of specific design-lesson
    # language (see app/intelligence/ai_service.py's prompt), so an
    # additional literal-keyword requirement on top of an already-correct
    # category match would otherwise hide real, relevant, already-
    # published signals - the exact "AI understanding succeeds -> zero
    # database results" failure this two-tier fallback exists to catch.
    if not signals and (effective_category is not None or effective_categories):
        signals = repo.get_published(
            limit=limit, category=effective_category, subcategory=subcategory,
            categories=effective_categories, keywords=None, sort=sort,
        )

    # Tier 3: the category the AI (or caller) identified turned out to be
    # wrong or too narrow for this specific signal (e.g. "is there any
    # oauth" understood as iam/app_api, but the real, already-published
    # OAuth signal happens to be filed under insecure_design - a real,
    # correct AI classification decision made at generation time that the
    # search-time category GUESS can't know about; see
    # app/intelligence/ai_service.py's threat-modeling-first prompt).
    # Named entities (the AI's own "named technologies/products/
    # organizations mentioned" - e.g. "OAuth", "Hugging Face") are precise
    # enough to search GLOBALLY, across every category, without the noise
    # risk a generic keyword like "security" or "latest" would create -
    # unlike Tier 4 below, this only fires for specific named things the
    # AI was confident enough to call out as entities.
    if not signals and ai_entities:
        signals = repo.get_published(
            limit=limit, category=None, categories=None, subcategory=subcategory,
            keywords=ai_entities, sort=sort,
        )

    # Tier 4: still nothing, AND no category was ever identified for this
    # query (neither an explicit caller filter nor the AI's own
    # understanding) - fall back to a plain, deterministic per-word
    # substring search over ALL published signals on the raw query (split
    # into individual words, not treated as one solid phrase - a full
    # multi-word natural-language query is very unlikely to appear
    # verbatim in any signal, which made the previous single-phrase
    # fallback nearly always return nothing).
    #
    # Deliberately NOT reached when a real category WAS identified
    # (Tier 2 already tried that category alone, and Tier 3 already tried
    # any named entities, and both found nothing) - falling through to an
    # unscoped global keyword search at that point would surface
    # topically-unrelated signals just because a common word like
    # "security" appears in their text, which is exactly the "returns
    # misleading results instead of an honest empty result" failure the
    # product explicitly forbids (a query that maps to a real, currently-
    # empty category must come back empty, not with noise from other
    # categories).
    if not signals and query and effective_category is None and not effective_categories:
        word_terms = [w for w in re.findall(r"\w+", query) if len(w) >= 2]
        signals = repo.get_published(
            limit=limit, category=None, categories=None, subcategory=subcategory,
            keywords=word_terms or [query], sort=sort,
        )

    db_duration_ms = (time.monotonic() - db_started) * 1000
    total_duration_ms = (time.monotonic() - search_started) * 1000
    logger.info(
        "search_timing",
        ai_understood=ai_understood,
        ai_duration_ms=round(ai_duration_ms, 1) if ai_duration_ms is not None else None,
        db_duration_ms=round(db_duration_ms, 1),
        total_duration_ms=round(total_duration_ms, 1),
        result_count=len(signals),
    )

    return SignalSearchResult(
        signals=signals, ai_understood=ai_understood, understood_categories=understood_categories,
    )
