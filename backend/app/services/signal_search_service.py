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
from dataclasses import dataclass
from typing import List, Optional

from sqlalchemy.orm import Session

from app.db.models import SecurityCategoryType, Signal
from app.repositories import SignalRepository
from app.intelligence.search_service import NaturalLanguageSearchService, SearchUnderstandingError
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

    if ai_enabled and ai_service is not None and query:
        try:
            understanding = ai_service.understand_query(query)
            ai_understood = True
            understood_categories = understanding.categories
            keyword_terms = list(dict.fromkeys(
                understanding.keywords + understanding.search_terms + understanding.entities
            ))
            keywords = keyword_terms or [understanding.semantic_query]
            ai_categories = _coerce_categories(understanding.categories) or None
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
            )
        except SearchUnderstandingError as e:
            logger.warning("search_ai_fallback", reason=str(e))
            ai_understood = False
            keywords = [query]

    effective_category = category if not explicit_categories else None
    effective_categories = explicit_categories if explicit_categories else (
        ai_categories if not has_explicit_category_filter else None
    )
    effective_subcategory_tier1 = subcategory if subcategory is not None else ai_subcategory

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

    # Tier 3: still nothing, AND no category was ever identified for this
    # query (neither an explicit caller filter nor the AI's own
    # understanding) - fall back to a plain, deterministic per-word
    # substring search over ALL published signals on the raw query (split
    # into individual words, not treated as one solid phrase - a full
    # multi-word natural-language query is very unlikely to appear
    # verbatim in any signal, which made the previous single-phrase
    # fallback nearly always return nothing).
    #
    # Deliberately NOT reached when a real category WAS identified
    # (Tier 2 already tried that category alone and found nothing) -
    # falling through to an unscoped global keyword search at that point
    # would surface topically-unrelated signals just because a common word
    # like "security" appears in their text, which is exactly the
    # "returns misleading results instead of an honest empty result"
    # failure the product explicitly forbids (a query that maps to a real,
    # currently-empty category must come back empty, not with noise from
    # other categories).
    if not signals and query and effective_category is None and not effective_categories:
        word_terms = [w for w in re.findall(r"\w+", query) if len(w) >= 2]
        signals = repo.get_published(
            limit=limit, category=None, categories=None, subcategory=subcategory,
            keywords=word_terms or [query], sort=sort,
        )

    return SignalSearchResult(
        signals=signals, ai_understood=ai_understood, understood_categories=understood_categories,
    )
