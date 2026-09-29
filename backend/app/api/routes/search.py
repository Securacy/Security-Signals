"""Natural-language security signal search - PUBLIC endpoint (Feature 3).

Registered under the same /api/v1/signals prefix as the rest of the public
signal API, since this is an alternate way to find PUBLISHED signals, not
a new resource. Never exposes anything beyond what /published already
would - same PUBLISHED + is_current constraint, enforced by
SignalRepository.get_published() regardless of what the AI understood.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.connection import get_db
from app.db.models import SecurityCategoryType
from app.repositories import SignalRepository, SignalCategoryRepository
from app.services.signal_search_service import search_published_signals
from app.api.rate_limit import limiter
from app.taxonomy import UnknownPublicCategoryError, internal_categories_to_public, public_category_to_internal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/signals", tags=["search"])

_settings = get_settings()

_MAX_QUERY_LENGTH = 500  # hard cap independent of settings.search_max_query_length,
                          # enforced at the transport layer before any processing

# Built once, lazily, and reused for the process lifetime - constructing a
# NaturalLanguageSearchService rebuilds a boto3 Bedrock client from scratch
# (and, when credentials are configured as Secrets Manager ARNs, makes a
# real extra network round-trip to resolve them - see
# app/intelligence/bedrock_client.py's _resolve_secret_value), which is
# pure per-request overhead: credentials/region/model config are static for
# the life of this process, exactly like every other setting this app
# already treats as fixed at startup. This does not change behavior -
# still the same client construction, just done once instead of on every
# search request - and still falls back to deterministic search below if
# construction fails.
_search_ai_service = None
_search_ai_service_init_failed = False


def _get_search_ai_service():
    global _search_ai_service, _search_ai_service_init_failed
    if _search_ai_service is not None or _search_ai_service_init_failed:
        return _search_ai_service
    try:
        from app.intelligence.search_service import NaturalLanguageSearchService
        _search_ai_service = NaturalLanguageSearchService.from_settings(_settings)
    except Exception as e:
        logger.warning(f"search_ai_unavailable: {type(e).__name__}: {e}")
        _search_ai_service_init_failed = True
    return _search_ai_service


@router.get("/search", response_model=dict)
@limiter.limit(_settings.search_rate_limit)
def search_signals(
    request: Request,
    q: str = Query(..., min_length=1, max_length=_MAX_QUERY_LENGTH),
    category: Optional[SecurityCategoryType] = None,
    public_category: Optional[str] = None,
    subcategory: Optional[str] = None,
    sort: str = Query(default="recent"),
    limit: int = Query(default=20, le=100),
    db: Session = Depends(get_db),
):
    """Natural-language search over PUBLISHED signals - PUBLIC endpoint.

    Falls back to deterministic keyword search automatically if AI
    understanding is disabled, unconfigured, or fails - this endpoint never
    hard-fails just because the AI search layer is unavailable.

    `public_category` (e.g. "product_security") translates to the internal
    categories it aggregates (see app.taxonomy) and takes precedence over
    the internal `category` param if both are given - the public widget
    uses this exclusively.
    """
    settings = get_settings()

    if sort not in SignalRepository.VALID_SORTS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort. Allowed: {sorted(SignalRepository.VALID_SORTS)}",
        )

    explicit_internal_categories = None
    if public_category is not None:
        try:
            explicit_internal_categories = public_category_to_internal(public_category)
        except UnknownPublicCategoryError as e:
            raise HTTPException(status_code=422, detail=str(e))
        category = None  # public_category takes precedence

    ai_service = _get_search_ai_service() if settings.search_ai_enabled else None

    result = search_published_signals(
        db, query=q, category=category, explicit_categories=explicit_internal_categories,
        subcategory=subcategory, sort=sort, limit=limit,
        ai_service=ai_service, ai_enabled=settings.search_ai_enabled,
    )

    category_repo = SignalCategoryRepository(db)
    categories_by_signal = {}
    for cat in category_repo.get_by_signal_ids([sig.id for sig in result.signals]):
        categories_by_signal.setdefault(cat.signal_id, []).append({
            "id": str(cat.id),
            "category": cat.category.value if hasattr(cat.category, "value") else cat.category,
            "subcategory": cat.subcategory,
        })

    return {
        "query": q,
        "ai_understood": result.ai_understood,
        "understood_categories": result.understood_categories,
        "understood_public_categories": internal_categories_to_public(result.understood_categories),
        "results": [
            {
                "id": str(sig.id),
                "title": sig.title,
                "summary": sig.summary,
                "security_impact": sig.security_impact,
                "principle": sig.principle,
                "recommended_action": sig.recommended_action,
                "published_at": sig.published_at.isoformat() if sig.published_at else None,
                "categories": categories_by_signal.get(sig.id, []),
                "public_categories": internal_categories_to_public(
                    c["category"] for c in categories_by_signal.get(sig.id, [])
                ),
            }
            for sig in result.signals
        ],
    }
