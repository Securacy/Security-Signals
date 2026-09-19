"""Signal management API routes.

Phase 5: Public API for published signals with evidence and categories
Phase 6: Protected endpoints for draft/in-review signal management + authentication
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from uuid import UUID
import logging

from app.db.connection import get_db
from app.db.models import User, SignalStatus, SecurityCategoryType, VisualStatus, SignalVisual
from app.repositories import SignalRepository, EvidenceRepository, SignalCategoryRepository
from app.api.dependencies import require_reviewer, require_admin
from app.services.signal_service import SignalService
from app.common.errors import NotFoundError
from app.taxonomy import UnknownPublicCategoryError, internal_categories_to_public, public_category_to_internal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/signals", tags=["signals"])


# Phase 5: Public endpoints - RESTORED WITH FULL CONTRACTS
# Phase 6 (frontend widget support): optional `category` filter and a
# lightweight `categories` field per item, added to this existing endpoint
# rather than introducing a new one. Omitting `category` preserves the
# original unfiltered response shape plus the additive `categories` field.
@router.get("/published", response_model=list)
def list_published_signals(
    skip: int = 0,
    limit: int = Query(default=10, le=100),
    category: Optional[SecurityCategoryType] = None,
    public_category: Optional[str] = None,
    subcategory: Optional[str] = None,
    search: Optional[str] = Query(default=None, max_length=200),
    sort: str = Query(default="recent"),
    db: Session = Depends(get_db)
):
    """List published signals - PUBLIC endpoint.

    Args:
        skip: Number of records to skip (pagination)
        limit: Maximum records to return (capped at 100)
        category: Optional INTERNAL category filter (e.g. "insecure_design") -
            kept for backward compatibility / internal callers.
        public_category: Optional PUBLIC category filter (e.g.
            "product_security"), translated to the internal categories it
            aggregates (see app.taxonomy). Takes precedence over `category`
            if both are given - the public widget uses this exclusively.
        subcategory: Optional AI subcategory filter (only meaningful with category=ai_security)
        search: Optional case-insensitive substring match over title/summary/security_impact
        sort: One of "recent" (default), "sources", "relevant", "priority" - see SignalRepository.get_published
        db: Database session

    Returns:
        List of published signals, each including its internal category
        tags AND its consolidated `public_categories` (deduplicated, see
        app.taxonomy.internal_categories_to_public).
    """
    if sort not in SignalRepository.VALID_SORTS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort. Allowed: {sorted(SignalRepository.VALID_SORTS)}",
        )

    internal_categories = None
    if public_category is not None:
        try:
            internal_categories = public_category_to_internal(public_category)
        except UnknownPublicCategoryError as e:
            raise HTTPException(status_code=422, detail=str(e))
        category = None  # public_category takes precedence

    signal_repo = SignalRepository(db)
    category_repo = SignalCategoryRepository(db)

    signals = signal_repo.get_published(
        skip=skip, limit=limit, category=category, categories=internal_categories,
        subcategory=subcategory, search=search, sort=sort,
    )

    categories_by_signal = {}
    for cat in category_repo.get_by_signal_ids([sig.id for sig in signals]):
        categories_by_signal.setdefault(cat.signal_id, []).append(
            {
                "id": str(cat.id),
                "category": cat.category.value if hasattr(cat.category, "value") else cat.category,
                "subcategory": cat.subcategory,
            }
        )

    return [
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
        for sig in signals
    ]


@router.get("/published/{signal_id}", response_model=dict)
def get_published_signal(
    signal_id: str,
    db: Session = Depends(get_db)
):
    """Get published signal details with evidence and categories - PUBLIC endpoint.
    
    Args:
        signal_id: UUID of the signal
        db: Database session
    
    Returns:
        Published signal with evidence and categories
    
    Raises:
        HTTPException 404: If signal not found or not published
    """
    signal_repo = SignalRepository(db)
    evidence_repo = EvidenceRepository(db)
    category_repo = SignalCategoryRepository(db)
    
    try:
        signal_uuid = UUID(signal_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid signal ID format")
    
    signal = signal_repo.get_by_id(signal_uuid)
    if not signal or signal.status != SignalStatus.PUBLISHED:
        raise HTTPException(status_code=404, detail="Signal not found")
    
    # Get evidence for this signal
    # Repository methods return empty lists if no records found
    evidence_list = evidence_repo.get_by_signal(signal.id)
    
    evidence_data = [
        {
            "id": str(ev.id),
            "source_url": ev.source_url,
            "source_title": ev.source_title,
            "excerpt": ev.excerpt,
            "created_at": ev.created_at.isoformat() if ev.created_at else None,
        }
        for ev in evidence_list
    ]
    
    # Get categories for this signal
    # Repository methods return empty lists if no records found
    categories = category_repo.get_by_signal(signal.id)

    categories_data = [
        {
            "id": str(cat.id),
            "category": cat.category.value if hasattr(cat.category, 'value') else cat.category,
            "subcategory": cat.subcategory,
        }
        for cat in categories
    ]

    # Signal-specific visual (Section 15-19 of the taxonomy/visuals spec):
    # only exposed on the detail response, never the list/feed response -
    # the feed stays lightweight (icons only); the actual image only
    # matters once a viewer opens one specific signal. Never triggers
    # generation from this GET - generation only happens once, at publish
    # time (SignalService.publish_signal) - this only reads whatever
    # already exists (or doesn't).
    visual = db.query(SignalVisual).filter_by(signal_id=signal.id).one_or_none()

    return {
        "id": str(signal.id),
        "title": signal.title,
        "summary": signal.summary,
        "security_impact": signal.security_impact,
        "principle": signal.principle,
        "recommended_action": signal.recommended_action,
        "published_at": signal.published_at.isoformat() if signal.published_at else None,
        "evidence": evidence_data,
        "categories": categories_data,
        "public_categories": internal_categories_to_public(c["category"] for c in categories_data),
        "visual_status": visual.status.value if visual else VisualStatus.PENDING.value,
        "visual_url": visual.url if visual and visual.status == VisualStatus.GENERATED else None,
    }


# Phase 6: Protected endpoints for reviewers
@router.get("/draft", response_model=list)
def list_draft_signals(
    current_user: User = Depends(require_reviewer),
    db: Session = Depends(get_db)
):
    """List DRAFT and IN_REVIEW signals - PROTECTED (REVIEWER/ADMIN only).
    
    Only users with REVIEWER or ADMIN role can access this endpoint.
    
    Args:
        current_user: Authenticated user (required)
        db: Database session
    
    Returns:
        List of draft and in-review signals
    
    Raises:
        HTTPException 401: If not authenticated
        HTTPException 403: If user does not have REVIEWER role
    """
    signal_repo = SignalRepository(db)
    
    # Get both DRAFT and IN_REVIEW signals
    draft_signals = signal_repo.get_by_status(SignalStatus.DRAFT)
    review_signals = signal_repo.get_by_status(SignalStatus.IN_REVIEW)
    
    all_signals = draft_signals + review_signals
    
    logger.info(f"list_draft_signals: user={current_user.username}, role={current_user.role.value}, count={len(all_signals)}")
    
    return [
        {
            "id": str(sig.id),
            "title": sig.title,
            "summary": sig.summary,
            "status": sig.status.value,
            "security_impact": sig.security_impact,
            "principle": sig.principle,
            "recommended_action": sig.recommended_action,
            "created_at": sig.created_at.isoformat() if sig.created_at else None,
            "reviewed_by": str(sig.reviewed_by) if sig.reviewed_by else None,
        }
        for sig in all_signals
    ]


# Phase 6: Review workflow - thin wrappers around SignalService.
# The lifecycle state machine and transactional audit logging live entirely
# in SignalService; these routes only handle auth, ID parsing, and HTTP
# status translation.

def _parse_signal_id(signal_id: str) -> UUID:
    """Parse a signal ID path parameter, raising 400 on malformed input."""
    try:
        return UUID(signal_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid signal ID format")


def _serialize_signal_detail(sig) -> dict:
    """Serialize a Signal after a lifecycle transition."""
    return {
        "id": str(sig.id),
        "title": sig.title,
        "status": sig.status.value,
        "summary": sig.summary,
        "security_impact": sig.security_impact,
        "principle": sig.principle,
        "recommended_action": sig.recommended_action,
        "reviewed_by": str(sig.reviewed_by) if sig.reviewed_by else None,
        "reviewed_at": sig.reviewed_at.isoformat() if sig.reviewed_at else None,
        "published_at": sig.published_at.isoformat() if sig.published_at else None,
    }


@router.post("/{signal_id}/submit-for-review", response_model=dict)
def submit_signal_for_review(
    signal_id: str,
    current_user: User = Depends(require_reviewer),
    db: Session = Depends(get_db),
):
    """Move a signal from DRAFT to IN_REVIEW - REVIEWER/ADMIN only."""
    sid = _parse_signal_id(signal_id)
    service = SignalService(db)
    try:
        signal = service.submit_for_review(sid, actor_id=current_user.id)
    except NotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Signal not found")
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    logger.info(f"signal_submitted_for_review: user={current_user.username}, signal={sid}")
    return _serialize_signal_detail(signal)


@router.post("/{signal_id}/approve", response_model=dict)
def approve_signal_route(
    signal_id: str,
    current_user: User = Depends(require_reviewer),
    db: Session = Depends(get_db),
):
    """Approve a signal (IN_REVIEW -> APPROVED) - REVIEWER/ADMIN only."""
    sid = _parse_signal_id(signal_id)
    service = SignalService(db)
    try:
        signal = service.approve_signal(sid, reviewer_id=current_user.id)
    except NotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Signal not found")
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    logger.info(f"signal_approved: user={current_user.username}, signal={sid}")
    return _serialize_signal_detail(signal)


@router.post("/{signal_id}/reject", response_model=dict)
def reject_signal_route(
    signal_id: str,
    current_user: User = Depends(require_reviewer),
    db: Session = Depends(get_db),
):
    """Reject a signal (IN_REVIEW -> REJECTED) - REVIEWER/ADMIN only."""
    sid = _parse_signal_id(signal_id)
    service = SignalService(db)
    try:
        signal = service.reject_signal(sid, reviewer_id=current_user.id)
    except NotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Signal not found")
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    logger.info(f"signal_rejected: user={current_user.username}, signal={sid}")
    return _serialize_signal_detail(signal)


@router.post("/{signal_id}/publish", response_model=dict)
def publish_signal_route(
    signal_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Publish a signal (APPROVED -> PUBLISHED) - ADMIN only.

    Publishing is the final, public-facing gate, so it is restricted to
    ADMIN rather than REVIEWER (segregation of duties between reviewing and
    the irreversible act of making a signal public).
    """
    sid = _parse_signal_id(signal_id)
    service = SignalService(db)
    try:
        signal = service.publish_signal(sid, actor_id=current_user.id)
    except NotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Signal not found")
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    logger.info(f"signal_published: user={current_user.username}, signal={sid}")
    return _serialize_signal_detail(signal)
