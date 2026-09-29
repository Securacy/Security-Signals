"""Signal management API routes.

Phase 5: Public API for published signals with evidence and categories
Phase 6: Protected endpoints for draft/in-review signal management + authentication
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
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


def _visual_fields_by_signal(db: Session, signal_ids: list) -> dict:
    """Visual state for the admin review lists: signal_id -> the fields
    added to each /draft and /approved item. Read-only - never triggers
    generation. A signal with no SignalVisual row at all (persisted before
    visuals were generated at DRAFT time, or with generation disabled)
    reports "none" - distinct from "pending", which means generation has
    genuinely been queued."""
    if not signal_ids:
        return {}
    rows = db.query(SignalVisual).filter(SignalVisual.signal_id.in_(signal_ids)).all()
    return {
        row.signal_id: {
            "visual_status": row.status.value,
            "visual_url": row.url if row.status == VisualStatus.GENERATED else None,
            "visual_requested_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    }


_NO_VISUAL = {"visual_status": "none", "visual_url": None, "visual_requested_at": None}


def _categories_by_signal(db: Session, signal_ids: list) -> dict:
    """Shared category lookup for list endpoints - same pattern
    list_published_signals already uses, extracted so /draft and /approved
    (admin review queue) can reuse it instead of duplicating the loop."""
    category_repo = SignalCategoryRepository(db)
    categories_by_signal: dict = {}
    for cat in category_repo.get_by_signal_ids(signal_ids):
        categories_by_signal.setdefault(cat.signal_id, []).append(
            {
                "id": str(cat.id),
                "category": cat.category.value if hasattr(cat.category, "value") else cat.category,
                "subcategory": cat.subcategory,
            }
        )
    return categories_by_signal


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

    signals = signal_repo.get_published(
        skip=skip, limit=limit, category=category, categories=internal_categories,
        subcategory=subcategory, search=search, sort=sort,
    )

    categories_by_signal = _categories_by_signal(db, [sig.id for sig in signals])

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
        # No SignalVisual row at all means this signal predates the visual-
        # generation feature (see SignalVisual's docstring) - "pending"
        # would wrongly imply a generation job is queued and will finish;
        # it never was and never will be. "none" matches the same
        # legacy-vs-queued distinction every admin route already makes
        # (see _NO_VISUAL above).
        "visual_status": visual.status.value if visual else "none",
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

    categories_by_signal = _categories_by_signal(db, [sig.id for sig in all_signals])
    visuals_by_signal = _visual_fields_by_signal(db, [sig.id for sig in all_signals])

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
            "categories": categories_by_signal.get(sig.id, []),
            **visuals_by_signal.get(sig.id, _NO_VISUAL),
        }
        for sig in all_signals
    ]


@router.get("/approved", response_model=list)
def list_approved_signals(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """List APPROVED signals awaiting publish - PROTECTED (ADMIN only).

    Reviewers move a signal from IN_REVIEW to APPROVED via /approve, but
    publishing (the public-facing gate) is admin-only - this is the
    admin-only counterpart to /draft that surfaces what's sitting in that
    approved-but-not-yet-published state, so the "ready to publish" queue is
    actually visible instead of only discoverable by ID.

    Args:
        current_user: Authenticated user (required, ADMIN only)
        db: Database session

    Returns:
        List of approved signals

    Raises:
        HTTPException 401: If not authenticated
        HTTPException 403: If user does not have ADMIN role
    """
    signal_repo = SignalRepository(db)
    approved_signals = signal_repo.get_by_status(SignalStatus.APPROVED)

    logger.info(f"list_approved_signals: user={current_user.username}, count={len(approved_signals)}")

    categories_by_signal = _categories_by_signal(db, [sig.id for sig in approved_signals])
    visuals_by_signal = _visual_fields_by_signal(db, [sig.id for sig in approved_signals])

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
            "reviewed_at": sig.reviewed_at.isoformat() if sig.reviewed_at else None,
            "categories": categories_by_signal.get(sig.id, []),
            **visuals_by_signal.get(sig.id, _NO_VISUAL),
        }
        for sig in approved_signals
    ]


@router.get("/rejected", response_model=list)
def list_rejected_signals(
    current_user: User = Depends(require_reviewer),
    db: Session = Depends(get_db)
):
    """List REJECTED signals - PROTECTED (REVIEWER/ADMIN only).

    Mirrors /draft and /approved: the counterpart that surfaces signals a
    reviewer or admin has rejected, so that history is visible as its own
    workflow stage instead of only discoverable by ID.

    Args:
        current_user: Authenticated user (required, REVIEWER/ADMIN)
        db: Database session

    Returns:
        List of rejected signals

    Raises:
        HTTPException 401: If not authenticated
        HTTPException 403: If user does not have REVIEWER or ADMIN role
    """
    signal_repo = SignalRepository(db)
    rejected_signals = signal_repo.get_by_status(SignalStatus.REJECTED)

    logger.info(f"list_rejected_signals: user={current_user.username}, count={len(rejected_signals)}")

    categories_by_signal = _categories_by_signal(db, [sig.id for sig in rejected_signals])
    visuals_by_signal = _visual_fields_by_signal(db, [sig.id for sig in rejected_signals])

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
            "reviewed_at": sig.reviewed_at.isoformat() if sig.reviewed_at else None,
            "categories": categories_by_signal.get(sig.id, []),
            **visuals_by_signal.get(sig.id, _NO_VISUAL),
        }
        for sig in rejected_signals
    ]


@router.get("/{signal_id}", response_model=dict)
def get_signal_detail(
    signal_id: str,
    current_user: User = Depends(require_reviewer),
    db: Session = Depends(get_db),
):
    """Full detail for ONE signal in ANY status - PROTECTED (REVIEWER/ADMIN
    only). Registered after the literal /draft, /approved and /published
    routes above so it never shadows them (FastAPI matches path routes in
    registration order, and this is a catch-all `{signal_id}` segment).

    /draft and /approved return list-shaped summaries only; this is the
    single endpoint the admin review UI's detail panel calls regardless of
    which section a signal was opened from, since a signal's status can
    change between DRAFT/IN_REVIEW/APPROVED/REJECTED/PUBLISHED while the
    reviewer has it open. VIEWER cannot call this - a viewer's only signal
    visibility is the public /published endpoints, which already have
    their own detail route.

    Mirrors get_published_signal's shape (evidence + categories + visual)
    plus the fields list_draft_signals/list_approved_signals already
    expose (status/created_at/reviewed_by/reviewed_at) - reuses the same
    repositories and helpers, no new persistence or business logic.
    """
    sid = _parse_signal_id(signal_id)
    signal_repo = SignalRepository(db)
    evidence_repo = EvidenceRepository(db)

    signal = signal_repo.get_by_id(sid)
    if not signal:
        raise HTTPException(status_code=404, detail="Signal not found")

    categories_data = _categories_by_signal(db, [sid]).get(sid, [])
    evidence_data = [
        {
            "id": str(ev.id),
            "source_url": ev.source_url,
            "source_title": ev.source_title,
            "excerpt": ev.excerpt,
            "created_at": ev.created_at.isoformat() if ev.created_at else None,
        }
        for ev in evidence_repo.get_by_signal(signal.id)
    ]
    visual_fields = _visual_fields_by_signal(db, [sid]).get(sid, _NO_VISUAL)

    return {
        "id": str(signal.id),
        "title": signal.title,
        "status": signal.status.value,
        "summary": signal.summary,
        "security_impact": signal.security_impact,
        "principle": signal.principle,
        "recommended_action": signal.recommended_action,
        "created_at": signal.created_at.isoformat() if signal.created_at else None,
        "reviewed_by": str(signal.reviewed_by) if signal.reviewed_by else None,
        "reviewed_at": signal.reviewed_at.isoformat() if signal.reviewed_at else None,
        "published_at": signal.published_at.isoformat() if signal.published_at else None,
        "categories": categories_data,
        "public_categories": internal_categories_to_public(c["category"] for c in categories_data),
        "evidence": evidence_data,
        **visual_fields,
    }


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


class RejectSignalRequest(BaseModel):
    """Optional review note explaining a rejection. Never required at the
    schema level (older/other callers may still call this endpoint with no
    body), but the admin UI's reject flow always collects one."""
    reason: Optional[str] = Field(default=None, max_length=2000)


@router.post("/{signal_id}/reject", response_model=dict)
def reject_signal_route(
    signal_id: str,
    body: RejectSignalRequest = RejectSignalRequest(),
    current_user: User = Depends(require_reviewer),
    db: Session = Depends(get_db),
):
    """Reject a signal (IN_REVIEW -> REJECTED) - REVIEWER/ADMIN only."""
    sid = _parse_signal_id(signal_id)
    service = SignalService(db)
    try:
        signal = service.reject_signal(sid, reviewer_id=current_user.id, reason=body.reason)
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
