"""Admin-only audit log API routes.

Phase 6: Read-only visibility into the immutable audit trail.

No update or delete endpoints exist here by design - AuditLog is append-only
(enforced at the application layer via AuditLogRepository, and at the
database layer by migration 006's triggers). This module only ever reads.
"""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.connection import get_db
from app.db.models import User
from app.api.dependencies import require_admin
from app.repositories import AuditLogRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


def _serialize_entry(entry) -> dict:
    """Serialize an AuditLog entry. `changes` is populated exclusively by our
    own service code and never carries passwords, hashes, or tokens."""
    return {
        "id": str(entry.id),
        "user_id": str(entry.user_id) if entry.user_id else None,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": str(entry.resource_id),
        "changes": entry.changes,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
    }


@router.get("", response_model=list)
def list_audit_entries(
    resource_type: Optional[str] = None,
    resource_id: Optional[UUID] = None,
    user_id: Optional[UUID] = None,
    action: Optional[str] = None,
    skip: int = 0,
    limit: int = Query(default=50, le=200),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """List audit entries with optional filtering and pagination - ADMIN only."""
    audit_repo = AuditLogRepository(db)
    entries = audit_repo.query(
        resource_type=resource_type,
        resource_id=resource_id,
        user_id=user_id,
        action=action,
        skip=skip,
        limit=limit,
    )
    return [_serialize_entry(e) for e in entries]


@router.get("/{audit_id}", response_model=dict)
def get_audit_entry(
    audit_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Get a single audit entry by ID - ADMIN only."""
    try:
        aid = UUID(audit_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid audit ID format")

    audit_repo = AuditLogRepository(db)
    entry = audit_repo.get_by_id(aid)
    if not entry:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    return _serialize_entry(entry)
