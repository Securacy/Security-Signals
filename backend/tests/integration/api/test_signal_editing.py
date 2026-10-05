"""Integration tests for human-in-the-loop signal content/category editing:
PATCH /api/v1/signals/{id} and PATCH /api/v1/signals/{id}/category.

Covers: RBAC (only REVIEWER/ADMIN may edit), lifecycle safety (only
DRAFT/IN_REVIEW signals are editable), server-side validation (category/
subcategory taxonomy, field lengths - never trusting the client), the
optimistic-lock conflict (409) path, and that every real edit writes a
real SIGNAL_EDITED/SIGNAL_CATEGORY_EDITED audit entry with an accurate
before/after diff.
"""
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy.orm import Session

from app.db.models import AuditLog, User, UserRole
from app.auth.password import hash_password
from app.auth.tokens import create_access_token
from app.services.signal_service import SignalService
from app.intelligence.schemas.signal_request import AISignalGenerationResponse


@pytest.fixture
def ai_response():
    return AISignalGenerationResponse(
        signal_title="Original AI-Generated Title",
        signal_description="Original AI-generated description of the security event.",
        category="iam",
        confidence=0.9,
        evidence_summary="Evidence discovered in security audit.",
        secure_design_principles=[],
    )


def _make_user(db: Session, username: str, role: UserRole) -> User:
    user = User(
        username=username,
        email=f"{username}@test.local",
        role=role,
        password_hash=hash_password("TestPassword123!"),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _token(user: User) -> str:
    return create_access_token(user_id=user.id, username=user.username, role=user.role.value)


def _draft_signal(db: Session, security_event, ai_response):
    service = SignalService(db)
    signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
    db.commit()
    return signal


class TestEditContentRBAC:
    def test_unauthenticated_401(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        response = client.patch(f"/api/v1/signals/{signal.id}", json={"title": "New title"})
        assert response.status_code == 401

    def test_viewer_cannot_edit_403(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        viewer = _make_user(db, "edit_viewer", UserRole.VIEWER)
        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"title": "New title"},
            headers={"Authorization": f"Bearer {_token(viewer)}"},
        )
        assert response.status_code == 403

    def test_reviewer_can_edit(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        reviewer = _make_user(db, "edit_reviewer", UserRole.REVIEWER)
        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"title": "Reviewer-corrected title"},
            headers={"Authorization": f"Bearer {_token(reviewer)}"},
        )
        assert response.status_code == 200
        assert response.json()["title"] == "Reviewer-corrected title"

    def test_admin_can_edit(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        admin = _make_user(db, "edit_admin", UserRole.ADMIN)
        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"title": "Admin-corrected title"},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 200


class TestEditContentLifecycle:
    def test_approved_signal_cannot_be_edited(self, client, db: Session, security_event, ai_response):
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        reviewer = _make_user(db, "edit_lifecycle_reviewer", UserRole.REVIEWER)
        service.approve_signal(signal.id, reviewer_id=reviewer.id)
        db.commit()

        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"title": "Should be rejected"},
            headers={"Authorization": f"Bearer {_token(reviewer)}"},
        )
        assert response.status_code == 400

    def test_in_review_signal_can_be_edited(self, client, db: Session, security_event, ai_response):
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        db.commit()
        reviewer = _make_user(db, "edit_in_review_reviewer", UserRole.REVIEWER)

        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"summary": "Corrected summary text"},
            headers={"Authorization": f"Bearer {_token(reviewer)}"},
        )
        assert response.status_code == 200
        assert response.json()["summary"] == "Corrected summary text"

    def test_nonexistent_signal_404(self, client, db: Session):
        admin = _make_user(db, "edit_404_admin", UserRole.ADMIN)
        response = client.patch(
            "/api/v1/signals/00000000-0000-0000-0000-000000000000",
            json={"title": "x"},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 404


class TestEditContentValidation:
    def test_overlong_title_rejected(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        admin = _make_user(db, "edit_val_admin", UserRole.ADMIN)
        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"title": "x" * 501},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 422

    def test_empty_title_rejected(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        admin = _make_user(db, "edit_empty_admin", UserRole.ADMIN)
        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"title": ""},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 422

    def test_unchanged_fields_are_a_no_op_and_write_no_audit(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        admin = _make_user(db, "edit_noop_admin", UserRole.ADMIN)
        before_count = db.query(AuditLog).count()

        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"title": signal.title},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 200
        assert db.query(AuditLog).count() == before_count


class TestEditContentOptimisticLock:
    def test_stale_expected_updated_at_returns_409(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        admin = _make_user(db, "edit_stale_admin", UserRole.ADMIN)
        stale = (signal.updated_at - timedelta(days=1)).isoformat() if signal.updated_at else datetime.now(timezone.utc).isoformat()

        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"title": "New title", "expected_updated_at": stale},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 409

    def test_matching_expected_updated_at_succeeds(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        admin = _make_user(db, "edit_fresh_admin", UserRole.ADMIN)

        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"title": "New title", "expected_updated_at": signal.updated_at.isoformat()},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 200


class TestEditContentAudit:
    def test_edit_writes_an_audit_entry_with_an_accurate_diff(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        original_title = signal.title
        admin = _make_user(db, "edit_audit_admin", UserRole.ADMIN)

        response = client.patch(
            f"/api/v1/signals/{signal.id}",
            json={"title": "Audited new title"},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 200

        entry = (
            db.query(AuditLog)
            .filter_by(resource_type="SIGNAL", resource_id=signal.id, action="SIGNAL_EDITED")
            .one()
        )
        assert entry.user_id == admin.id
        assert entry.changes["title"]["from"] == original_title
        assert entry.changes["title"]["to"] == "Audited new title"
        assert "summary" not in entry.changes  # only the field that actually changed


class TestEditCategory:
    def test_edit_category_requires_subcategory_for_ai_security(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        admin = _make_user(db, "edit_cat_ai_admin", UserRole.ADMIN)
        response = client.patch(
            f"/api/v1/signals/{signal.id}/category",
            json={"category": "ai_security"},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 422

    def test_edit_category_rejects_subcategory_for_non_ai_security(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        admin = _make_user(db, "edit_cat_non_ai_admin", UserRole.ADMIN)
        response = client.patch(
            f"/api/v1/signals/{signal.id}/category",
            json={"category": "ransomware", "subcategory": "llm_vulnerability"},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 422

    def test_edit_category_rejects_unknown_category(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        admin = _make_user(db, "edit_cat_unknown_admin", UserRole.ADMIN)
        response = client.patch(
            f"/api/v1/signals/{signal.id}/category",
            json={"category": "not_a_real_category"},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 422

    def test_edit_category_success_flips_assigned_by_to_human_and_audits(
        self, client, db: Session, security_event, ai_response
    ):
        signal = _draft_signal(db, security_event, ai_response)
        admin = _make_user(db, "edit_cat_success_admin", UserRole.ADMIN)

        response = client.patch(
            f"/api/v1/signals/{signal.id}/category",
            json={"category": "ransomware"},
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 200
        assert response.json()["categories"][0]["category"] == "ransomware"

        from app.db.models import SignalCategory, AssignmentMethod
        row = db.query(SignalCategory).filter_by(signal_id=signal.id).one()
        assert row.assigned_by == AssignmentMethod.HUMAN

        entry = (
            db.query(AuditLog)
            .filter_by(resource_type="SIGNAL", resource_id=signal.id, action="SIGNAL_CATEGORY_EDITED")
            .one()
        )
        assert entry.changes["category"]["from"] == "iam"
        assert entry.changes["category"]["to"] == "ransomware"

    def test_viewer_cannot_edit_category_403(self, client, db: Session, security_event, ai_response):
        signal = _draft_signal(db, security_event, ai_response)
        viewer = _make_user(db, "edit_cat_viewer", UserRole.VIEWER)
        response = client.patch(
            f"/api/v1/signals/{signal.id}/category",
            json={"category": "ransomware"},
            headers={"Authorization": f"Bearer {_token(viewer)}"},
        )
        assert response.status_code == 403
