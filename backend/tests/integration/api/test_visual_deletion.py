"""Integration tests for DELETE /api/v1/signals/{id}/visual - reviewer/
admin moderation action that removes a signal's generated visual without
touching the signal itself, its evidence/categories, or regenerating.
"""
import pytest
from sqlalchemy.orm import Session

from app.db.models import AuditLog, Signal, SignalVisual, VisualStatus, User, UserRole
from app.auth.password import hash_password
from app.auth.tokens import create_access_token
from app.services.signal_service import SignalService
from app.intelligence.schemas.signal_request import AISignalGenerationResponse


@pytest.fixture
def ai_response():
    return AISignalGenerationResponse(
        signal_title="Signal With A Visual To Delete",
        signal_description="Description used for the visual-deletion test suite.",
        category="ransomware",
        confidence=0.9,
        evidence_summary="Evidence for the visual-deletion test.",
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


def _signal_with_generated_visual(db: Session, security_event, ai_response):
    service = SignalService(db)
    signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
    visual = SignalVisual(
        signal_id=signal.id, status=VisualStatus.GENERATED,
        url=f"/media/signals/{signal.id}.png", prompt_version="v2",
    )
    db.add(visual)
    db.commit()
    db.refresh(signal)
    return signal


class TestVisualDeletionRBAC:
    def test_unauthenticated_401(self, client, db: Session, security_event, ai_response):
        signal = _signal_with_generated_visual(db, security_event, ai_response)
        response = client.delete(f"/api/v1/signals/{signal.id}/visual")
        assert response.status_code == 401

    def test_viewer_cannot_delete_403(self, client, db: Session, security_event, ai_response):
        signal = _signal_with_generated_visual(db, security_event, ai_response)
        viewer = _make_user(db, "visdel_viewer", UserRole.VIEWER)
        response = client.delete(
            f"/api/v1/signals/{signal.id}/visual", headers={"Authorization": f"Bearer {_token(viewer)}"},
        )
        assert response.status_code == 403

    def test_reviewer_can_delete(self, client, db: Session, security_event, ai_response):
        signal = _signal_with_generated_visual(db, security_event, ai_response)
        reviewer = _make_user(db, "visdel_reviewer", UserRole.REVIEWER)
        response = client.delete(
            f"/api/v1/signals/{signal.id}/visual", headers={"Authorization": f"Bearer {_token(reviewer)}"},
        )
        assert response.status_code == 200
        assert response.json()["visual_status"] == "none"

    def test_admin_can_delete(self, client, db: Session, security_event, ai_response):
        signal = _signal_with_generated_visual(db, security_event, ai_response)
        admin = _make_user(db, "visdel_admin", UserRole.ADMIN)
        response = client.delete(
            f"/api/v1/signals/{signal.id}/visual", headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 200


class TestVisualDeletionSafety:
    def test_404_when_signal_does_not_exist(self, client, db: Session):
        admin = _make_user(db, "visdel_404_admin", UserRole.ADMIN)
        response = client.delete(
            "/api/v1/signals/00000000-0000-0000-0000-000000000000/visual",
            headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 404

    def test_400_when_signal_has_no_visual(self, client, db: Session, security_event, ai_response):
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        db.commit()
        admin = _make_user(db, "visdel_novisual_admin", UserRole.ADMIN)

        response = client.delete(
            f"/api/v1/signals/{signal.id}/visual", headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 400

    def test_deletion_never_deletes_the_signal_itself_or_its_categories_or_evidence(
        self, client, db: Session, security_event, ai_response
    ):
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        visual = SignalVisual(signal_id=signal.id, status=VisualStatus.GENERATED, url=f"/media/signals/{signal.id}.png")
        db.add(visual)
        db.commit()
        admin = _make_user(db, "visdel_safety_admin", UserRole.ADMIN)

        response = client.delete(
            f"/api/v1/signals/{signal.id}/visual", headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 200

        remaining = db.query(Signal).filter_by(id=signal.id).one()
        assert remaining.title == signal.title
        assert len(remaining.categories) == 1
        assert len(remaining.evidence) == 1
        assert db.query(SignalVisual).filter_by(signal_id=signal.id).one_or_none() is None

    def test_deletion_does_not_require_a_particular_lifecycle_status(
        self, client, db: Session, security_event, ai_response
    ):
        """Unlike content editing, visual deletion is allowed at any
        status - an inappropriate image on an already-PUBLISHED signal is
        exactly the case that most needs to be removable."""
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        service.submit_for_review(signal.id)
        admin = _make_user(db, "visdel_lifecycle_admin", UserRole.ADMIN)
        service.approve_signal(signal.id, reviewer_id=admin.id)
        service.publish_signal(signal.id, actor_id=admin.id)
        visual = SignalVisual(signal_id=signal.id, status=VisualStatus.GENERATED, url=f"/media/signals/{signal.id}.png")
        db.add(visual)
        db.commit()

        response = client.delete(
            f"/api/v1/signals/{signal.id}/visual", headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "published"


class TestVisualDeletionAudit:
    def test_deletion_writes_an_audit_entry(self, client, db: Session, security_event, ai_response):
        signal = _signal_with_generated_visual(db, security_event, ai_response)
        admin = _make_user(db, "visdel_audit_admin", UserRole.ADMIN)

        response = client.delete(
            f"/api/v1/signals/{signal.id}/visual", headers={"Authorization": f"Bearer {_token(admin)}"},
        )
        assert response.status_code == 200

        entry = (
            db.query(AuditLog)
            .filter_by(resource_type="SIGNAL", resource_id=signal.id, action="SIGNAL_VISUAL_DELETED")
            .one()
        )
        assert entry.user_id == admin.id
        assert entry.changes["title"] == signal.title
        assert entry.changes["visual_status"] == "generated"
