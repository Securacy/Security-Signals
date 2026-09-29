"""Integration tests for:
- GET /api/v1/signals/approved (admin-only "ready to publish" queue)
- The optional `reason` field on POST /api/v1/signals/{id}/reject
- The `categories` field on GET /api/v1/signals/draft and /approved (Review
  Queue slice - reuses the same category lookup list_published_signals
  already uses, see _categories_by_signal in app/api/routes/signals.py)
"""
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.db.models import User, UserRole
from app.auth.password import hash_password
from app.auth.tokens import create_access_token
from app.services.signal_service import SignalService
from app.repositories import AuditLogRepository
from app.intelligence.schemas.signal_request import AISignalGenerationResponse


@pytest.fixture
def ai_response():
    return AISignalGenerationResponse(
        signal_title="Test Signal For Approval Queue",
        signal_description="Comprehensive security signal description covering analysis and remediation steps.",
        category="insecure_design",
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


def _in_review_signal(db: Session, security_event, ai_response):
    service = SignalService(db)
    signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
    service.add_evidence(
        signal_id=signal.id, source_url="https://example.com", source_title="Title", excerpt="Excerpt"
    )
    service.submit_for_review(signal.id)
    db.commit()
    return signal


class TestListApprovedSignals:
    def test_admin_sees_approved_signals(self, client, db, security_event, ai_response):
        admin = _make_user(db, "approved_admin", UserRole.ADMIN)
        signal = _in_review_signal(db, security_event, ai_response)
        service = SignalService(db)
        service.approve_signal(signal.id, reviewer_id=admin.id)
        db.commit()

        response = client.get(
            "/api/v1/signals/approved", headers={"Authorization": f"Bearer {_token(admin)}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == str(signal.id)
        assert data[0]["status"] == "approved"

    def test_draft_and_in_review_signals_excluded(self, client, db, security_event, ai_response):
        admin = _make_user(db, "approved_admin2", UserRole.ADMIN)
        _in_review_signal(db, security_event, ai_response)  # stays IN_REVIEW, not approved

        response = client.get(
            "/api/v1/signals/approved", headers={"Authorization": f"Bearer {_token(admin)}"}
        )

        assert response.status_code == 200
        assert response.json() == []

    def test_reviewer_forbidden(self, client, db):
        reviewer = _make_user(db, "approved_reviewer", UserRole.REVIEWER)

        response = client.get(
            "/api/v1/signals/approved", headers={"Authorization": f"Bearer {_token(reviewer)}"}
        )

        assert response.status_code == 403

    def test_viewer_forbidden(self, client, db):
        viewer = _make_user(db, "approved_viewer", UserRole.VIEWER)

        response = client.get(
            "/api/v1/signals/approved", headers={"Authorization": f"Bearer {_token(viewer)}"}
        )

        assert response.status_code == 403

    def test_unauthenticated_rejected(self, client):
        response = client.get("/api/v1/signals/approved")
        assert response.status_code == 401


class TestRejectSignalReason:
    def test_reject_with_reason_recorded_on_audit_entry(self, client, db, security_event, ai_response):
        reviewer = _make_user(db, "reject_reason_reviewer", UserRole.REVIEWER)
        signal = _in_review_signal(db, security_event, ai_response)

        response = client.post(
            f"/api/v1/signals/{signal.id}/reject",
            json={"reason": "Evidence is stale and no longer verifiable."},
            headers={"Authorization": f"Bearer {_token(reviewer)}"},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "rejected"

        audit_repo = AuditLogRepository(db)
        entries = audit_repo.get_by_resource("SIGNAL", signal.id)
        latest = entries[-1]
        assert latest.action == "SIGNAL_REJECTED"
        assert latest.changes["reason"] == "Evidence is stale and no longer verifiable."

    def test_reject_without_body_still_works(self, client, db, security_event, ai_response):
        """Backward compatible: no request body at all is still accepted."""
        reviewer = _make_user(db, "reject_no_body_reviewer", UserRole.REVIEWER)
        signal = _in_review_signal(db, security_event, ai_response)

        response = client.post(
            f"/api/v1/signals/{signal.id}/reject",
            headers={"Authorization": f"Bearer {_token(reviewer)}"},
        )

        assert response.status_code == 200
        audit_repo = AuditLogRepository(db)
        latest = audit_repo.get_by_resource("SIGNAL", signal.id)[-1]
        assert latest.changes["reason"] is None


class TestReviewQueueCategoriesField:
    """The Review Queue needs to show each signal's category - /draft and
    /approved include the same `categories` shape /published already does."""

    def test_draft_list_includes_categories(self, client, db, security_event, ai_response):
        reviewer = _make_user(db, "categories_reviewer", UserRole.REVIEWER)
        signal = _in_review_signal(db, security_event, ai_response)

        response = client.get(
            "/api/v1/signals/draft", headers={"Authorization": f"Bearer {_token(reviewer)}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["categories"] == [
            {"id": data[0]["categories"][0]["id"], "category": "insecure_design", "subcategory": None}
        ]

    def test_approved_list_includes_categories(self, client, db, security_event, ai_response):
        admin = _make_user(db, "categories_admin", UserRole.ADMIN)
        signal = _in_review_signal(db, security_event, ai_response)
        service = SignalService(db)
        service.approve_signal(signal.id, reviewer_id=admin.id)
        db.commit()

        response = client.get(
            "/api/v1/signals/approved", headers={"Authorization": f"Bearer {_token(admin)}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["categories"][0]["category"] == "insecure_design"


class TestReviewListsExposeVisualState:
    """/draft and /approved report each signal's real SignalVisual state so
    the reviewer UI can show the image, "generating", or "unavailable" -
    read-only, never triggering generation."""

    def _draft(self, db, security_event, ai_response, title):
        service = SignalService(db)
        response = ai_response.model_copy(update={"signal_title": title})
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=response)
        service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
        db.commit()
        return signal

    def test_each_visual_status_is_reported_and_url_only_when_generated(self, client, db, security_event, ai_response):
        from app.db.models import SignalVisual, VisualStatus

        reviewer = _make_user(db, "visual_state_reviewer", UserRole.REVIEWER)
        legacy = self._draft(db, security_event, ai_response, "Legacy no visual")
        pending = self._draft(db, security_event, ai_response, "Pending visual")
        done = self._draft(db, security_event, ai_response, "Generated visual")
        failed = self._draft(db, security_event, ai_response, "Failed visual")
        db.add_all([
            SignalVisual(signal_id=pending.id, status=VisualStatus.PENDING),
            SignalVisual(signal_id=done.id, status=VisualStatus.GENERATED, url="/media/signals/done.png"),
            SignalVisual(signal_id=failed.id, status=VisualStatus.FAILED, error="boom"),
        ])
        db.commit()

        response = client.get("/api/v1/signals/draft", headers={"Authorization": f"Bearer {_token(reviewer)}"})

        assert response.status_code == 200
        by_id = {item["id"]: item for item in response.json()}
        assert by_id[str(legacy.id)]["visual_status"] == "none"
        assert by_id[str(legacy.id)]["visual_url"] is None
        assert by_id[str(pending.id)]["visual_status"] == "pending"
        assert by_id[str(pending.id)]["visual_url"] is None
        assert by_id[str(pending.id)]["visual_requested_at"] is not None
        assert by_id[str(done.id)]["visual_status"] == "generated"
        assert by_id[str(done.id)]["visual_url"] == "/media/signals/done.png"
        assert by_id[str(failed.id)]["visual_status"] == "failed"
        assert by_id[str(failed.id)]["visual_url"] is None  # never an image for a failed visual

    def test_listing_never_triggers_generation(self, client, db, security_event, ai_response):
        from app.db.models import SignalVisual

        reviewer = _make_user(db, "visual_readonly_reviewer", UserRole.REVIEWER)
        signal = self._draft(db, security_event, ai_response, "No side effects")

        client.get("/api/v1/signals/draft", headers={"Authorization": f"Bearer {_token(reviewer)}"})

        assert db.query(SignalVisual).filter_by(signal_id=signal.id).one_or_none() is None

    def test_approved_list_reports_visual_state_too(self, client, db, security_event, ai_response):
        from app.db.models import SignalVisual, VisualStatus

        admin = _make_user(db, "visual_state_admin", UserRole.ADMIN)
        signal = self._draft(db, security_event, ai_response, "Approved with visual")
        db.add(SignalVisual(signal_id=signal.id, status=VisualStatus.GENERATED, url="/media/signals/a.png"))
        service = SignalService(db)
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id, reviewer_id=admin.id)
        db.commit()

        response = client.get("/api/v1/signals/approved", headers={"Authorization": f"Bearer {_token(admin)}"})

        item = response.json()[0]
        assert item["visual_status"] == "generated" and item["visual_url"] == "/media/signals/a.png"


class TestAbandonedPendingVisualsAreRetryCandidates:
    def test_only_a_pending_row_older_than_the_stall_window_is_a_candidate(self, db, security_event, ai_response):
        from datetime import datetime, timedelta, timezone
        from app.db.models import SignalVisual, VisualStatus
        from app.intelligence.visual_service import PENDING_STALLED_AFTER_MINUTES, find_stale_visuals

        service = SignalService(db)
        fresh = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        old = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        db.add_all([
            SignalVisual(signal_id=fresh.id, status=VisualStatus.PENDING),
            SignalVisual(
                signal_id=old.id, status=VisualStatus.PENDING,
                created_at=datetime.now(timezone.utc) - timedelta(minutes=PENDING_STALLED_AFTER_MINUTES + 5),
            ),
        ])
        db.commit()

        candidate_ids = {v.signal_id for v in find_stale_visuals(db)}

        assert old.id in candidate_ids
        assert fresh.id not in candidate_ids


class TestSignalDetailEndpoint:
    """GET /api/v1/signals/{id} - full detail (evidence + categories +
    visual) for a signal in ANY status, for the admin review detail panel.
    REVIEWER/ADMIN only; never for VIEWER, who only ever sees published
    signals via the public endpoints."""

    def _draft_with_evidence(self, db, security_event, ai_response):
        service = SignalService(db)
        signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
        service.add_evidence(
            signal_id=signal.id, source_url="https://example.com/evidence-1",
            source_title="Evidence Source", excerpt="A grounded excerpt.",
        )
        db.commit()
        return signal

    def test_reviewer_sees_full_detail_for_a_draft_signal_including_evidence_and_categories(
        self, client, db, security_event, ai_response,
    ):
        reviewer = _make_user(db, "detail_reviewer", UserRole.REVIEWER)
        signal = self._draft_with_evidence(db, security_event, ai_response)

        response = client.get(f"/api/v1/signals/{signal.id}", headers={"Authorization": f"Bearer {_token(reviewer)}"})

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(signal.id)
        assert data["status"] == "draft"
        assert data["title"] == signal.title
        assert data["security_impact"] and data["principle"] and data["recommended_action"]
        assert len(data["evidence"]) == 1
        assert data["evidence"][0]["source_title"] == "Evidence Source"
        assert data["categories"][0]["category"] == "insecure_design"
        assert data["public_categories"] == ["product_security"]
        assert data["visual_status"] == "none"
        assert data["visual_url"] is None

    def test_admin_sees_full_detail_for_an_approved_signal(self, client, db, security_event, ai_response):
        admin = _make_user(db, "detail_admin", UserRole.ADMIN)
        signal = self._draft_with_evidence(db, security_event, ai_response)
        service = SignalService(db)
        service.submit_for_review(signal.id)
        service.approve_signal(signal.id, reviewer_id=admin.id)
        db.commit()

        response = client.get(f"/api/v1/signals/{signal.id}", headers={"Authorization": f"Bearer {_token(admin)}"})

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "approved"
        assert data["reviewed_by"] == str(admin.id)
        assert data["reviewed_at"] is not None

    def test_detail_reflects_a_real_generated_visual(self, client, db, security_event, ai_response):
        from app.db.models import SignalVisual, VisualStatus

        reviewer = _make_user(db, "detail_visual_reviewer", UserRole.REVIEWER)
        signal = self._draft_with_evidence(db, security_event, ai_response)
        db.add(SignalVisual(signal_id=signal.id, status=VisualStatus.GENERATED, url="/media/signals/x.png"))
        db.commit()

        response = client.get(f"/api/v1/signals/{signal.id}", headers={"Authorization": f"Bearer {_token(reviewer)}"})

        data = response.json()
        assert data["visual_status"] == "generated"
        assert data["visual_url"] == "/media/signals/x.png"

    def test_viewer_is_forbidden(self, client, db, security_event, ai_response):
        viewer = _make_user(db, "detail_viewer", UserRole.VIEWER)
        signal = self._draft_with_evidence(db, security_event, ai_response)

        response = client.get(f"/api/v1/signals/{signal.id}", headers={"Authorization": f"Bearer {_token(viewer)}"})

        assert response.status_code == 403

    def test_unauthenticated_is_rejected(self, client, db, security_event, ai_response):
        signal = self._draft_with_evidence(db, security_event, ai_response)
        assert client.get(f"/api/v1/signals/{signal.id}").status_code == 401

    def test_nonexistent_signal_is_404(self, client, db):
        reviewer = _make_user(db, "detail_404_reviewer", UserRole.REVIEWER)
        response = client.get(f"/api/v1/signals/{uuid4()}", headers={"Authorization": f"Bearer {_token(reviewer)}"})
        assert response.status_code == 404

    def test_malformed_id_is_400(self, client, db):
        reviewer = _make_user(db, "detail_400_reviewer", UserRole.REVIEWER)
        response = client.get("/api/v1/signals/not-a-uuid", headers={"Authorization": f"Bearer {_token(reviewer)}"})
        assert response.status_code == 400

    def test_the_catchall_route_never_shadows_the_literal_draft_approved_or_published_routes(
        self, client, db,
    ):
        """Route-ordering regression guard: /signals/{signal_id} is a
        catch-all and must be registered after the literal-path routes."""
        reviewer = _make_user(db, "route_order_reviewer", UserRole.REVIEWER)
        headers = {"Authorization": f"Bearer {_token(reviewer)}"}

        assert client.get("/api/v1/signals/draft", headers=headers).status_code == 200
        assert isinstance(client.get("/api/v1/signals/draft", headers=headers).json(), list)
        # /approved is admin-only - a reviewer must get a real 403 from
        # list_approved_signals, not a 400/404 from get_signal_detail
        # having wrongly claimed "approved" as a signal_id.
        assert client.get("/api/v1/signals/approved", headers=headers).status_code == 403
        assert client.get("/api/v1/signals/published").status_code == 200
        # /rejected must resolve to list_rejected_signals, never be
        # swallowed by the {signal_id} catch-all as a malformed UUID (400).
        assert client.get("/api/v1/signals/rejected", headers=headers).status_code == 200
        assert isinstance(client.get("/api/v1/signals/rejected", headers=headers).json(), list)


class TestListRejectedSignals:
    def test_reviewer_sees_rejected_signals(self, client, db, security_event, ai_response):
        reviewer = _make_user(db, "rejected_reviewer", UserRole.REVIEWER)
        signal = _in_review_signal(db, security_event, ai_response)
        service = SignalService(db)
        service.reject_signal(signal.id, reviewer_id=reviewer.id, reason="Evidence is stale")
        db.commit()

        response = client.get("/api/v1/signals/rejected", headers={"Authorization": f"Bearer {_token(reviewer)}"})

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == str(signal.id)
        assert data[0]["status"] == "rejected"

    def test_admin_also_sees_rejected_signals(self, client, db, security_event, ai_response):
        admin = _make_user(db, "rejected_admin", UserRole.ADMIN)
        signal = _in_review_signal(db, security_event, ai_response)
        service = SignalService(db)
        service.reject_signal(signal.id, reviewer_id=admin.id)
        db.commit()

        response = client.get("/api/v1/signals/rejected", headers={"Authorization": f"Bearer {_token(admin)}"})
        assert response.status_code == 200
        assert len(response.json()) == 1

    def test_other_statuses_excluded(self, client, db, security_event, ai_response):
        reviewer = _make_user(db, "rejected_reviewer2", UserRole.REVIEWER)
        _in_review_signal(db, security_event, ai_response)  # stays IN_REVIEW, never rejected

        response = client.get("/api/v1/signals/rejected", headers={"Authorization": f"Bearer {_token(reviewer)}"})
        assert response.status_code == 200
        assert response.json() == []

    def test_viewer_forbidden(self, client, db):
        viewer = _make_user(db, "rejected_viewer", UserRole.VIEWER)
        response = client.get("/api/v1/signals/rejected", headers={"Authorization": f"Bearer {_token(viewer)}"})
        assert response.status_code == 403

    def test_unauthenticated_rejected(self, client):
        response = client.get("/api/v1/signals/rejected")
        assert response.status_code == 401

    def test_rejected_list_includes_categories_and_reviewer(self, client, db, security_event, ai_response):
        reviewer = _make_user(db, "rejected_reviewer3", UserRole.REVIEWER)
        signal = _in_review_signal(db, security_event, ai_response)
        service = SignalService(db)
        service.reject_signal(signal.id, reviewer_id=reviewer.id, reason="Not credible")
        db.commit()

        response = client.get("/api/v1/signals/rejected", headers={"Authorization": f"Bearer {_token(reviewer)}"})
        data = response.json()[0]
        assert data["reviewed_by"] == str(reviewer.id)
        assert data["reviewed_at"] is not None
        assert isinstance(data["categories"], list)
