"""Integration tests for signal lifecycle audit logging."""
import pytest
from uuid import uuid4
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.db.models import SignalStatus, User, UserRole
from app.services.signal_service import SignalService
from app.repositories import AuditLogRepository
from app.intelligence.schemas.signal_request import AISignalGenerationResponse


@pytest.fixture
def admin_user(db: Session):
    """Create admin user for testing."""
    from app.db.models import User, UserRole
    from app.auth.password import hash_password
    
    user = User(
        username="audit_test_admin",
        email="audit_test_admin@test.local",
        role=UserRole.ADMIN,
        password_hash=hash_password("TestPassword123!"),
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def test_signal(db: Session, security_event, ai_response):
    """Create a test signal in DRAFT status."""
    service = SignalService(db)
    signal = service.create_signal_from_ai(
        event_id=security_event.id,
        ai_response=ai_response
    )
    
    # Add evidence (required for submit_for_review)
    service.add_evidence(
        signal_id=signal.id,
        source_url="https://example.com/advisory",
        source_title="Security Advisory",
        excerpt="Evidence of vulnerability"
    )
    db.commit()
    db.refresh(signal)
    return signal


@pytest.fixture
def ai_response():
    """Create test AI response."""
    return AISignalGenerationResponse(
        signal_title="Test Signal",
        signal_description="Comprehensive security signal description covering vulnerability analysis and remediation steps for system hardening.",
        category="insecure_design",
        confidence=0.8,
        evidence_summary="Evidence discovered in security audit.",
        secure_design_principles=[]
    )


class TestSignalAuditSubmitForReview:
    """Test audit logging for submit_for_review."""
    
    def test_submit_for_review_creates_audit_entry(self, db: Session, test_signal):
        """SIGNAL_SUBMITTED_FOR_REVIEW audit entry created when signal submitted."""
        service = SignalService(db)
        audit_repo = AuditLogRepository(db)
        
        initial_audit_count = len(audit_repo.get_by_resource("SIGNAL", test_signal.id))
        
        # Submit signal for review
        service.submit_for_review(test_signal.id)
        db.commit()
        
        # Verify audit entry created
        audit_logs = audit_repo.get_by_resource("SIGNAL", test_signal.id)
        assert len(audit_logs) > initial_audit_count
        
        latest_audit = audit_logs[-1]
        assert latest_audit.action == "SIGNAL_SUBMITTED_FOR_REVIEW"
        assert latest_audit.resource_type == "SIGNAL"
        assert latest_audit.resource_id == test_signal.id
        assert latest_audit.user_id is None
        assert latest_audit.changes is not None
        assert "status_from" in latest_audit.changes
        assert latest_audit.changes["status_from"] == SignalStatus.DRAFT.value


class TestSignalAuditApprove:
    """Test audit logging for approve_signal."""
    
    def test_approve_signal_creates_audit_entry(self, db: Session, test_signal, admin_user):
        """SIGNAL_APPROVED audit entry created when signal approved."""
        service = SignalService(db)
        audit_repo = AuditLogRepository(db)
        
        # Transition to IN_REVIEW
        service.submit_for_review(test_signal.id)
        db.commit()
        
        initial_audit_count = len(audit_repo.get_by_resource("SIGNAL", test_signal.id))
        
        # Approve signal
        service.approve_signal(test_signal.id, admin_user.id)
        db.commit()
        
        # Verify audit entry created
        audit_logs = audit_repo.get_by_resource("SIGNAL", test_signal.id)
        assert len(audit_logs) > initial_audit_count
        
        latest_audit = audit_logs[-1]
        assert latest_audit.action == "SIGNAL_APPROVED"
        assert latest_audit.resource_type == "SIGNAL"
        assert latest_audit.resource_id == test_signal.id
        assert latest_audit.user_id == admin_user.id
        assert latest_audit.changes is not None
        assert latest_audit.changes["status_from"] == SignalStatus.IN_REVIEW.value
        assert latest_audit.changes["status_to"] == SignalStatus.APPROVED.value


class TestSignalAuditReject:
    """Test audit logging for reject_signal."""
    
    def test_reject_signal_creates_audit_entry(self, db: Session, test_signal, admin_user):
        """SIGNAL_REJECTED audit entry created when signal rejected."""
        service = SignalService(db)
        audit_repo = AuditLogRepository(db)
        
        # Transition to IN_REVIEW
        service.submit_for_review(test_signal.id)
        db.commit()
        
        initial_audit_count = len(audit_repo.get_by_resource("SIGNAL", test_signal.id))
        
        # Reject signal
        service.reject_signal(test_signal.id, admin_user.id)
        db.commit()
        
        # Verify audit entry created
        audit_logs = audit_repo.get_by_resource("SIGNAL", test_signal.id)
        assert len(audit_logs) > initial_audit_count
        
        latest_audit = audit_logs[-1]
        assert latest_audit.action == "SIGNAL_REJECTED"
        assert latest_audit.resource_type == "SIGNAL"
        assert latest_audit.resource_id == test_signal.id
        assert latest_audit.user_id == admin_user.id
        assert latest_audit.changes["status_from"] == SignalStatus.IN_REVIEW.value
        assert latest_audit.changes["status_to"] == SignalStatus.REJECTED.value


class TestSignalAuditPublish:
    """Test audit logging for publish_signal."""
    
    def test_publish_signal_creates_audit_entry(self, db: Session, test_signal, admin_user):
        """SIGNAL_PUBLISHED audit entry created when signal published."""
        service = SignalService(db)
        audit_repo = AuditLogRepository(db)
        
        # Transition: DRAFT -> IN_REVIEW -> APPROVED
        service.submit_for_review(test_signal.id)
        db.commit()
        
        service.approve_signal(test_signal.id, admin_user.id)
        db.commit()
        
        initial_audit_count = len(audit_repo.get_by_resource("SIGNAL", test_signal.id))
        
        # Publish signal
        service.publish_signal(test_signal.id)
        db.commit()
        
        # Verify audit entry created
        audit_logs = audit_repo.get_by_resource("SIGNAL", test_signal.id)
        assert len(audit_logs) > initial_audit_count
        
        latest_audit = audit_logs[-1]
        assert latest_audit.action == "SIGNAL_PUBLISHED"
        assert latest_audit.resource_type == "SIGNAL"
        assert latest_audit.resource_id == test_signal.id
        assert latest_audit.user_id is None
        assert latest_audit.changes["status_from"] == SignalStatus.APPROVED.value
        assert latest_audit.changes["status_to"] == SignalStatus.PUBLISHED.value


class TestAuditTransactionIntegrity:
    """Test that audit and signal state changes are atomic."""
    
    def test_audit_failure_prevents_state_change_commit(self, db: Session, test_signal):
        """If audit creation fails, signal state change does not commit."""
        service = SignalService(db)
        audit_repo = AuditLogRepository(db)
        
        # Mock AuditLogRepository to simulate failure
        original_create = audit_repo.create
        
        def failing_create(**kwargs):
            raise Exception("Simulated audit creation failure")
        
        audit_repo.create = failing_create
        service.audit_repo.create = failing_create
        
        # Attempt submit_for_review (should fail at audit creation)
        try:
            service.submit_for_review(test_signal.id)
            db.commit()
        except Exception:
            db.rollback()
            pass
        
        # Verify signal status NOT changed (still DRAFT)
        signal = service.signal_repo.get_by_id(test_signal.id)
        assert signal.status == SignalStatus.DRAFT
