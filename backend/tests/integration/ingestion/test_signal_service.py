"""Integration tests for signal service."""
import os
import pytest
from uuid import uuid4
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from app.db.models import Base, SecurityEvent, EventSeverity, EventType, SignalStatus, User, UserRole
from app.services.signal_service import SignalService
from app.intelligence.schemas.signal_request import (
    AISignalGenerationResponse, SecureDesignPrinciple
)
from tests.conftest import _USE_ALEMBIC_SCHEMA, _truncate_all_tables


@pytest.fixture(scope="function")
def test_session():
    """Create test session with proper cleanup between tests.

    Drops all tables before each test to ensure clean state.
    Follows the canonical pattern from tests/conftest.py.

    Respects TEST_DB_SCHEMA_SOURCE=alembic the same way the shared `db`
    fixture does: when set, schema comes from real migrations (established
    once per session), and this fixture only resets data between tests
    instead of dropping/recreating the schema via the ORM - otherwise it
    would silently wipe out the migrated schema for every other test still
    to run in the same session.
    """
    test_url = os.getenv("DATABASE_URL_TEST")
    if not test_url:
        pytest.skip("DATABASE_URL_TEST not set")

    if "_test" not in test_url:
        pytest.skip("Not a test database")

    engine = create_engine(test_url, echo=False)

    if _USE_ALEMBIC_SCHEMA:
        _truncate_all_tables(engine)
    else:
        # Drop all tables first (clean slate for this test)
        Base.metadata.drop_all(engine)

        # Create fresh tables
        Base.metadata.create_all(engine)

    session = Session(engine)
    yield session

    # Cleanup after test
    session.close()
    if not _USE_ALEMBIC_SCHEMA:
        Base.metadata.drop_all(engine)
    engine.dispose()


def test_create_signal_from_ai(test_session):
    """Create signal from AI response."""
    # Create test event
    event = SecurityEvent(
        name="Test Event",
        description="Test description",
        event_type=EventType.VULNERABILITY,
        severity=EventSeverity.HIGH,
    )
    test_session.add(event)
    test_session.commit()
  
    # Create AI response
    ai_response = AISignalGenerationResponse(
        signal_title="Signal",
        signal_description="This is a detailed security signal description about a critical vulnerability in the system.",
        category="vulnerability",
        confidence=0.8,
        evidence_summary="Evidence of compromise discovered in security audit.",
        secure_design_principles=[]
    )
    
    # Create signal
    service = SignalService(test_session)
    signal = service.create_signal_from_ai(event.id, ai_response)
    
    assert signal.id is not None
    assert signal.title == "Signal"
    assert signal.summary == "This is a detailed security signal description about a critical vulnerability in the system."
    assert signal.security_impact == "This is a detailed security signal description about a critical vulnerability in the system."
    assert signal.status == SignalStatus.DRAFT
    assert signal.reviewed_by is None


def test_get_published_signals(test_session):
    """Get published signals."""
    # Create admin user
    admin_user = User(
        username="test_admin",
        email="test_admin@example.com",
        role=UserRole.ADMIN,
        password_hash="test_password_hash",
        is_active=True
    )
    test_session.add(admin_user)
    test_session.commit()
    
    # Create event
    event = SecurityEvent(
        name="Event",
        description="Description",
        event_type=EventType.VULNERABILITY,
        severity=EventSeverity.MEDIUM,
    )
    test_session.add(event)
    test_session.commit()
    
    # Create signal
    service = SignalService(test_session)
    ai_response = AISignalGenerationResponse(
        signal_title="Signal",
        signal_description="Comprehensive security signal description covering vulnerability analysis and remediation steps for system hardening.",
        category="vulnerability",
        confidence=0.8,
        evidence_summary="Evidence discovered in security audit and vulnerability assessment.",
        secure_design_principles=[]
    )
    signal = service.create_signal_from_ai(event.id, ai_response)
    
    # Add evidence (required before submitting for review)
    service.add_evidence(
        signal_id=signal.id,
        source_url="https://example.com/advisory",
        source_title="Security Advisory",
        excerpt="Evidence of vulnerability confirmed"
    )
    
    # Transition: DRAFT -> IN_REVIEW
    signal = service.submit_for_review(signal.id)
    assert signal.status == SignalStatus.IN_REVIEW
    
    # Transition: IN_REVIEW -> APPROVED (using real admin_user)
    signal = service.approve_signal(signal.id, admin_user.id)
    assert signal.status == SignalStatus.APPROVED
    
    # Transition: APPROVED -> PUBLISHED
    signal = service.publish_signal(signal.id)
    assert signal.status == SignalStatus.PUBLISHED
    
    # Query published
    published = service.get_published_signals()

    assert len(published) == 1
    assert published[0].status == SignalStatus.PUBLISHED
