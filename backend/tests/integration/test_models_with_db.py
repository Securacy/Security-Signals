"""
Integration tests: Full model CRUD with PostgreSQL.

Tests complete workflows including relationships, constraints, and
integrity checks using a DISPOSABLE PostgreSQL test database.

WARNING: This test will DROP ALL TABLES in the database specified by DATABASE_URL_TEST.
         NEVER use with a production or development database.
         Use only with a dedicated, disposable test database.

STATUS: COMPLETE - 10 executable integration tests
        Tests SKIP if:
        - DATABASE_URL_TEST is not set
        - PostgreSQL is not available
        - DATABASE_URL (non-test) is set instead of DATABASE_URL_TEST
"""

import os
import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone
from uuid import uuid4

from app.db.models import Base, Source, Article, SecurityEvent, Signal, Evidence, User, AuditLog
from app.db.models import SourceType, EventType, EventSeverity, SignalStatus, UserRole, SecurityCategoryType, AssignmentMethod, SignalCategory
from tests.conftest import _USE_ALEMBIC_SCHEMA, _truncate_all_tables

# Validate test database configuration
def _validate_test_db_config():
    """Ensure test database is explicitly configured, not production."""
    test_url = os.getenv("DATABASE_URL_TEST")
    dev_url = os.getenv("DATABASE_URL")
    
    # Must have DATABASE_URL_TEST set
    if not test_url:
        return False, "DATABASE_URL_TEST not set"
    
    # Must be PostgreSQL
    if "postgresql" not in test_url:
        return False, "DATABASE_URL_TEST does not point to PostgreSQL"
    
    # If DATABASE_URL is also set, validate they are different
    if dev_url and dev_url == test_url:
        return False, "DATABASE_URL_TEST must differ from DATABASE_URL (use dedicated test database)"
    
    return True, None


# Skip entire module if test database not properly configured
_is_configured, _reason = _validate_test_db_config()
pytestmark = pytest.mark.skipif(
    not _is_configured,
    reason=_reason or "Test database not configured"
)


@pytest.fixture(scope="function")
def postgres_session():
    """
    Create PostgreSQL session and clean up after each test.

    WARNING: This fixture uses DATABASE_URL_TEST which should point to
             a dedicated, disposable test database only.
             It will DROP ALL TABLES (unless TEST_DB_SCHEMA_SOURCE=alembic,
             see tests/conftest.py - in that mode it only resets data, so it
             doesn't silently replace the migrated schema with an
             ORM-built one for whatever other tests run afterward in the
             same session).
    """
    test_url = os.getenv("DATABASE_URL_TEST")
    engine = sa.create_engine(test_url)

    if _USE_ALEMBIC_SCHEMA:
        _truncate_all_tables(engine)
    else:
        # Drop all tables (DISPOSABLE TEST DATABASE ONLY)
        Base.metadata.drop_all(engine)

        # Create all tables
        Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    yield session
    
    session.close()
    engine.dispose()


class TestModelsWithPostgreSQL:
    """Test models with real PostgreSQL database."""

    def test_source_article_relationship(self, postgres_session):
        """Test Source.articles relationship with real PostgreSQL."""
        source = Source(
            name="TestSource",
            source_type=SourceType.RSS,
            url="https://example.com/feed"
        )
        article = Article(
            source_id=source.id,
            url="https://example.com/article",
            title="Test Article",
            content_hash="a" * 64
        )
        source.articles.append(article)
        postgres_session.add(source)
        postgres_session.commit()
        
        retrieved_source = postgres_session.query(Source).filter_by(name="TestSource").one()
        assert len(retrieved_source.articles) == 1
        assert retrieved_source.articles[0].title == "Test Article"

    def test_event_article_many_to_many(self, postgres_session):
        """Test many-to-many relationship between SecurityEvent and Article."""
        source = Source(
            name="S",
            source_type=SourceType.RSS,
            url="https://example.com"
        )
        postgres_session.add(source)
        postgres_session.flush()  # Generate source.id before using it
        
        article1 = Article(
            source_id=source.id,
            url="https://example.com/1",
            title="Article 1",
            content_hash="a" * 64
        )
        article2 = Article(
            source_id=source.id,
            url="https://example.com/2",
            title="Article 2",
            content_hash="b" * 64
        )
        event = SecurityEvent(
            name="CVE-001",
            description="Test",
            event_type=EventType.VULNERABILITY,
            severity=EventSeverity.HIGH
        )
        event.articles.append(article1)
        event.articles.append(article2)
        
        postgres_session.add(event)
        postgres_session.commit()
        
        retrieved_event = postgres_session.query(SecurityEvent).filter_by(name="CVE-001").one()
        assert len(retrieved_event.articles) == 2

    def test_signal_cascade_delete(self, postgres_session):
        """Test that deleting Signal cascades to SignalCategory and Evidence."""
        event = SecurityEvent(
            name="E",
            description="D",
            event_type=EventType.VULNERABILITY,
            severity=EventSeverity.HIGH
        )
        postgres_session.add(event)
        postgres_session.flush()  # Generate event.id before using it
        
        signal = Signal(
            event_id=event.id,
            title="T",
            summary="S",
            security_impact="I",
            principle="P",
            recommended_action="A"
        )
        postgres_session.add(signal)
        postgres_session.flush()  # Generate signal.id before using it
        
        category = SignalCategory(
            signal_id=signal.id,
            category=SecurityCategoryType.INSECURE_DESIGN,
            assigned_by=AssignmentMethod.AI
        )
        evidence = Evidence(
            signal_id=signal.id,
            article_id=None,
            source_url="https://example.com",
            source_title="Test",
            excerpt="Test"
        )
        
        postgres_session.add(category)
        postgres_session.add(evidence)
        postgres_session.commit()
        
        signal_id = signal.id
        category_id = category.id
        evidence_id = evidence.id
        
        # Delete signal
        postgres_session.delete(signal)
        postgres_session.commit()
        
        # Verify cascade deleted category and evidence
        assert postgres_session.query(SignalCategory).filter_by(id=category_id).one_or_none() is None
        assert postgres_session.query(Evidence).filter_by(id=evidence_id).one_or_none() is None

    def test_signal_restrict_on_event_delete(self, postgres_session):
        """Test that Cannot delete SecurityEvent if signals exist (RESTRICT)."""
        event = SecurityEvent(
            name="E",
            description="D",
            event_type=EventType.VULNERABILITY,
            severity=EventSeverity.HIGH
        )
        postgres_session.add(event)
        postgres_session.flush()  # Generate event.id before using it
        
        signal = Signal(
            event_id=event.id,
            title="T",
            summary="S",
            security_impact="I",
            principle="P",
            recommended_action="A"
        )
        
        postgres_session.add(signal)
        postgres_session.commit()
        
        # Try to delete event - should raise
        postgres_session.delete(event)
        with pytest.raises(sa.exc.IntegrityError):
            postgres_session.commit()

    def test_article_unique_constraint_violation(self, postgres_session):
        """Test that duplicate article URLs fail with unique constraint."""
        source = Source(
            name="S",
            source_type=SourceType.RSS,
            url="https://example.com"
        )
        article1 = Article(
            source_id=source.id,
            url="https://example.com/same",
            title="Article 1",
            content_hash="a" * 64
        )
        article2 = Article(
            source_id=source.id,
            url="https://example.com/same",
            title="Article 2",
            content_hash="b" * 64
        )
        
        postgres_session.add(source)
        postgres_session.add(article1)
        postgres_session.add(article2)
        
        with pytest.raises(sa.exc.IntegrityError):
            postgres_session.commit()

    def test_timezone_aware_timestamps(self, postgres_session):
        """Test that timestamps are stored with timezone in PostgreSQL."""
        source = Source(
            name="TZ",
            source_type=SourceType.RSS,
            url="https://example.com"
        )
        postgres_session.add(source)
        postgres_session.commit()
        
        retrieved = postgres_session.query(Source).filter_by(name="TZ").one()
        assert retrieved.created_at.tzinfo is not None
        assert retrieved.created_at.tzinfo == timezone.utc

    def test_json_config_storage(self, postgres_session):
        """Test that Source.config stores JSON correctly."""
        config = {"retry": 5, "headers": {"Authorization": "Bearer token"}}
        source = Source(
            name="JSON",
            source_type=SourceType.API,
            url="https://example.com",
            config=config
        )
        postgres_session.add(source)
        postgres_session.commit()
        
        retrieved = postgres_session.query(Source).filter_by(name="JSON").one()
        assert retrieved.config == config
        assert retrieved.config["retry"] == 5

    def test_enum_validation(self, postgres_session):
        """Test that SQLAlchemy Enum validates at DB level."""
        event = SecurityEvent(
            name="E",
            description="D",
            event_type=EventType.VULNERABILITY,
            severity=EventSeverity.HIGH
        )
        postgres_session.add(event)
        postgres_session.commit()
        
        retrieved = postgres_session.query(SecurityEvent).filter_by(name="E").one()
        assert retrieved.event_type == EventType.VULNERABILITY
        assert retrieved.severity == EventSeverity.HIGH

    def test_user_set_null_on_signal_delete(self, postgres_session):
        """Test that Signal.reviewed_by → SET NULL when User deleted."""
        user = User(
            username="reviewer",
            email="rev@example.com",
            role=UserRole.REVIEWER,
            password_hash="hash"
        )
        postgres_session.add(user)
        postgres_session.flush()  # Generate user.id before using it
        
        event = SecurityEvent(
            name="E",
            description="D",
            event_type=EventType.VULNERABILITY,
            severity=EventSeverity.HIGH
        )
        postgres_session.add(event)
        postgres_session.flush()  # Generate event.id before using it
        
        signal = Signal(
            event_id=event.id,
            reviewed_by=user.id,
            title="T",
            summary="S",
            security_impact="I",
            principle="P",
            recommended_action="A"
        )
        
        postgres_session.add(signal)
        postgres_session.commit()
        
        signal_id = signal.id
        
        # Delete user
        postgres_session.delete(user)
        postgres_session.commit()
        
        # Verify signal.reviewed_by is NULL
        retrieved_signal = postgres_session.query(Signal).filter_by(id=signal_id).one()
        assert retrieved_signal.reviewed_by is None

