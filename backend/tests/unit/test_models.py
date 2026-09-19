"""
Unit tests for SQLAlchemy model definitions and enums.

Tests model field definitions, enum values, and instantiation.
Does NOT require a database - tests ORM model structure directly.

STATUS: COMPLETE - 31 executable test methods (database-independent)
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone
from app.db.models import (
    Base, Source, Article, SecurityEvent, Signal, SignalCategory,
    Evidence, User, AuditLog, EventArticleMapping, utc_now,
    SourceType, EventType, EventSeverity, SignalStatus,
    SecurityCategoryType, AISecuritySubcategory, UserRole, AssignmentMethod
)


class TestSourceModel:
    """Test Source entity definition."""

    def test_source_fields_exist(self):
        """Source model has required fields."""
        assert hasattr(Source, 'id')
        assert hasattr(Source, 'name')
        assert hasattr(Source, 'source_type')
        assert hasattr(Source, 'url')
        assert hasattr(Source, 'is_active')
        assert hasattr(Source, 'config')
        assert hasattr(Source, 'created_at')
        assert hasattr(Source, 'updated_at')

    def test_source_instantiation(self):
        """Source can be instantiated."""
        source = Source(
            name="TestFeed",
            source_type=SourceType.RSS,
            url="https://example.com/feed"
        )
        assert source.name == "TestFeed"
        assert source.source_type == SourceType.RSS
        assert source.url == "https://example.com/feed"

    def test_source_has_articles_relationship(self):
        """Source has articles relationship."""
        assert hasattr(Source, 'articles')

    def test_source_repr(self):
        """Source __repr__ includes name."""
        source = Source(
            name="ReprTest",
            source_type=SourceType.RSS,
            url="https://example.com"
        )
        assert "ReprTest" in repr(source)


class TestArticleModel:
    """Test Article entity definition."""

    def test_article_fields_exist(self):
        """Article model has required fields."""
        assert hasattr(Article, 'id')
        assert hasattr(Article, 'source_id')
        assert hasattr(Article, 'url')
        assert hasattr(Article, 'title')
        assert hasattr(Article, 'content_hash')
        assert hasattr(Article, 'is_relevant')
        assert hasattr(Article, 'relevance_score')

    def test_article_instantiation(self):
        """Article can be instantiated."""
        article = Article(
            source_id=uuid4(),
            url="https://example.com/article",
            title="Security News",
            content_hash="a" * 64
        )
        assert article.url == "https://example.com/article"
        assert article.title == "Security News"

    def test_article_default_is_relevant(self):
        """Article is_relevant defaults to False."""
        article = Article(
            source_id=uuid4(),
            url="https://example.com/a",
            title="Title",
            content_hash="a" * 64
        )
        assert Article.__table__.c.is_relevant.default.arg is False
        assert Article.__table__.c.relevance_score.default.arg == 0.0

    def test_article_repr(self):
        """Article __repr__ includes URL."""
        article = Article(
            source_id=uuid4(),
            url="https://example.com/test",
            title="Title",
            content_hash="a" * 64
        )
        assert "example.com" in repr(article)


class TestSecurityEventModel:
    """Test SecurityEvent entity definition."""

    def test_event_fields_exist(self):
        """SecurityEvent model has required fields."""
        assert hasattr(SecurityEvent, 'id')
        assert hasattr(SecurityEvent, 'name')
        assert hasattr(SecurityEvent, 'description')
        assert hasattr(SecurityEvent, 'event_type')
        assert hasattr(SecurityEvent, 'severity')
        assert hasattr(SecurityEvent, 'is_major')

    def test_event_instantiation(self):
        """SecurityEvent can be instantiated."""
        event = SecurityEvent(
            name="CVE-2026-0001",
            description="Critical vulnerability",
            event_type=EventType.VULNERABILITY,
            severity=EventSeverity.CRITICAL
        )
        assert event.name == "CVE-2026-0001"
        assert event.event_type == EventType.VULNERABILITY
        assert event.severity == EventSeverity.CRITICAL

    def test_event_repr(self):
        """SecurityEvent __repr__ includes name."""
        event = SecurityEvent(
            name="TestEvent",
            description="D",
            event_type=EventType.VULNERABILITY,
            severity=EventSeverity.HIGH
        )
        assert "TestEvent" in repr(event)


class TestSignalModel:
    """Test Signal entity definition."""

    def test_signal_fields_exist(self):
        """Signal model has required fields."""
        assert hasattr(Signal, 'id')
        assert hasattr(Signal, 'event_id')
        assert hasattr(Signal, 'title')
        assert hasattr(Signal, 'summary')
        assert hasattr(Signal, 'security_impact')
        assert hasattr(Signal, 'principle')
        assert hasattr(Signal, 'recommended_action')
        assert hasattr(Signal, 'status')
        assert hasattr(Signal, 'reviewed_by')

    def test_signal_instantiation(self):
        """Signal can be instantiated."""
        signal = Signal(
            event_id=uuid4(),
            title="Patch Immediately",
            summary="Critical update required",
            security_impact="RCE possible",
            principle="Keep systems patched",
            recommended_action="Apply vendor patch"
        )
        assert signal.title == "Patch Immediately"
        assert Signal.__table__.c.status.default.arg == SignalStatus.DRAFT

    def test_signal_has_categories_relationship(self):
        """Signal has categories relationship."""
        assert hasattr(Signal, 'categories')

    def test_signal_has_evidence_relationship(self):
        """Signal has evidence relationship."""
        assert hasattr(Signal, 'evidence')

    def test_signal_repr(self):
        """Signal __repr__ includes title."""
        signal = Signal(
            event_id=uuid4(),
            title="Test Title",
            summary="S",
            security_impact="I",
            principle="P",
            recommended_action="A"
        )
        assert "Test Title" in repr(signal)


class TestSignalCategoryModel:
    """Test SignalCategory entity definition."""

    def test_category_fields_exist(self):
        """SignalCategory model has required fields."""
        assert hasattr(SignalCategory, 'id')
        assert hasattr(SignalCategory, 'signal_id')
        assert hasattr(SignalCategory, 'category')
        assert hasattr(SignalCategory, 'subcategory')
        assert hasattr(SignalCategory, 'confidence')
        assert hasattr(SignalCategory, 'assigned_by')

    def test_category_instantiation(self):
        """SignalCategory can be instantiated."""
        category = SignalCategory(
            signal_id=uuid4(),
            category=SecurityCategoryType.INSECURE_DESIGN,
            confidence=0.95,
            assigned_by=AssignmentMethod.AI
        )
        assert category.category == SecurityCategoryType.INSECURE_DESIGN
        assert category.confidence == 0.95

    def test_category_repr(self):
        """SignalCategory __repr__ includes category."""
        category = SignalCategory(
            signal_id=uuid4(),
            category=SecurityCategoryType.AI_SECURITY,
            assigned_by=AssignmentMethod.AI
        )
        assert "ai_security" in repr(category)


class TestEvidenceModel:
    """Test Evidence entity definition."""

    def test_evidence_fields_exist(self):
        """Evidence model has required fields."""
        assert hasattr(Evidence, 'id')
        assert hasattr(Evidence, 'signal_id')
        assert hasattr(Evidence, 'article_id')
        assert hasattr(Evidence, 'source_url')
        assert hasattr(Evidence, 'source_title')
        assert hasattr(Evidence, 'excerpt')
        assert hasattr(Evidence, 'created_at')

    def test_evidence_no_updated_at(self):
        """Evidence does NOT have updated_at (immutable)."""
        assert not hasattr(Evidence, 'updated_at')

    def test_evidence_instantiation(self):
        """Evidence can be instantiated."""
        evidence = Evidence(
            signal_id=uuid4(),
            article_id=None,
            source_url="https://example.com",
            source_title="Source",
            excerpt="Quote..."
        )
        assert evidence.source_url == "https://example.com"
        assert evidence.article_id is None

    def test_evidence_repr(self):
        """Evidence __repr__ includes URL."""
        evidence = Evidence(
            signal_id=uuid4(),
            article_id=None,
            source_url="https://example.com/test",
            source_title="Test",
            excerpt="Test"
        )
        assert "example.com" in repr(evidence)


class TestUserModel:
    """Test User entity definition."""

    def test_user_fields_exist(self):
        """User model has required fields."""
        assert hasattr(User, 'id')
        assert hasattr(User, 'username')
        assert hasattr(User, 'email')
        assert hasattr(User, 'role')
        assert hasattr(User, 'password_hash')
        assert hasattr(User, 'is_active')

    def test_user_instantiation(self):
        """User can be instantiated."""
        user = User(
            username="alice",
            email="alice@example.com",
            role=UserRole.REVIEWER,
            password_hash="hash"
        )
        assert user.username == "alice"
        assert user.role == UserRole.REVIEWER
        assert User.__table__.c.is_active.default.arg is True

    def test_user_repr(self):
        """User __repr__ includes username."""
        user = User(
            username="testuser",
            email="test@example.com",
            role=UserRole.REVIEWER,
            password_hash="hash"
        )
        assert "testuser" in repr(user)


class TestAuditLogModel:
    """Test AuditLog entity definition."""

    def test_auditlog_fields_exist(self):
        """AuditLog model has required fields."""
        assert hasattr(AuditLog, 'id')
        assert hasattr(AuditLog, 'user_id')
        assert hasattr(AuditLog, 'action')
        assert hasattr(AuditLog, 'resource_type')
        assert hasattr(AuditLog, 'resource_id')
        assert hasattr(AuditLog, 'timestamp')

    def test_auditlog_instantiation(self):
        """AuditLog can be instantiated."""
        audit = AuditLog(
            user_id=uuid4(),
            action="SIGNAL_APPROVED",
            resource_type="signal",
            resource_id=uuid4()
        )
        assert audit.action == "SIGNAL_APPROVED"

    def test_auditlog_repr(self):
        """AuditLog __repr__ includes action."""
        audit = AuditLog(
            user_id=uuid4(),
            action="TEST_ACTION",
            resource_type="test",
            resource_id=uuid4()
        )
        assert "TEST_ACTION" in repr(audit)


class TestEnumDefinitions:
    """Test all enum definitions."""

    def test_source_type_enum(self):
        """Test SourceType enum."""
        assert len(SourceType) == 3
        assert SourceType.RSS in SourceType
        assert SourceType.API in SourceType
        assert SourceType.WEBHOOK in SourceType

    def test_event_type_enum(self):
        """Test EventType enum (7 values)."""
        assert len(EventType) == 7
        assert EventType.VULNERABILITY in EventType
        assert EventType.BREACH in EventType

    def test_event_severity_enum(self):
        """Test EventSeverity enum (4 values)."""
        assert len(EventSeverity) == 4
        assert EventSeverity.CRITICAL in EventSeverity
        assert EventSeverity.HIGH in EventSeverity
        assert EventSeverity.MEDIUM in EventSeverity
        assert EventSeverity.LOW in EventSeverity

    def test_signal_status_enum(self):
        """Test SignalStatus enum (5 values)."""
        assert len(SignalStatus) == 5
        assert SignalStatus.DRAFT in SignalStatus
        assert SignalStatus.PUBLISHED in SignalStatus

    def test_security_category_enum(self):
        """Test SecurityCategoryType enum (10 values)."""
        assert len(SecurityCategoryType) == 10
        assert SecurityCategoryType.INSECURE_DESIGN in SecurityCategoryType
        assert SecurityCategoryType.AI_SECURITY in SecurityCategoryType

    def test_ai_security_subcategory_enum(self):
        """Test AISecuritySubcategory enum (8 values)."""
        assert len(AISecuritySubcategory) == 8
        assert AISecuritySubcategory.LLM_VULNERABILITY in AISecuritySubcategory
        assert AISecuritySubcategory.AGENT_ABUSE in AISecuritySubcategory

    def test_user_role_enum(self):
        """Test UserRole enum (3 values)."""
        assert len(UserRole) == 3
        assert UserRole.ADMIN in UserRole
        assert UserRole.REVIEWER in UserRole
        assert UserRole.VIEWER in UserRole

    def test_assignment_method_enum(self):
        """Test AssignmentMethod enum (3 values)."""
        assert len(AssignmentMethod) == 3
        assert AssignmentMethod.AI in AssignmentMethod
        assert AssignmentMethod.HUMAN in AssignmentMethod
        assert AssignmentMethod.HEURISTIC in AssignmentMethod


class TestUtilityFunctions:
    """Test utility functions."""

    def test_utc_now_is_timezone_aware(self):
        """utc_now() returns timezone-aware datetime."""
        now = utc_now()
        assert now.tzinfo is not None
        assert now.tzinfo == timezone.utc

    def test_utc_now_is_datetime(self):
        """utc_now() returns datetime object."""
        now = utc_now()
        assert isinstance(now, datetime)


class TestModelTableNames:
    """Test model table names are correct."""

    def test_source_tablename(self):
        """Source table is 'source'."""
        assert Source.__tablename__ == 'source'

    def test_article_tablename(self):
        """Article table is 'article'."""
        assert Article.__tablename__ == 'article'

    def test_security_event_tablename(self):
        """SecurityEvent table is 'security_event'."""
        assert SecurityEvent.__tablename__ == 'security_event'

    def test_signal_tablename(self):
        """Signal table is 'signal'."""
        assert Signal.__tablename__ == 'signal'

    def test_signal_category_tablename(self):
        """SignalCategory table is 'signal_category'."""
        assert SignalCategory.__tablename__ == 'signal_category'

    def test_evidence_tablename(self):
        """Evidence table is 'evidence'."""
        assert Evidence.__tablename__ == 'evidence'

    def test_user_tablename(self):
        """User table is 'user'."""
        assert User.__tablename__ == 'user'

    def test_auditlog_tablename(self):
        """AuditLog table is 'audit_log'."""
        assert AuditLog.__tablename__ == 'audit_log'


class TestBaseMetadata:
    """Test that Base metadata is properly configured."""

    def test_base_metadata_exists(self):
        """Base.metadata should exist."""
        assert Base.metadata is not None

    def test_all_models_in_metadata(self):
        """All models should be registered in Base.metadata."""
        table_names = {table.name for table in Base.metadata.tables.values()}
        expected_tables = {
            'source', 'article', 'security_event', 'event_article_mapping',
            'signal', 'signal_category', 'evidence', 'user', 'audit_log'
        }
        for table_name in expected_tables:
            assert table_name in table_names
