"""
Unit tests for Repository layer.

Tests repository logic using mocked SQLAlchemy sessions.
Does NOT require a database.

STATUS: COMPLETE - 26 executable test methods (database-independent)
"""

import pytest
from unittest.mock import Mock, MagicMock
from uuid import uuid4

from app.db.models import (
    Source, Article, SecurityEvent, Signal, Evidence, User, AuditLog,
    EventType, EventSeverity, SignalStatus, SourceType, UserRole
)
from app.repositories import (
    SourceRepository, ArticleRepository, SecurityEventRepository,
    SignalRepository, EvidenceRepository, UserRepository, AuditLogRepository
)
from app.common.errors import DatabaseError, UniqueConstraintError


@pytest.fixture
def mock_session():
    """Create a mocked SQLAlchemy session."""
    return MagicMock()


@pytest.fixture
def source_repo(mock_session):
    return SourceRepository(mock_session)


@pytest.fixture
def article_repo(mock_session):
    return ArticleRepository(mock_session)


@pytest.fixture
def event_repo(mock_session):
    return SecurityEventRepository(mock_session)


@pytest.fixture
def signal_repo(mock_session):
    return SignalRepository(mock_session)


@pytest.fixture
def evidence_repo(mock_session):
    return EvidenceRepository(mock_session)


@pytest.fixture
def user_repo(mock_session):
    return UserRepository(mock_session)


@pytest.fixture
def audit_repo(mock_session):
    return AuditLogRepository(mock_session)


class TestSourceRepository:
    """Test SourceRepository methods."""

    def test_repository_inherits_from_base(self, source_repo):
        """SourceRepository has BaseRepository methods."""
        assert hasattr(source_repo, 'create')
        assert hasattr(source_repo, 'get_by_id')
        assert hasattr(source_repo, 'get_all')
        assert hasattr(source_repo, 'update')
        assert hasattr(source_repo, 'delete')
        assert hasattr(source_repo, 'commit')
        assert hasattr(source_repo, 'rollback')

    def test_source_repo_has_get_by_name(self, source_repo):
        """SourceRepository has get_by_name method."""
        assert hasattr(source_repo, 'get_by_name')

    def test_source_repo_has_get_active_sources(self, source_repo):
        """SourceRepository has get_active_sources method."""
        assert hasattr(source_repo, 'get_active_sources')

    def test_source_create_calls_add(self, mock_session, source_repo):
        """Create calls session.add()."""
        source_repo.create(
            name="Test",
            source_type=SourceType.RSS,
            url="https://example.com"
        )
        mock_session.add.assert_called_once()

    def test_source_commit_calls_session_commit(self, mock_session, source_repo):
        """Commit calls session.commit()."""
        source_repo.commit()
        mock_session.commit.assert_called_once()


class TestArticleRepository:
    """Test ArticleRepository methods."""

    def test_article_repo_has_get_by_url(self, article_repo):
        """ArticleRepository has get_by_url method."""
        assert hasattr(article_repo, 'get_by_url')

    def test_article_repo_has_get_by_source_and_external_id(self, article_repo):
        """ArticleRepository has get_by_source_and_external_id method."""
        assert hasattr(article_repo, 'get_by_source_and_external_id')

    def test_article_repo_has_get_by_content_hash(self, article_repo):
        """ArticleRepository has get_by_content_hash method."""
        assert hasattr(article_repo, 'get_by_content_hash')

    def test_article_repo_has_get_relevant_articles(self, article_repo):
        """ArticleRepository has get_relevant_articles method."""
        assert hasattr(article_repo, 'get_relevant_articles')

    def test_article_repo_has_get_by_source(self, article_repo):
        """ArticleRepository has get_by_source method."""
        assert hasattr(article_repo, 'get_by_source')


class TestSecurityEventRepository:
    """Test SecurityEventRepository methods."""

    def test_event_repo_has_get_by_name(self, event_repo):
        """SecurityEventRepository has get_by_name method."""
        assert hasattr(event_repo, 'get_by_name')

    def test_event_repo_has_get_major_events(self, event_repo):
        """SecurityEventRepository has get_major_events method."""
        assert hasattr(event_repo, 'get_major_events')

    def test_event_repo_has_get_by_type(self, event_repo):
        """SecurityEventRepository has get_by_type method."""
        assert hasattr(event_repo, 'get_by_type')

    def test_event_repo_has_get_by_severity(self, event_repo):
        """SecurityEventRepository has get_by_severity method."""
        assert hasattr(event_repo, 'get_by_severity')

    def test_event_repo_has_add_article(self, event_repo):
        """SecurityEventRepository has add_article method."""
        assert hasattr(event_repo, 'add_article')


class TestSignalRepository:
    """Test SignalRepository methods."""

    def test_signal_repo_has_get_by_status(self, signal_repo):
        """SignalRepository has get_by_status method."""
        assert hasattr(signal_repo, 'get_by_status')

    def test_signal_repo_has_get_published(self, signal_repo):
        """SignalRepository has get_published method."""
        assert hasattr(signal_repo, 'get_published')

    def test_signal_repo_has_get_by_event(self, signal_repo):
        """SignalRepository has get_by_event method."""
        assert hasattr(signal_repo, 'get_by_event')

    def test_signal_repo_has_get_reviewed_by_user(self, signal_repo):
        """SignalRepository has get_reviewed_by_user method."""
        assert hasattr(signal_repo, 'get_reviewed_by_user')


class TestEvidenceRepository:
    """Test Evidence repository immutability enforcement."""

    def test_evidence_repo_blocks_update(self, evidence_repo):
        """EvidenceRepository.update() raises DatabaseError."""
        with pytest.raises(DatabaseError) as exc_info:
            evidence_repo.update(uuid4(), source_url="https://new.url")
        assert "immutable" in str(exc_info.value).lower()

    def test_evidence_repo_blocks_delete(self, evidence_repo):
        """EvidenceRepository.delete() raises DatabaseError."""
        with pytest.raises(DatabaseError) as exc_info:
            evidence_repo.delete(uuid4())
        assert "immutable" in str(exc_info.value).lower() or "cannot be deleted" in str(exc_info.value).lower()

    def test_evidence_repo_has_get_by_signal(self, evidence_repo):
        """EvidenceRepository has get_by_signal method."""
        assert hasattr(evidence_repo, 'get_by_signal')

    def test_evidence_repo_has_get_by_article(self, evidence_repo):
        """EvidenceRepository has get_by_article method."""
        assert hasattr(evidence_repo, 'get_by_article')


class TestAuditLogRepository:
    """Test AuditLog repository immutability enforcement."""

    def test_auditlog_repo_blocks_update(self, audit_repo):
        """AuditLogRepository.update() raises DatabaseError."""
        with pytest.raises(DatabaseError) as exc_info:
            audit_repo.update(uuid4(), action="NEW_ACTION")
        assert "immutable" in str(exc_info.value).lower()

    def test_auditlog_repo_blocks_delete(self, audit_repo):
        """AuditLogRepository.delete() raises DatabaseError."""
        with pytest.raises(DatabaseError) as exc_info:
            audit_repo.delete(uuid4())
        assert "immutable" in str(exc_info.value).lower() or "cannot be deleted" in str(exc_info.value).lower()

    def test_auditlog_repo_has_get_by_resource(self, audit_repo):
        """AuditLogRepository has get_by_resource method."""
        assert hasattr(audit_repo, 'get_by_resource')

    def test_auditlog_repo_has_get_by_user(self, audit_repo):
        """AuditLogRepository has get_by_user method."""
        assert hasattr(audit_repo, 'get_by_user')

    def test_auditlog_repo_has_get_by_action(self, audit_repo):
        """AuditLogRepository has get_by_action method."""
        assert hasattr(audit_repo, 'get_by_action')


class TestUserRepository:
    """Test UserRepository methods."""

    def test_user_repo_has_get_by_username(self, user_repo):
        """UserRepository has get_by_username method."""
        assert hasattr(user_repo, 'get_by_username')

    def test_user_repo_has_get_by_email(self, user_repo):
        """UserRepository has get_by_email method."""
        assert hasattr(user_repo, 'get_by_email')

    def test_user_repo_has_get_active_users(self, user_repo):
        """UserRepository has get_active_users method."""
        assert hasattr(user_repo, 'get_active_users')

    def test_user_repo_has_get_by_role(self, user_repo):
        """UserRepository has get_by_role method."""
        assert hasattr(user_repo, 'get_by_role')


class TestRepositoryErrorHandling:
    """Test repository error handling."""

    def test_base_repo_rollback_on_error(self, mock_session, source_repo):
        """Repository calls rollback on error."""
        mock_session.add.side_effect = Exception("Test error")
        try:
            source_repo.create(
                name="Test",
                source_type=SourceType.RSS,
                url="https://example.com"
            )
        except DatabaseError:
            pass
        mock_session.rollback.assert_called()

    def test_repository_has_session_attribute(self, mock_session, source_repo):
        """Repository stores session reference."""
        assert source_repo.session is not None

    def test_repository_has_model_class_attribute(self, source_repo):
        """Repository stores model class reference."""
        assert source_repo.model_class is not None
