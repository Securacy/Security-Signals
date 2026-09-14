"""
Repository pattern for data access.

Repositories provide CRUD operations for each entity.
Abstracting database operations from business logic.

IMMUTABILITY ENFORCEMENT (Phase 2):
- Evidence and AuditLog repositories block UPDATE and DELETE operations.
- No database-level enforcement yet (deferred to Phase 6).

Unit tests mock these; integration tests use real database.
"""

from typing import Optional, List, Any
from uuid import UUID
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_
from sqlalchemy.exc import IntegrityError, NoResultFound

from app.db.models import (
    Source, Article, SecurityEvent, Signal, SignalCategory,
    Evidence, User, AuditLog, EventArticleMapping,
    EventType, EventSeverity, SignalStatus, SecurityCategoryType
)
from app.common.errors import (
    DatabaseError, NotFoundError, UniqueConstraintError
)
class BaseRepository:
    """Base repository with common CRUD operations."""

    def __init__(self, session: Session, model_class):
        self.session = session
        self.model_class = model_class

    def create(self, **kwargs) -> Any:
        """Create and save a new entity."""
        try:
            instance = self.model_class(**kwargs)
            self.session.add(instance)
            self.session.flush()  # Assign ID without commit
            return instance
        except IntegrityError as e:
            self.session.rollback()
            if "unique constraint" in str(e).lower():
                raise UniqueConstraintError(f"Unique constraint violation: {e}")
            raise DatabaseError(f"Database integrity error: {e}")
        except Exception as e:
            self.session.rollback()
            raise DatabaseError(f"Error creating {self.model_class.__name__}: {e}")

    def get_by_id(self, id: UUID) -> Optional[Any]:
        """Get entity by ID."""
        try:
            return self.session.query(self.model_class).filter(
                self.model_class.id == id
            ).one_or_none()
        except Exception as e:
            raise DatabaseError(f"Error fetching {self.model_class.__name__}: {e}")

    def get_all(self, skip: int = 0, limit: int = 100) -> List[Any]:
        """Get all entities with pagination."""
        try:
            return self.session.query(self.model_class).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching {self.model_class.__name__}: {e}")

    def update(self, id: UUID, **kwargs) -> Optional[Any]:
        """Update an entity."""
        try:
            instance = self.get_by_id(id)
            if not instance:
                return None
            
            for key, value in kwargs.items():
                if hasattr(instance, key):
                    setattr(instance, key, value)
            
            self.session.flush()
            return instance
        except IntegrityError as e:
            self.session.rollback()
            if "unique constraint" in str(e).lower():
                raise UniqueConstraintError(f"Unique constraint violation: {e}")
            raise DatabaseError(f"Database integrity error: {e}")
        except Exception as e:
            self.session.rollback()
            raise DatabaseError(f"Error updating {self.model_class.__name__}: {e}")

    def delete(self, id: UUID) -> bool:
        """Delete an entity."""
        try:
            instance = self.get_by_id(id)
            if not instance:
                return False
            self.session.delete(instance)
            self.session.flush()
            return True
        except Exception as e:
            self.session.rollback()
            raise DatabaseError(f"Error deleting {self.model_class.__name__}: {e}")

    def commit(self):
        """Commit session changes."""
        try:
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            raise DatabaseError(f"Error committing transaction: {e}")

    def rollback(self):
        """Rollback session changes."""
        self.session.rollback()


# ============================================================================
# SOURCE REPOSITORY
# ============================================================================

class SourceRepository(BaseRepository):
    """Repository for Source entities."""

    def __init__(self, session: Session):
        super().__init__(session, Source)

    def get_by_name(self, name: str) -> Optional[Source]:
        """Get source by name."""
        try:
            return self.session.query(Source).filter(Source.name == name).one_or_none()
        except Exception as e:
            raise DatabaseError(f"Error fetching source by name: {e}")

    def get_active_sources(self, skip: int = 0, limit: int = 100) -> List[Source]:
        """Get all active sources."""
        try:
            return self.session.query(Source).filter(
                Source.is_active == True
            ).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching active sources: {e}")


# ============================================================================
# ARTICLE REPOSITORY
# ============================================================================

class ArticleRepository(BaseRepository):
    """Repository for Article entities."""

    def __init__(self, session: Session):
        super().__init__(session, Article)

    def get_by_url(self, url: str) -> Optional[Article]:
        """Get article by URL."""
        try:
            return self.session.query(Article).filter(Article.url == url).one_or_none()
        except Exception as e:
            raise DatabaseError(f"Error fetching article by URL: {e}")

    def get_by_source_and_external_id(self, source_id: UUID, external_id: str) -> Optional[Article]:
        """Get article by source and external ID."""
        try:
            return self.session.query(Article).filter(
                and_(Article.source_id == source_id, Article.external_id == external_id)
            ).one_or_none()
        except Exception as e:
            raise DatabaseError(f"Error fetching article by source and external ID: {e}")

    def get_by_content_hash(self, content_hash: str) -> Optional[Article]:
        """Get article by content hash (deduplication)."""
        try:
            return self.session.query(Article).filter(
                Article.content_hash == content_hash
            ).one_or_none()
        except Exception as e:
            raise DatabaseError(f"Error fetching article by content hash: {e}")

    def get_relevant_articles(self, skip: int = 0, limit: int = 100) -> List[Article]:
        """Get articles marked as relevant."""
        try:
            return self.session.query(Article).filter(
                Article.is_relevant == True
            ).order_by(desc(Article.created_at)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching relevant articles: {e}")

    def get_by_source(self, source_id: UUID, skip: int = 0, limit: int = 100) -> List[Article]:
        """Get articles from a specific source."""
        try:
            return self.session.query(Article).filter(
                Article.source_id == source_id
            ).order_by(desc(Article.created_at)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching articles by source: {e}")


# ============================================================================
# SECURITY EVENT REPOSITORY
# ============================================================================

class SecurityEventRepository(BaseRepository):
    """Repository for SecurityEvent entities."""

    def __init__(self, session: Session):
        super().__init__(session, SecurityEvent)

    def get_by_name(self, name: str) -> Optional[SecurityEvent]:
        """Get event by name."""
        try:
            return self.session.query(SecurityEvent).filter(
                SecurityEvent.name == name
            ).one_or_none()
        except Exception as e:
            raise DatabaseError(f"Error fetching event by name: {e}")

    def get_major_events(self, skip: int = 0, limit: int = 100) -> List[SecurityEvent]:
        """Get major events."""
        try:
            return self.session.query(SecurityEvent).filter(
                SecurityEvent.is_major == True
            ).order_by(desc(SecurityEvent.created_at)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching major events: {e}")

    def get_by_type(self, event_type: EventType, skip: int = 0, limit: int = 100) -> List[SecurityEvent]:
        """Get events by type."""
        try:
            return self.session.query(SecurityEvent).filter(
                SecurityEvent.event_type == event_type
            ).order_by(desc(SecurityEvent.created_at)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching events by type: {e}")

    def get_by_severity(self, severity: EventSeverity, skip: int = 0, limit: int = 100) -> List[SecurityEvent]:
        """Get events by severity."""
        try:
            return self.session.query(SecurityEvent).filter(
                SecurityEvent.severity == severity
            ).order_by(desc(SecurityEvent.created_at)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching events by severity: {e}")

    def add_article(self, event_id: UUID, article_id: UUID):
        """Add article to event (many-to-many)."""
        try:
            mapping = EventArticleMapping(event_id=event_id, article_id=article_id)
            self.session.add(mapping)
            self.session.flush()
            return mapping
        except IntegrityError:
            # Already mapped
            pass
        except Exception as e:
            self.session.rollback()
            raise DatabaseError(f"Error adding article to event: {e}")


# ============================================================================
# SIGNAL REPOSITORY
# ============================================================================

class SignalRepository(BaseRepository):
    """Repository for Signal entities."""

    def __init__(self, session: Session):
        super().__init__(session, Signal)

    def get_by_status(self, status: SignalStatus, skip: int = 0, limit: int = 100) -> List[Signal]:
        """Get signals by status."""
        try:
            return self.session.query(Signal).filter(
                Signal.status == status
            ).order_by(desc(Signal.created_at)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching signals by status: {e}")

    def get_published(
        self,
        skip: int = 0,
        limit: int = 100,
        category: Optional[SecurityCategoryType] = None,
    ) -> List[Signal]:
        """Get published signals (public API), optionally filtered by category.

        `category` is optional and additive: omitting it preserves the
        original unfiltered behavior for any existing caller.
        """
        try:
            q = self.session.query(Signal).filter(Signal.status == SignalStatus.PUBLISHED)
            if category is not None:
                q = q.join(SignalCategory, SignalCategory.signal_id == Signal.id).filter(
                    SignalCategory.category == category
                )
            return q.order_by(desc(Signal.published_at)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching published signals: {e}")

    def get_by_event(self, event_id: UUID, skip: int = 0, limit: int = 100) -> List[Signal]:
        """Get signals for a specific event."""
        try:
            return self.session.query(Signal).filter(
                Signal.event_id == event_id
            ).order_by(desc(Signal.created_at)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching signals by event: {e}")

    def get_reviewed_by_user(self, user_id: UUID, skip: int = 0, limit: int = 100) -> List[Signal]:
        """Get signals reviewed by a specific user."""
        try:
            return self.session.query(Signal).filter(
                Signal.reviewed_by == user_id
            ).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching signals reviewed by user: {e}")


# ============================================================================
# SIGNAL CATEGORY REPOSITORY
# ============================================================================

class SignalCategoryRepository(BaseRepository):
    """Repository for SignalCategory entities."""

    def __init__(self, session: Session):
        super().__init__(session, SignalCategory)

    def get_by_signal(self, signal_id: UUID) -> List[SignalCategory]:
        """Get all categories for a signal."""
        try:
            return self.session.query(SignalCategory).filter(
                SignalCategory.signal_id == signal_id
            ).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching categories by signal: {e}")

    def get_by_signal_ids(self, signal_ids: List[UUID]) -> List[SignalCategory]:
        """Get categories for multiple signals in one query (avoids N+1 when
        rendering a list of signals, e.g. the public /published feed)."""
        if not signal_ids:
            return []
        try:
            return self.session.query(SignalCategory).filter(
                SignalCategory.signal_id.in_(signal_ids)
            ).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching categories by signal ids: {e}")

    def get_by_category_type(self, category: str, skip: int = 0, limit: int = 100) -> List[SignalCategory]:
        """Get categories by type."""
        try:
            return self.session.query(SignalCategory).filter(
                SignalCategory.category == category
            ).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching categories by type: {e}")


# ============================================================================
# EVIDENCE REPOSITORY (Immutable - Application Level)
# ============================================================================

class EvidenceRepository(BaseRepository):
    """
    Repository for Evidence entities.
    
    Evidence is logically immutable at application level (Phase 2).
    - No UPDATE operations allowed
    - No DELETE operations allowed (except via cascade)
    
    Database-level enforcement deferred to Phase 6 (triggers, role-based access).
    """

    def __init__(self, session: Session):
        super().__init__(session, Evidence)

    def get_by_signal(self, signal_id: UUID) -> List[Evidence]:
        """Get all evidence for a signal."""
        try:
            return self.session.query(Evidence).filter(
                Evidence.signal_id == signal_id
            ).order_by(Evidence.created_at).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching evidence by signal: {e}")

    def get_by_article(self, article_id: UUID) -> List[Evidence]:
        """Get evidence citations to a specific article."""
        try:
            return self.session.query(Evidence).filter(
                Evidence.article_id == article_id
            ).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching evidence by article: {e}")

    def update(self, id: UUID, **kwargs):
        """
        Override: Evidence is immutable (application-level enforcement).
        
        Phase 2: No updates allowed via repository.
        Phase 6: Add database-level triggers to prevent UPDATE.
        """
        raise DatabaseError(
            "Evidence records are immutable and cannot be updated. "
            "Create new Evidence record if source data changes."
        )

    def delete(self, id: UUID) -> bool:
        """
        Override: Evidence can only be deleted via Signal cascade.
        
        Phase 2: No direct deletes allowed via repository.
        Phase 6: Add database-level permissions to prevent DELETE.
        """
        raise DatabaseError(
            "Evidence records cannot be deleted directly. "
            "Delete the parent Signal to cascade-delete Evidence."
        )


# ============================================================================
# USER REPOSITORY
# ============================================================================

class UserRepository(BaseRepository):
    """
    Repository for User entities.
    
    Phase 2: Basic CRUD only. No password hashing, no authentication.
    Phase 6: Add password hashing, authentication logic, session management.
    """

    def __init__(self, session: Session):
        super().__init__(session, User)

    def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        try:
            return self.session.query(User).filter(User.username == username).one_or_none()
        except Exception as e:
            raise DatabaseError(f"Error fetching user by username: {e}")

    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        try:
            return self.session.query(User).filter(User.email == email).one_or_none()
        except Exception as e:
            raise DatabaseError(f"Error fetching user by email: {e}")

    def get_active_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """Get all active users."""
        try:
            return self.session.query(User).filter(
                User.is_active == True
            ).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching active users: {e}")

    def get_by_role(self, role: str, skip: int = 0, limit: int = 100) -> List[User]:
        """Get users by role."""
        try:
            return self.session.query(User).filter(User.role == role).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching users by role: {e}")


# ============================================================================
# AUDIT LOG REPOSITORY (Immutable - Application Level)
# ============================================================================

class AuditLogRepository(BaseRepository):
    """
    Repository for AuditLog entities.
    
    AuditLog is logically immutable at application level (Phase 2).
    - No UPDATE operations allowed
    - No DELETE operations allowed
    
    Database-level enforcement deferred to Phase 6 (triggers, role-based access).
    """

    def __init__(self, session: Session):
        super().__init__(session, AuditLog)

    def get_by_resource(self, resource_type: str, resource_id: UUID) -> List[AuditLog]:
        """Get audit trail for a specific resource."""
        try:
            return self.session.query(AuditLog).filter(
                and_(AuditLog.resource_type == resource_type, AuditLog.resource_id == resource_id)
            ).order_by(AuditLog.timestamp).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching audit log by resource: {e}")

    def get_by_user(self, user_id: UUID, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get audit trail for a specific user."""
        try:
            return self.session.query(AuditLog).filter(
                AuditLog.user_id == user_id
            ).order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching audit log by user: {e}")

    def get_by_action(self, action: str, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get audit entries by action type."""
        try:
            return self.session.query(AuditLog).filter(
                AuditLog.action == action
            ).order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error fetching audit log by action: {e}")

    def query(
        self,
        resource_type: Optional[str] = None,
        resource_id: Optional[UUID] = None,
        user_id: Optional[UUID] = None,
        action: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """Combined filtering for the admin audit API (all filters optional)."""
        try:
            q = self.session.query(AuditLog)
            if resource_type is not None:
                q = q.filter(AuditLog.resource_type == resource_type)
            if resource_id is not None:
                q = q.filter(AuditLog.resource_id == resource_id)
            if user_id is not None:
                q = q.filter(AuditLog.user_id == user_id)
            if action is not None:
                q = q.filter(AuditLog.action == action)
            return q.order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit).all()
        except Exception as e:
            raise DatabaseError(f"Error querying audit log: {e}")

    def update(self, id: UUID, **kwargs):
        """
        Override: AuditLog is immutable (application-level enforcement).
        
        Phase 2: No updates allowed via repository.
        Phase 6: Add database-level triggers to prevent UPDATE.
        """
        raise DatabaseError(
            "AuditLog records are immutable and cannot be updated."
        )

    def delete(self, id: UUID) -> bool:
        """
        Override: AuditLog cannot be deleted.
        
        Phase 2: No deletes allowed via repository.
        Phase 6: Add database-level permissions to prevent DELETE.
        """
        raise DatabaseError(
            "AuditLog records cannot be deleted. Audit trail is permanent."
        )
