"""
SQLAlchemy ORM models for Security Signals.
9 core entities: Source, Article, SecurityEvent, EventArticleMapping, Signal, 
SignalCategory, Evidence, User, AuditLog.

All models use UUID primary keys and timezone-aware timestamps.
Trust boundary: External content marked as untrusted.
Provenance: Evidence table is canonical source of truth.

IMMUTABILITY NOTE (Evidence & AuditLog):
- Evidence and AuditLog are logically immutable at application layer.
- No UPDATE or DELETE operations via repositories.
- Database-level enforcement (triggers, constraints) deferred to Phase 6.
"""

from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import (
    Column, String, Text, Boolean, Float, DateTime, JSON, Index,
    ForeignKey, UniqueConstraint, Enum as SQLEnum, event
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import enum

Base = declarative_base()


# ============================================================================
# UTILITY
# ============================================================================

def utc_now() -> datetime:
    """Get current UTC time with timezone info."""
    return datetime.now(timezone.utc)


# ============================================================================
# ENUMS (Controlled Taxonomies)
# ============================================================================

class SourceType(str, enum.Enum):
    """Source type enumeration."""
    RSS = "rss"
    API = "api"
    WEBHOOK = "webhook"


class EventType(str, enum.Enum):
    """Security event type enumeration."""
    VULNERABILITY = "vulnerability"
    BREACH = "breach"
    THREAT = "threat"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    INCIDENT = "incident"
    DISCLOSURE = "disclosure"


class EventSeverity(str, enum.Enum):
    """Event severity level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SignalStatus(str, enum.Enum):
    """Signal lifecycle status."""
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    PUBLISHED = "published"


class SecurityCategoryType(str, enum.Enum):
    """Security domain taxonomy.

    Security Signals is a threat-modeling platform: categories answer "what
    security domain or design concern does this event belong to", not "is
    this technically a vulnerability". INSECURE_DESIGN replaced the former
    VULNERABILITY category (see migration 012) - a vulnerability may still
    be described inside a signal's content, but "vulnerability" alone was
    not a useful threat-modeling domain. A design/architecture flaw (broken
    trust boundary, insecure auth architecture, fail-open behavior, unsafe
    multi-tenant isolation, etc.) belongs here; a pure implementation defect
    with no design-level lesson (e.g. a memory-safety bug in a library)
    belongs under the domain that library serves (typically INFRASTRUCTURE
    or APP_API).
    """
    INSECURE_DESIGN = "insecure_design"
    CLOUD_SECURITY = "cloud_security"
    IAM = "iam"
    APP_API = "app_api"
    SUPPLY_CHAIN = "supply_chain"
    DATA_PRIVACY = "data_privacy"
    RANSOMWARE = "ransomware"
    THREAT_INTEL = "threat_intel"
    AI_SECURITY = "ai_security"
    INFRASTRUCTURE = "infrastructure"


class AISecuritySubcategory(str, enum.Enum):
    """AI Security-specific subcategories (only valid with AI_SECURITY category)."""
    LLM_VULNERABILITY = "llm_vulnerability"
    AGENT_ABUSE = "agent_abuse"
    AI_DATA_LEAKAGE = "ai_data_leakage"
    MODEL_POISONING = "model_poisoning"
    AI_SUPPLY_CHAIN = "ai_supply_chain"
    AI_INFRASTRUCTURE = "ai_infrastructure"
    AI_ENABLED_ATTACKS = "ai_enabled_attacks"
    MISALIGNED_AI_PERMISSIONS = "misaligned_ai_permissions"


class UserRole(str, enum.Enum):
    """User authorization role."""
    ADMIN = "admin"
    REVIEWER = "reviewer"
    VIEWER = "viewer"


class AssignmentMethod(str, enum.Enum):
    """How category was assigned."""
    AI = "ai"
    HUMAN = "human"
    HEURISTIC = "heuristic"


# ============================================================================
# ENTITY 1: SOURCE
# ============================================================================

class Source(Base):
    """
    RSS feeds, APIs, webhooks, and other external security news sources.
    
    One source has many articles. A broken source should not stop
    the entire ingestion pipeline.
    
    CASCADE: Articles cannot be deleted when source exists (RESTRICT).
    """
    __tablename__ = "source"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Identity
    name = Column(String(255), nullable=False, unique=True, index=True)
    source_type = Column(SQLEnum(SourceType), nullable=False)
    url = Column(String(2048), nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    
    # Configuration (retry policy, headers, timeout, etc.)
    config = Column(JSON, nullable=True)
    
    # Tracking
    last_ingested_at = Column(DateTime(timezone=True), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    
    # Relationships
    # NOTE: No cascade on articles since FK is RESTRICT.
    # Deleting Source raises error if articles exist.
    articles = relationship(
        "Article",
        back_populates="source"
    )
    
    def __repr__(self):
        return f"<Source {self.name}>"


# ============================================================================
# ENTITY 2: ARTICLE
# ============================================================================

class Article(Base):
    """
    Raw, untrusted ingested content from external sources.
    
    Articles are grouped into SecurityEvents. Multiple articles
    (from different sources) may refer to the same underlying incident.
    
    Content is stored as-is for provenance and audit trail.
    Trust boundary: All fields are UNTRUSTED external data.
    
    CASCADE: Deleting Source raises error (RESTRICT). Article persists.
    """
    __tablename__ = "article"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Foreign key to source
    source_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("source.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )
    
    # Source-specific identifier
    external_id = Column(String(500), nullable=True)
    
    # Content (UNTRUSTED)
    url = Column(String(2048), nullable=False, unique=True, index=True)
    canonical_url = Column(String(2048), nullable=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    content = Column(Text, nullable=True)
    author = Column(String(255), nullable=True)
    
    # Timing
    published_at = Column(DateTime(timezone=True), nullable=True, index=True)
    ingested_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    
    # Deduplication
    content_hash = Column(String(64), nullable=False, index=True)  # SHA256
    
    # Relevance (set during processing)
    is_relevant = Column(Boolean, default=False, index=True)
    relevance_score = Column(Float, default=0.0)
    
    # Audit
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    
    # Relationships
    source = relationship("Source", back_populates="articles")
    events = relationship(
        "SecurityEvent",
        secondary="event_article_mapping",
        back_populates="articles"
    )
    evidence = relationship(
        "Evidence",
        back_populates="article",
        cascade="all, delete-orphan"
    )
    
    # Constraints
    __table_args__ = (
        UniqueConstraint("source_id", "external_id", name="uq_article_source_external"),
        Index("ix_article_source_hash", "source_id", "content_hash"),
        Index("ix_article_relevance", "is_relevant", "created_at"),
    )
    
    def __repr__(self):
        return f"<Article {self.url[:50]}>"


# ============================================================================
# ENTITY 3: SECURITY_EVENT
# ============================================================================

class SecurityEvent(Base):
    """
    Grouped security incident or disclosure.
    
    Multiple articles from different sources may all report on the same
    underlying event (e.g., CVE disclosure, breach, incident).
    This table represents the grouped, deduplicated event.
    
    One event generates one or more signals.
    
    CASCADE: Signals cannot be deleted when event exists (RESTRICT).
    """
    __tablename__ = "security_event"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Identity
    name = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    
    # Classification
    event_type = Column(SQLEnum(EventType), nullable=False, index=True)
    severity = Column(SQLEnum(EventSeverity), nullable=False, index=True)
    
    # Detection
    is_major = Column(Boolean, default=False, index=True)
    detected_at = Column(DateTime(timezone=True), nullable=True)
    
    # Audit
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    
    # Relationships
    # NOTE: No cascade on signals since FK is RESTRICT.
    # Deleting SecurityEvent raises error if signals exist.
    articles = relationship(
        "Article",
        secondary="event_article_mapping",
        back_populates="events"
    )
    signals = relationship(
        "Signal",
        back_populates="event"
    )
    
    # Constraints
    __table_args__ = (
        Index("ix_event_major_type", "is_major", "event_type"),
        Index("ix_event_created", "created_at"),
    )
    
    def __repr__(self):
        return f"<SecurityEvent {self.name}>"


# ============================================================================
# ENTITY 4: EVENT_ARTICLE_MAPPING
# ============================================================================

class EventArticleMapping(Base):
    """
    Many-to-many mapping between SecurityEvents and Articles.
    
    One event can have multiple source articles.
    One article can belong to multiple events.
    
    CASCADE: When Event or Article deleted, mapping is deleted.
    """
    __tablename__ = "event_article_mapping"

    event_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("security_event.id", ondelete="CASCADE"),
        primary_key=True
    )
    article_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("article.id", ondelete="CASCADE"),
        primary_key=True,
        index=True
    )
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


# ============================================================================
# ENTITY 5: SIGNAL
# ============================================================================

class Signal(Base):
    """
    AI-generated, human-reviewed security insight derived from a SecurityEvent.
    
    A signal transforms raw security data into actionable, structured
    intelligence. Signals have a lifecycle: DRAFT → IN_REVIEW → APPROVED/REJECTED → PUBLISHED.
    
    Provenance: Evidence records are the CANONICAL source. No Signal.sources JSON.
    Authentication: Only placeholders in Phase 2. Phase 6 implements auth.
    
    CASCADE: 
    - Signals cannot be deleted when event exists (RESTRICT).
    - Categories and Evidence deleted with Signal (CASCADE).
    - Reviewer (User) deleted: Signal.reviewed_by → SET NULL.
    """
    __tablename__ = "signal"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Foreign keys
    event_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("security_event.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )
    reviewed_by = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    
    # Lifecycle
    status = Column(SQLEnum(SignalStatus), nullable=False, default=SignalStatus.DRAFT, index=True)
    
    # Content (TRUSTED, generated by AI or humans)
    title = Column(String(500), nullable=False)
    summary = Column(Text, nullable=False)
    security_impact = Column(Text, nullable=False)
    principle = Column(String(500), nullable=False)
    recommended_action = Column(Text, nullable=False)
    
    # NOTE: Signal.sources is NOT stored here.
    # Evidence records are the canonical provenance source.
    
    # Timing
    ai_generated_at = Column(DateTime(timezone=True), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    published_at = Column(DateTime(timezone=True), nullable=True, index=True)

    # Current-feed visibility (migration 013): a PUBLISHED signal starts
    # is_current=True. It is set False ONLY as a side effect of a NEWER
    # signal being published in the same category beyond the configured
    # retention count (SignalService.publish_signal /
    # app.ingestion.freshness_policy.FreshnessPolicy.max_current_signals_per_category)
    # - never deleted, never retired by a standalone job, and never retired
    # just because no new data arrived. The public API's "published" feed
    # filters on is_current=True; historical rows remain queryable for
    # audit/analytics/dedup via status alone.
    is_current = Column(Boolean, nullable=False, default=True, server_default="true", index=True)

    # Audit
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    
    # Relationships
    event = relationship("SecurityEvent", back_populates="signals")
    reviewer = relationship("User", back_populates="reviewed_signals")
    categories = relationship(
        "SignalCategory",
        back_populates="signal",
        cascade="all, delete-orphan"
    )
    evidence = relationship(
        "Evidence",
        back_populates="signal",
        cascade="all, delete-orphan"
    )
    visual = relationship(
        "SignalVisual",
        back_populates="signal",
        uselist=False,
        cascade="all, delete-orphan",
    )

    # Constraints
    __table_args__ = (
        Index("ix_signal_status_published", "status", "published_at"),
        Index("ix_signal_created", "created_at"),
    )
    
    def __repr__(self):
        return f"<Signal {self.title[:50]}>"


# ============================================================================
# ENTITY 6: SIGNAL_CATEGORY
# ============================================================================

class SignalCategory(Base):
    """
    Taxonomy classification for a signal.
    
    One signal can have multiple categories (tags).
    Categories use controlled vocabulary: SecurityCategoryType enum.
    Subcategories only valid for specific categories (e.g., AI_SECURITY has AI-specific subcategories).
    
    CASCADE: Deleted with Signal (part of signal).
    """
    __tablename__ = "signal_category"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Foreign key
    signal_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("signal.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Classification (CONTROLLED TAXONOMY)
    category = Column(SQLEnum(SecurityCategoryType), nullable=False, index=True)
    subcategory = Column(String(100), nullable=True)  # E.g., "llm_vulnerability"
    confidence = Column(Float, nullable=False, default=1.0)
    assigned_by = Column(SQLEnum(AssignmentMethod), nullable=False)
    
    # Audit
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    
    # Relationships
    signal = relationship("Signal", back_populates="categories")
    
    # Constraints
    __table_args__ = (
        Index("ix_category_signal", "signal_id", "category"),
    )
    
    def __repr__(self):
        return f"<SignalCategory {self.category.value}>"


# ============================================================================
# ENTITY 7: EVIDENCE (Logically Immutable)
# ============================================================================

class Evidence(Base):
    """
    Canonical provenance and source citation for a signal.
    
    IMMUTABILITY (Application-Level - Phase 2):
    - Evidence is append-only and cannot be updated or deleted.
    - No UPDATE or DELETE operations via repository layer.
    - No updated_at column (immutable by design).
    
    FUTURE ENFORCEMENT (Phase 6):
    - Database-level triggers to prevent UPDATE
    - Role-based access control to prevent DELETE
    - Audit logging of access attempts
    
    Each signal must be backed by one or more evidence records.
    
    Evidence can reference:
    - An Article (ingested external content), OR
    - Manual research (article_id=NULL)
    
    The excerpt field contains the exact quote/fact from the source.
    This preserves what was actually claimed and allows verification.
    
    CASCADE: Deleted with Signal.
    """
    __tablename__ = "evidence"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Foreign keys
    signal_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("signal.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    article_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("article.id", ondelete="CASCADE"),
        nullable=True,  # Can reference article or manual research
        index=True
    )
    
    # Source reference
    source_url = Column(String(2048), nullable=False)
    source_title = Column(String(500), nullable=False)
    excerpt = Column(Text, nullable=False)  # The actual quote/fact
    
    # NOTE: No updated_at. Evidence is immutable.
    # Audit
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    
    # Relationships
    signal = relationship("Signal", back_populates="evidence")
    article = relationship("Article", back_populates="evidence")
    
    def __repr__(self):
        return f"<Evidence {self.source_url[:50]}>"


# ============================================================================
# ENTITY 7b: SIGNAL_VISUAL
# ============================================================================

class VisualStatus(str, enum.Enum):
    """Lifecycle of a signal's AI-generated, signal-specific visual."""
    PENDING = "pending"
    GENERATED = "generated"
    FAILED = "failed"


class SignalVisual(Base):
    """
    AI-generated, signal-specific threat visualization - exactly one per
    Signal (never shared/reused between signals or across a category).

    This is NOT the same thing as a category icon: category icons are
    small, static, reusable SVGs rendered entirely in the frontend (see
    frontend/src/widget/publicTaxonomy.tsx). A SignalVisual is a unique
    image generated from THIS signal's own real content
    (title/summary/security_impact/principle/recommended_action), produced
    once (see ThreatVisualService.generate_for_signal, invoked from
    SignalService.publish_signal) and persisted so every later view reuses
    the same file - never regenerated on a normal page load.

    Lifecycle: PENDING (row exists, generation not yet attempted or in
    flight) -> GENERATED (file persisted, url set, generated_at set) or
    FAILED (generation was attempted and did not succeed). Image-generation
    failure never blocks or is blocked by signal publication - the row is
    created best-effort after a signal is already published; the frontend
    falls back to a category-based static visual whenever status is
    anything other than GENERATED.

    CASCADE: deleted with Signal (part of signal, like Evidence/SignalCategory).
    """
    __tablename__ = "signal_visual"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)

    signal_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("signal.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # exactly one visual per signal
        index=True,
    )

    status = Column(SQLEnum(VisualStatus), nullable=False, default=VisualStatus.PENDING, index=True)
    url = Column(String(1000), nullable=True)  # relative path (e.g. /media/signals/<id>.png) once generated
    prompt_version = Column(String(50), nullable=False, default="v1")
    error = Column(Text, nullable=True)  # last failure reason - never a secret, see ThreatVisualService

    generated_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    signal = relationship("Signal", back_populates="visual", uselist=False)

    def __repr__(self):
        return f"<SignalVisual {self.status.value} signal_id={self.signal_id}>"


# ============================================================================
# ENTITY 8: USER (Groundwork for Phase 6)
# ============================================================================

class User(Base):
    """
    Admin, reviewer, or viewer user.
    
    Phase 2: Groundwork only. User model created, roles defined.
    - No password hashing implementation
    - No authentication logic
    - password_hash is placeholder string (Phase 6 adds bcrypt/argon2)
    
    Phase 6: Implement authentication, authorization, password hashing.
    """
    __tablename__ = "user"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Identity
    username = Column(String(255), nullable=False, unique=True, index=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    role = Column(SQLEnum(UserRole), nullable=False)
    
    # Authentication (placeholder, no implementation in Phase 2)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    
    # Audit
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    reviewed_signals = relationship("Signal", back_populates="reviewer")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    def __repr__(self):
        return f"<User {self.username}>"


# ============================================================================
# ENTITY 9: AUDIT_LOG (Logically Immutable)
# ============================================================================

class AuditLog(Base):
    """
    Immutable audit trail of all important state transitions.
    
    IMMUTABILITY (Application-Level - Phase 2):
    - Audit logs are append-only and cannot be updated or deleted.
    - No UPDATE or DELETE operations via repository layer.
    
    FUTURE ENFORCEMENT (Phase 6):
    - Database-level triggers to prevent UPDATE
    - Role-based access control to prevent DELETE
    
    Records:
    - Who performed the action (user_id, nullable for system actions)
    - What action occurred (e.g., SIGNAL_APPROVED, SIGNAL_PUBLISHED)
    - What resource was affected (resource_type, resource_id)
    - Before/after state changes (JSON)
    - When it happened (timestamp)
    
    Enables full traceability and compliance.
    
    CASCADE: User deleted → audit_log.user_id SET NULL (keep trail).
    """
    __tablename__ = "audit_log"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Foreign key (nullable for system-initiated actions)
    user_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    
    # Action details
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=False, index=True)
    resource_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    
    # Change tracking
    changes = Column(JSON, nullable=True)
    
    # Audit
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    # Constraints
    __table_args__ = (
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )
    
    def __repr__(self):
        return f"<AuditLog {self.action}>"
