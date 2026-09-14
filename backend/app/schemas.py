"""
Pydantic schemas for request/response validation.

15 schemas covering:
- Entity creation schemas (CRUD input)
- Enum schemas (controlled vocabularies)
- Critical validation: taxonomy, confidence ranges, subcategory rules

IMMUTABILITY: Evidence and AuditLog have no update schemas (append-only).
AUTHENTICATION: User schema groundwork only (Phase 6 implements auth).
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from uuid import UUID
from datetime import datetime
from enum import Enum
from datetime import datetime
from typing import Optional, List
from uuid import UUID

class SignalOut(BaseModel):
    """Signal output schema."""
    id: UUID
    title: str
    status: str
    confidence: float
    published_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class SignalDetailOut(BaseModel):
    """Signal detail with categories and evidence."""
    id: UUID
    title: str
    description: str
    status: str
    confidence: float
    categories: List[dict] = []
    evidence: List[dict] = []
    published_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# ============================================================================
# ENUM SCHEMAS (Controlled Vocabularies)
# ============================================================================

class SourceTypeSchema(str, Enum):
    """Source type enumeration."""
    RSS = "rss"
    API = "api"
    WEBHOOK = "webhook"


class EventTypeSchema(str, Enum):
    """Security event type enumeration."""
    VULNERABILITY = "vulnerability"
    BREACH = "breach"
    THREAT = "threat"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    INCIDENT = "incident"
    DISCLOSURE = "disclosure"


class EventSeveritySchema(str, Enum):
    """Event severity level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SignalStatusSchema(str, Enum):
    """Signal lifecycle status."""
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    PUBLISHED = "published"


class SecurityCategorySchema(str, Enum):
    """Security domain taxonomy (10 categories)."""
    VULNERABILITY = "vulnerability"
    CLOUD_SECURITY = "cloud_security"
    IAM = "iam"
    APP_API = "app_api"
    SUPPLY_CHAIN = "supply_chain"
    DATA_PRIVACY = "data_privacy"
    RANSOMWARE = "ransomware"
    THREAT_INTEL = "threat_intel"
    AI_SECURITY = "ai_security"
    INFRASTRUCTURE = "infrastructure"


class AISecuritySubcategorySchema(str, Enum):
    """AI Security-specific subcategories (8 values, only valid with AI_SECURITY)."""
    LLM_VULNERABILITY = "llm_vulnerability"
    AGENT_ABUSE = "agent_abuse"
    AI_DATA_LEAKAGE = "ai_data_leakage"
    MODEL_POISONING = "model_poisoning"
    AI_SUPPLY_CHAIN = "ai_supply_chain"
    AI_INFRASTRUCTURE = "ai_infrastructure"
    AI_ENABLED_ATTACKS = "ai_enabled_attacks"
    MISALIGNED_AI_PERMISSIONS = "misaligned_ai_permissions"


class UserRoleSchema(str, Enum):
    """User authorization role."""
    ADMIN = "admin"
    REVIEWER = "reviewer"
    VIEWER = "viewer"


class AssignmentMethodSchema(str, Enum):
    """How category was assigned."""
    AI = "ai"
    HUMAN = "human"
    HEURISTIC = "heuristic"


# ============================================================================
# ENTITY CREATION SCHEMAS
# ============================================================================

class SourceCreateSchema(BaseModel):
    """Schema for creating a source."""
    name: str
    source_type: SourceTypeSchema
    url: str
    is_active: bool = True
    config: Optional[dict] = None


class ArticleCreateSchema(BaseModel):
    """Schema for creating an article."""
    source_id: UUID
    external_id: Optional[str] = None
    url: str
    title: str
    description: Optional[str] = None
    content: Optional[str] = None
    author: Optional[str] = None
    published_at: Optional[datetime] = None
    content_hash: str = Field(..., min_length=64, max_length=64)
    is_relevant: bool = False
    relevance_score: float = 0.0


class SecurityEventCreateSchema(BaseModel):
    """Schema for creating a security event."""
    name: str
    description: str
    event_type: EventTypeSchema
    severity: EventSeveritySchema
    is_major: bool = False
    detected_at: Optional[datetime] = None


class SignalCategoryCreateSchema(BaseModel):
    """
    Schema for creating a signal category.
    
    CRITICAL VALIDATION:
    - Subcategory only valid with AI_SECURITY category
    - Subcategory must be from AISecuritySubcategorySchema if provided with AI_SECURITY
    - Confidence must be 0.0-1.0
    """
    category: SecurityCategorySchema
    subcategory: Optional[str] = None
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    assigned_by: AssignmentMethodSchema

    @field_validator('subcategory')
    def validate_subcategory(cls, v, info):
        """
        Validate subcategory:
        1. If category != AI_SECURITY and subcategory is set → Error
        2. If category == AI_SECURITY and subcategory is set → must be valid AI subcategory
        """
        category = info.data.get('category')
        
        if v is None:
            return v
        
        # Subcategory only valid with AI_SECURITY
        if category != SecurityCategorySchema.AI_SECURITY:
            raise ValueError(f"Subcategory '{v}' can only be used with AI_SECURITY category")
        
        # If AI_SECURITY, subcategory must be valid
        valid_subcategories = {
            "llm_vulnerability",
            "agent_abuse",
            "ai_data_leakage",
            "model_poisoning",
            "ai_supply_chain",
            "ai_infrastructure",
            "ai_enabled_attacks",
            "misaligned_ai_permissions"
        }
        
        if v not in valid_subcategories:
            raise ValueError(f"'{v}' is not a valid AI security subcategory")
        
        return v


class EvidenceCreateSchema(BaseModel):
    """Schema for creating evidence (immutable)."""
    signal_id: UUID
    article_id: Optional[UUID] = None
    source_url: str
    source_title: str
    excerpt: str


class SignalCreateSchema(BaseModel):
    """Schema for creating a signal."""
    event_id: UUID
    title: str
    summary: str
    security_impact: str
    principle: str
    recommended_action: str
    reviewed_by: Optional[UUID] = None


class UserCreateSchema(BaseModel):
    """Schema for creating a user (Phase 2 groundwork)."""
    username: str
    email: str
    role: UserRoleSchema
    password_hash: str
    is_active: bool = True


# ============================================================================
# RESPONSE SCHEMAS (Optional - Phase 3+)
# ============================================================================

class SourceResponseSchema(BaseModel):
    """Schema for source in API response."""
    id: UUID
    name: str
    source_type: SourceTypeSchema
    url: str
    is_active: bool
    created_at: datetime


class UserResponseSchema(BaseModel):
    """
    Schema for user in API response.
    Note: Does NOT include password_hash.
    """
    id: UUID
    username: str
    email: str
    role: UserRoleSchema
    is_active: bool
    created_at: datetime
# Phase 6: Authentication Schemas

class LoginRequestSchema(BaseModel):
    """Schema for login request."""
    username: str
    password: str


class TokenSchema(BaseModel):
    """Schema for JWT token response."""
    access_token: str
    token_type: str = "bearer"


class AuthUserSchema(BaseModel):
    """Schema for user in authentication response."""
    id: UUID
    username: str
    email: str
    role: UserRoleSchema
    is_active: bool


class LoginResponseSchema(BaseModel):
    """Schema for login response."""
    access_token: str
    token_type: str = "bearer"
    user: AuthUserSchema
