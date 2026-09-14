"""AI signal generation request schema."""

from typing import Optional, List
from pydantic import BaseModel, Field, field_validator


class AISignalGenerationRequest(BaseModel):
    """Request to generate a signal from a security event."""
    
    event_id: str = Field(..., description="SecurityEvent UUID")
    event_title: str = Field(..., min_length=1, max_length=500, description="Event title")
    event_description: str = Field(..., min_length=1, max_length=10000, description="Event description")
    article_titles: List[str] = Field(default_factory=list, description="Related article titles")
    article_summaries: List[str] = Field(default_factory=list, description="Related article summaries")
    
    @field_validator('event_id')
    @classmethod
    def validate_event_id(cls, v):
        """Validate UUID format."""
        if not v or len(v) < 8:
            raise ValueError("Invalid event_id")
        return v


class SecureDesignPrinciple(BaseModel):
    """Secure design principle mapping."""
    principle: str = Field(..., description="Principle name (e.g., 'Defense in Depth')")
    connection: str = Field(..., description="How signal relates to principle")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence 0-1")


class AISignalGenerationResponse(BaseModel):
    """AI-generated signal response with structured output."""
    
    signal_title: str = Field(..., min_length=5, max_length=200)
    signal_description: str = Field(..., min_length=20, max_length=5000)
    category: str = Field(..., description="SecurityCategoryType enum value")
    ai_subcategory: Optional[str] = Field(None, description="AISecuritySubcategory if AI_SECURITY")
    confidence: float = Field(ge=0.5, le=1.0, description="Signal confidence 0.5-1.0")
    evidence_summary: str = Field(..., min_length=10, max_length=2000, description="Grounded in source material")
    secure_design_principles: List[SecureDesignPrinciple] = Field(default_factory=list)
    
    @field_validator('category')
    @classmethod
    def validate_category(cls, v):
        """Validate against allowed categories."""
        allowed = {
            'vulnerability', 'cloud_security', 'iam', 'app_api', 'supply_chain',
            'data_privacy', 'ransomware', 'threat_intel', 'ai_security', 'infrastructure'
        }
        if v.lower() not in allowed:
            raise ValueError(f"Invalid category. Allowed: {allowed}")
        return v
    
    @field_validator('ai_subcategory')
    @classmethod
    def validate_ai_subcategory(cls, v, info):
        """If AI_SECURITY category, validate subcategory."""
        category = info.data.get('category', '').lower()
        if category == 'ai_security':
            allowed_ai = {
                'llm_vulnerability', 'agent_abuse', 'ai_data_leakage', 'model_poisoning',
                'ai_supply_chain', 'ai_infrastructure', 'ai_enabled_attacks', 'misaligned_ai_permissions'
            }
            if v is None or v.lower() not in allowed_ai:
                raise ValueError(f"AI_SECURITY requires valid ai_subcategory. Allowed: {allowed_ai}")
            return v
        elif v is not None:
            raise ValueError("ai_subcategory only valid for AI_SECURITY category")
        return v
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v):
        """Confidence must be high."""
        if v < 0.5:
            raise ValueError("Confidence must be >= 0.5")
        return v
