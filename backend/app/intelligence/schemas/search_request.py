"""Structured schema for AI-assisted natural-language search (Feature 3).

This is the ONLY thing the AI is allowed to produce for search: a bounded,
strictly-validated description of query intent. It is never SQL, never a
database query, never free-form text that gets executed - the application
builds the actual database query from these validated fields, and every
field the AI can influence is checked against a fixed, real allowlist
(the same SecurityCategoryType/AISecuritySubcategory enums signal
generation uses) before it ever reaches a query.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator

_ALLOWED_CATEGORIES = {
    'insecure_design', 'cloud_security', 'iam', 'app_api', 'supply_chain',
    'data_privacy', 'ransomware', 'threat_intel', 'ai_security', 'infrastructure',
}
_ALLOWED_SUBCATEGORIES = {
    'llm_vulnerability', 'agent_abuse', 'ai_data_leakage', 'model_poisoning',
    'ai_supply_chain', 'ai_infrastructure', 'ai_enabled_attacks', 'misaligned_ai_permissions',
}

_MAX_LIST_ITEMS = 8
_MAX_TERM_LENGTH = 80


def _clean_term_list(values: List[str]) -> List[str]:
    """Bound list length and per-item length - defense against an
    over-long or adversarially-large AI response consuming excessive
    downstream query-building work."""
    cleaned = [v.strip()[:_MAX_TERM_LENGTH] for v in values if v and v.strip()]
    return cleaned[:_MAX_LIST_ITEMS]


class SearchQueryUnderstanding(BaseModel):
    """AI's structured understanding of a natural-language search query.

    Never used as, or converted into, a raw database query - every field
    is a filter VALUE the application's own query-builder consumes after
    validation, never a query fragment or instruction.
    """

    intent: str = Field(..., min_length=1, max_length=200)
    categories: List[str] = Field(default_factory=list)
    subcategories: List[str] = Field(default_factory=list)
    keywords: List[str] = Field(default_factory=list)
    entities: List[str] = Field(default_factory=list)
    time_range: Optional[str] = Field(default=None, max_length=50)
    search_terms: List[str] = Field(default_factory=list)
    semantic_query: str = Field(..., min_length=1, max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator('categories')
    @classmethod
    def validate_categories(cls, v: List[str]) -> List[str]:
        cleaned = _clean_term_list(v)
        # Silently drop anything not in the real taxonomy rather than
        # rejecting the whole response - an AI hallucinating an extra,
        # invalid category value shouldn't break search; it just doesn't
        # get used as a filter.
        return [c for c in cleaned if c.lower() in _ALLOWED_CATEGORIES]

    @field_validator('subcategories')
    @classmethod
    def validate_subcategories(cls, v: List[str]) -> List[str]:
        cleaned = _clean_term_list(v)
        return [s for s in cleaned if s.lower() in _ALLOWED_SUBCATEGORIES]

    @field_validator('keywords', 'entities', 'search_terms')
    @classmethod
    def validate_term_lists(cls, v: List[str]) -> List[str]:
        return _clean_term_list(v)
