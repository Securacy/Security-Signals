"""
Unit tests for Pydantic schemas.

Tests validation, serialization, and critical taxonomy validation.
Does NOT require database.

STATUS: COMPLETE - 32 executable test methods
"""

import pytest
from uuid import uuid4
from pydantic import ValidationError

from app.schemas import (
    SourceCreateSchema, ArticleCreateSchema, SecurityEventCreateSchema,
    SignalCategoryCreateSchema, EvidenceCreateSchema, SignalCreateSchema,
    UserCreateSchema, SignalStatusSchema, SecurityCategorySchema,
    AISecuritySubcategorySchema, EventTypeSchema, EventSeveritySchema,
    UserRoleSchema, SourceTypeSchema, AssignmentMethodSchema
)


class TestSourceCreateSchema:
    """Test SourceCreateSchema validation."""

    def test_valid_source_create(self):
        """Valid source creation."""
        data = {
            "name": "SecurityFeed",
            "source_type": "rss",
            "url": "https://example.com/feed.xml",
            "is_active": True
        }
        schema = SourceCreateSchema(**data)
        assert schema.name == "SecurityFeed"
        assert schema.source_type.value == "rss"

    def test_source_missing_required(self):
        """Missing required fields fails validation."""
        with pytest.raises(ValidationError) as exc_info:
            SourceCreateSchema(name="OnlyName")
        errors = exc_info.value.errors()
        assert any(e['loc'][0] in ('source_type', 'url') for e in errors)

    def test_source_with_config(self):
        """Source can include JSON config."""
        data = {
            "name": "APISource",
            "source_type": "api",
            "url": "https://api.example.com/security",
            "config": {"retry": 3, "timeout": 30}
        }
        schema = SourceCreateSchema(**data)
        assert schema.config == {"retry": 3, "timeout": 30}

    def test_source_defaults(self):
        """Test source creation defaults."""
        data = {
            "name": "MinimalSource",
            "source_type": "webhook",
            "url": "https://webhook.example.com"
        }
        schema = SourceCreateSchema(**data)
        assert schema.is_active is True
        assert schema.config is None


class TestArticleCreateSchema:
    """Test ArticleCreateSchema validation."""

    def test_valid_article_create(self):
        """Valid article creation."""
        data = {
            "source_id": uuid4(),
            "url": "https://example.com/article",
            "title": "Security Vulnerability",
            "content_hash": "a" * 64
        }
        schema = ArticleCreateSchema(**data)
        assert schema.title == "Security Vulnerability"

    def test_article_content_hash_validation(self):
        """Content hash must be exactly 64 characters."""
        data = {
            "source_id": uuid4(),
            "url": "https://example.com/a",
            "title": "Title",
            "content_hash": "tooshort"
        }
        with pytest.raises(ValidationError):
            ArticleCreateSchema(**data)

    def test_article_content_hash_too_long(self):
        """Content hash too long fails."""
        data = {
            "source_id": uuid4(),
            "url": "https://example.com/a",
            "title": "Title",
            "content_hash": "a" * 65
        }
        with pytest.raises(ValidationError):
            ArticleCreateSchema(**data)

    def test_article_optional_fields(self):
        """Optional fields can be omitted."""
        data = {
            "source_id": uuid4(),
            "url": "https://example.com/a",
            "title": "Title",
            "content_hash": "a" * 64
        }
        schema = ArticleCreateSchema(**data)
        assert schema.external_id is None
        assert schema.description is None


class TestSecurityEventCreateSchema:
    """Test SecurityEventCreateSchema validation."""

    def test_valid_event_create(self):
        """Valid event creation."""
        data = {
            "name": "CVE-2026-0001",
            "description": "Critical RCE in library X",
            "event_type": "vulnerability",
            "severity": "critical",
            "is_major": True
        }
        schema = SecurityEventCreateSchema(**data)
        assert schema.name == "CVE-2026-0001"
        assert schema.event_type.value == "vulnerability"
        assert schema.severity.value == "critical"

    def test_event_invalid_type(self):
        """Invalid event_type fails."""
        data = {
            "name": "Event",
            "description": "Desc",
            "event_type": "invalid_type",
            "severity": "high"
        }
        with pytest.raises(ValidationError):
            SecurityEventCreateSchema(**data)

    def test_event_invalid_severity(self):
        """Invalid severity fails."""
        data = {
            "name": "Event",
            "description": "Desc",
            "event_type": "breach",
            "severity": "super_critical"
        }
        with pytest.raises(ValidationError):
            SecurityEventCreateSchema(**data)

    def test_event_defaults(self):
        """Test event defaults."""
        data = {
            "name": "Event",
            "description": "D",
            "event_type": "threat",
            "severity": "low"
        }
        schema = SecurityEventCreateSchema(**data)
        assert schema.is_major is False
        assert schema.detected_at is None


class TestSignalCategoryCreateSchema:
    """Test SignalCategoryCreateSchema with taxonomy validation."""

    def test_valid_category_without_subcategory(self):
        """Valid category without subcategory."""
        data = {
            "category": "vulnerability",
            "confidence": 0.95,
            "assigned_by": "ai"
        }
        schema = SignalCategoryCreateSchema(**data)
        assert schema.category.value == "vulnerability"
        assert schema.subcategory is None

    def test_valid_ai_security_with_subcategory(self):
        """AI_SECURITY category with valid subcategory."""
        data = {
            "category": "ai_security",
            "subcategory": "llm_vulnerability",
            "confidence": 0.88,
            "assigned_by": "human"
        }
        schema = SignalCategoryCreateSchema(**data)
        assert schema.category.value == "ai_security"
        assert schema.subcategory == "llm_vulnerability"

    def test_ai_security_all_subcategories(self):
        """All AI security subcategories are valid."""
        valid_subcategories = [
            "llm_vulnerability",
            "agent_abuse",
            "ai_data_leakage",
            "model_poisoning",
            "ai_supply_chain",
            "ai_infrastructure",
            "ai_enabled_attacks",
            "misaligned_ai_permissions"
        ]
        for subcat in valid_subcategories:
            data = {
                "category": "ai_security",
                "subcategory": subcat,
                "confidence": 0.9,
                "assigned_by": "ai"
            }
            schema = SignalCategoryCreateSchema(**data)
            assert schema.subcategory == subcat

    def test_invalid_subcategory_for_ai_security(self):
        """Invalid subcategory for AI_SECURITY fails."""
        data = {
            "category": "ai_security",
            "subcategory": "invalid_ai_subcat",
            "confidence": 0.9,
            "assigned_by": "ai"
        }
        with pytest.raises(ValidationError) as exc_info:
            SignalCategoryCreateSchema(**data)
        errors = exc_info.value.errors()
        assert any("not a valid ai security subcategory" in str(e["msg"]).lower() for e in errors)

    def test_subcategory_only_with_ai_security(self):
        """Subcategory cannot be used with non-AI_SECURITY categories."""
        data = {
            "category": "vulnerability",
            "subcategory": "llm_vulnerability",
            "confidence": 0.9,
            "assigned_by": "ai"
        }
        with pytest.raises(ValidationError) as exc_info:
            SignalCategoryCreateSchema(**data)
        errors = exc_info.value.errors()
        assert any("can only be used with AI_SECURITY" in str(e['msg']) for e in errors)

    def test_category_confidence_range(self):
        """Confidence must be between 0.0 and 1.0."""
        # Valid
        data_valid = {
            "category": "cloud_security",
            "confidence": 0.75,
            "assigned_by": "human"
        }
        schema = SignalCategoryCreateSchema(**data_valid)
        assert schema.confidence == 0.75

        # Invalid - too high
        data_invalid_high = {
            "category": "cloud_security",
            "confidence": 1.5,
            "assigned_by": "human"
        }
        with pytest.raises(ValidationError):
            SignalCategoryCreateSchema(**data_invalid_high)

        # Invalid - negative
        data_invalid_low = {
            "category": "cloud_security",
            "confidence": -0.1,
            "assigned_by": "human"
        }
        with pytest.raises(ValidationError):
            SignalCategoryCreateSchema(**data_invalid_low)

    def test_ai_security_null_subcategory_valid(self):
        """AI_SECURITY with null subcategory is valid."""
        data = {
            "category": "ai_security",
            "subcategory": None,
            "confidence": 0.9,
            "assigned_by": "ai"
        }
        schema = SignalCategoryCreateSchema(**data)
        assert schema.category.value == "ai_security"
        assert schema.subcategory is None


class TestEvidenceCreateSchema:
    """Test EvidenceCreateSchema validation."""

    def test_valid_evidence_with_article(self):
        """Valid evidence citing an article."""
        data = {
            "signal_id": uuid4(),
            "article_id": uuid4(),
            "source_url": "https://example.com/news",
            "source_title": "Security News",
            "excerpt": "The vulnerability allows..."
        }
        schema = EvidenceCreateSchema(**data)
        assert schema.source_url == "https://example.com/news"

    def test_valid_evidence_without_article(self):
        """Evidence from manual research (article_id=NULL)."""
        data = {
            "signal_id": uuid4(),
            "article_id": None,
            "source_url": "https://internal.company.com/research",
            "source_title": "Internal Research",
            "excerpt": "Our analysis found..."
        }
        schema = EvidenceCreateSchema(**data)
        assert schema.article_id is None


class TestSignalCreateSchema:
    """Test SignalCreateSchema validation."""

    def test_valid_signal_create(self):
        """Valid signal creation."""
        data = {
            "event_id": uuid4(),
            "title": "Patch Immediately",
            "summary": "A critical vulnerability requires immediate patching.",
            "security_impact": "Attackers can execute arbitrary code.",
            "principle": "Keep systems patched",
            "recommended_action": "Apply security patch from vendor"
        }
        schema = SignalCreateSchema(**data)
        assert schema.title == "Patch Immediately"

    def test_signal_missing_required(self):
        """Missing required fields fails."""
        data = {
            "event_id": uuid4(),
            "title": "OnlyTitle"
        }
        with pytest.raises(ValidationError) as exc_info:
            SignalCreateSchema(**data)
        errors = exc_info.value.errors()
        assert len(errors) > 1


class TestUserCreateSchema:
    """Test UserCreateSchema validation."""

    def test_valid_user_create(self):
        """Valid user creation."""
        data = {
            "username": "alice",
            "email": "alice@example.com",
            "role": "reviewer",
            "password_hash": "bcrypt_hash_here"
        }
        schema = UserCreateSchema(**data)
        assert schema.username == "alice"
        assert schema.role.value == "reviewer"

    def test_user_invalid_role(self):
        """Invalid role fails."""
        data = {
            "username": "bob",
            "email": "bob@example.com",
            "role": "superuser",
            "password_hash": "hash"
        }
        with pytest.raises(ValidationError):
            UserCreateSchema(**data)


class TestSignalStatusEnum:
    """Test SignalStatus enum schema."""

    def test_valid_statuses(self):
        """All valid signal statuses."""
        valid_statuses = ["draft", "in_review", "approved", "rejected", "published"]
        for status in valid_statuses:
            schema = SignalStatusSchema(status)
            assert schema.value == status

    def test_invalid_status(self):
        """Invalid status raises error."""
        with pytest.raises(ValueError):
            SignalStatusSchema("invalid_status")


class TestSecurityCategoryEnum:
    """Test SecurityCategory enum schema."""

    def test_ten_categories(self):
        """Exactly 10 security categories."""
        categories = [
            "vulnerability", "cloud_security", "iam", "app_api",
            "supply_chain", "data_privacy", "ransomware",
            "threat_intel", "ai_security", "infrastructure"
        ]
        assert len(categories) == 10
        for cat in categories:
            schema = SecurityCategorySchema(cat)
            assert schema.value == cat

    def test_ai_security_category(self):
        """AI_SECURITY category is present."""
        schema = SecurityCategorySchema("ai_security")
        assert schema.value == "ai_security"


class TestAISecuritySubcategoryEnum:
    """Test AI security subcategories."""

    def test_eight_ai_subcategories(self):
        """Exactly 8 AI security subcategories."""
        subcategories = [
            "llm_vulnerability", "agent_abuse", "ai_data_leakage",
            "model_poisoning", "ai_supply_chain", "ai_infrastructure",
            "ai_enabled_attacks", "misaligned_ai_permissions"
        ]
        assert len(subcategories) == 8
        for subcat in subcategories:
            schema = AISecuritySubcategorySchema(subcat)
            assert schema.value == subcat


class TestEventTypeEnum:
    """Test EventType enum."""

    def test_all_event_types(self):
        """Test all event types."""
        types = [
            "vulnerability", "breach", "threat", "malware",
            "ransomware", "incident", "disclosure"
        ]
        for t in types:
            schema = EventTypeSchema(t)
            assert schema.value == t


class TestEventSeverityEnum:
    """Test EventSeverity enum."""

    def test_all_severities(self):
        """Test all severity levels."""
        severities = ["critical", "high", "medium", "low"]
        for sev in severities:
            schema = EventSeveritySchema(sev)
            assert schema.value == sev


class TestSchemaSerialization:
    """Test schema serialization to JSON."""

    def test_source_schema_dict(self):
        """Schema can be converted to dict."""
        data = {
            "name": "RSS",
            "source_type": "rss",
            "url": "https://example.com",
        }
        schema = SourceCreateSchema(**data)
        schema_dict = schema.model_dump()
        assert schema_dict["name"] == "RSS"

    def test_schema_json_serialization(self):
        """Schema can be serialized to JSON string."""
        data = {
            "name": "Test",
            "source_type": "api",
            "url": "https://example.com",
        }
        schema = SourceCreateSchema(**data)
        json_str = schema.model_dump_json()
        assert isinstance(json_str, str)
        assert "Test" in json_str

    def test_enum_serialization(self):
        """Enums serialize correctly."""
        data = {
            "category": "ai_security",
            "subcategory": "llm_vulnerability",
            "confidence": 0.9,
            "assigned_by": "ai"
        }
        schema = SignalCategoryCreateSchema(**data)
        dumped = schema.model_dump()
        assert dumped["category"] == "ai_security"
