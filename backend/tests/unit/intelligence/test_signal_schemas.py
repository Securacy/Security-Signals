"""Pydantic schema validation tests for AI signals."""

import pytest
from uuid import uuid4
from pydantic import ValidationError

from app.intelligence.schemas.signal_request import (
    AISignalGenerationRequest,
    AISignalGenerationResponse,
    SecureDesignPrinciple
)


class TestAISignalGenerationRequest:
    """AISignalGenerationRequest validation."""
    
    def test_minimal_valid_request(self):
        req = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="CVE-2024-12345",
            event_description="Apache HTTP Server RCE"
        )
        assert req.event_title == "CVE-2024-12345"
    
    def test_full_valid_request(self):
        req = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="CVE-2024-12345",
            event_description="Apache vulnerability",
            article_titles=["Advisory"],
            article_summaries=["Details"]
        )
        assert len(req.article_titles) == 1
    
    def test_empty_title_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationRequest(
                event_id=str(uuid4()),
                event_title="",
                event_description="Description"
            )
    
    def test_title_max_length_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationRequest(
                event_id=str(uuid4()),
                event_title="x" * 501,
                event_description="Description"
            )
    
    def test_empty_description_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationRequest(
                event_id=str(uuid4()),
                event_title="Title",
                event_description=""
            )
    
    def test_description_max_length_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationRequest(
                event_id=str(uuid4()),
                event_title="Title",
                event_description="x" * 10001
            )


class TestAISignalGenerationResponse:
    """AISignalGenerationResponse validation."""
    
    def test_valid_vulnerability_response(self):
        resp = AISignalGenerationResponse(
            signal_title="Critical Apache RCE",
            signal_description="Remote code execution requiring immediate patch for Apache HTTP Server",
            category="vulnerability",
            ai_subcategory=None,
            confidence=0.95,
            evidence_summary="Apache released security update for CVE-2024-12345",
            secure_design_principles=[]
        )
        assert resp.confidence == 0.95
    
    def test_valid_ai_security_response(self):
        resp = AISignalGenerationResponse(
            signal_title="LLM Prompt Injection",
            signal_description="Claude API vulnerable to prompt injection in production systems",
            category="ai_security",
            ai_subcategory="llm_vulnerability",
            confidence=0.88,
            evidence_summary="LLM systems vulnerable to adversarial prompts",
            secure_design_principles=[]
        )
        assert resp.ai_subcategory == "llm_vulnerability"
    
    def test_all_security_categories_valid(self):
        categories = [
            "vulnerability", "cloud_security", "iam", "app_api",
            "supply_chain", "data_privacy", "ransomware", "threat_intel",
            "ai_security", "infrastructure"
        ]
        
        for cat in categories:
            ai_sub = "llm_vulnerability" if cat == "ai_security" else None
            resp = AISignalGenerationResponse(
                signal_title="Signal Title",
                signal_description="This is a valid description for testing category validation",
                category=cat,
                ai_subcategory=ai_sub,
                confidence=0.75,
                evidence_summary="Evidence for testing category",
                secure_design_principles=[]
            )
            assert resp.category == cat
    
    def test_all_ai_subcategories_valid(self):
        subcats = [
            "llm_vulnerability", "agent_abuse", "ai_data_leakage",
            "model_poisoning", "ai_supply_chain", "ai_infrastructure",
            "ai_enabled_attacks", "misaligned_ai_permissions"
        ]
        
        for subcat in subcats:
            resp = AISignalGenerationResponse(
                signal_title="AI Security Signal",
                signal_description="Testing AI security subcategories with full description content",
                category="ai_security",
                ai_subcategory=subcat,
                confidence=0.85,
                evidence_summary="Evidence for AI security testing",
                secure_design_principles=[]
            )
            assert resp.ai_subcategory == subcat
    
    def test_invalid_category_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationResponse(
                signal_title="Title",
                signal_description="Valid description text here",
                category="invalid_category",
                confidence=0.85,
                evidence_summary="Evidence here",
                secure_design_principles=[]
            )
    
    def test_ai_security_requires_subcategory(self):
        with pytest.raises(ValidationError):
            AISignalGenerationResponse(
                signal_title="Title",
                signal_description="Valid description text here",
                category="ai_security",
                ai_subcategory=None,
                confidence=0.85,
                evidence_summary="Evidence here",
                secure_design_principles=[]
            )
    
    def test_invalid_ai_subcategory_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationResponse(
                signal_title="Title",
                signal_description="Valid description text here",
                category="ai_security",
                ai_subcategory="invalid_subcat",
                confidence=0.85,
                evidence_summary="Evidence here",
                secure_design_principles=[]
            )
    
    def test_subcategory_rejected_without_ai_security(self):
        with pytest.raises(ValidationError):
            AISignalGenerationResponse(
                signal_title="Title",
                signal_description="Valid description text here",
                category="vulnerability",
                ai_subcategory="llm_vulnerability",
                confidence=0.85,
                evidence_summary="Evidence here",
                secure_design_principles=[]
            )
    
    def test_confidence_0_5_accepted(self):
        resp = AISignalGenerationResponse(
            signal_title="Title Test",
            signal_description="Valid description with minimum threshold testing",
            category="vulnerability",
            confidence=0.5,
            evidence_summary="Evidence for testing",
            secure_design_principles=[]
        )
        assert resp.confidence == 0.5
    
    def test_confidence_0_49_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationResponse(
                signal_title="Title Test",
                signal_description="Valid description text here",
                category="vulnerability",
                confidence=0.49,
                evidence_summary="Evidence here",
                secure_design_principles=[]
            )
    
    def test_confidence_1_0_accepted(self):
        resp = AISignalGenerationResponse(
            signal_title="Title Test",
            signal_description="Valid description with maximum confidence testing",
            category="vulnerability",
            confidence=1.0,
            evidence_summary="Evidence for testing",
            secure_design_principles=[]
        )
        assert resp.confidence == 1.0
    
    def test_confidence_1_01_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationResponse(
                signal_title="Title Test",
                signal_description="Valid description text here",
                category="vulnerability",
                confidence=1.01,
                evidence_summary="Evidence here",
                secure_design_principles=[]
            )
    
    def test_short_title_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationResponse(
                signal_title="Bad",
                signal_description="Valid description text here",
                category="vulnerability",
                confidence=0.85,
                evidence_summary="Evidence",
                secure_design_principles=[]
            )
    
    def test_long_title_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationResponse(
                signal_title="x" * 201,
                signal_description="Valid description text here",
                category="vulnerability",
                confidence=0.85,
                evidence_summary="Evidence",
                secure_design_principles=[]
            )
    
    def test_short_description_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationResponse(
                signal_title="Valid Title",
                signal_description="Short",
                category="vulnerability",
                confidence=0.85,
                evidence_summary="Evidence",
                secure_design_principles=[]
            )
    
    def test_short_evidence_rejected(self):
        with pytest.raises(ValidationError):
            AISignalGenerationResponse(
                signal_title="Valid Title",
                signal_description="Valid description text here",
                category="vulnerability",
                confidence=0.85,
                evidence_summary="Short",
                secure_design_principles=[]
            )
    
    def test_multiple_secure_design_principles(self):
        resp = AISignalGenerationResponse(
            signal_title="Title Test",
            signal_description="Valid description with multiple principles testing",
            category="vulnerability",
            confidence=0.85,
            evidence_summary="Evidence for testing",
            secure_design_principles=[
                SecureDesignPrinciple(
                    principle="Defense in Depth",
                    connection="Multiple layers",
                    confidence=0.9
                ),
                SecureDesignPrinciple(
                    principle="Least Privilege",
                    connection="Minimize access",
                    confidence=0.85
                )
            ]
        )
        assert len(resp.secure_design_principles) == 2


class TestSecureDesignPrinciple:
    """SecureDesignPrinciple validation."""
    
    def test_valid_principle(self):
        principle = SecureDesignPrinciple(
            principle="Defense in Depth",
            connection="Multiple layers",
            confidence=0.9
        )
        assert principle.confidence == 0.9
    
    def test_confidence_0_accepted(self):
        principle = SecureDesignPrinciple(
            principle="Principle",
            connection="Connection",
            confidence=0.0
        )
        assert principle.confidence == 0.0
    
    def test_confidence_1_accepted(self):
        principle = SecureDesignPrinciple(
            principle="Principle",
            connection="Connection",
            confidence=1.0
        )
        assert principle.confidence == 1.0
    
    def test_confidence_out_of_range_high(self):
        with pytest.raises(ValidationError):
            SecureDesignPrinciple(
                principle="Principle",
                connection="Connection",
                confidence=1.5
            )
    
    def test_confidence_negative_rejected(self):
        with pytest.raises(ValidationError):
            SecureDesignPrinciple(
                principle="Principle",
                connection="Connection",
                confidence=-0.1
            )
