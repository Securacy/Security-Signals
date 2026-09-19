#cat > tests/unit/intelligence/test_ai_service.py << 'EOF'
"""Tests for AI signal service - validation and schema tests."""

import pytest
from uuid import uuid4

from app.intelligence.schemas.signal_request import (
    AISignalGenerationRequest, AISignalGenerationResponse, SecureDesignPrinciple
)


class TestAISignalRequestValidation:
    """Request schema validation."""
    
    def test_valid_request_minimal(self):
        """Minimal valid request."""
        req = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="CVE-2024-1234 RCE",
            event_description="Critical vulnerability in Apache"
        )
        assert req.event_title == "CVE-2024-1234 RCE"
        assert req.event_description == "Critical vulnerability in Apache"
    
    def test_valid_request_with_articles(self):
        """Request with article references."""
        req = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="CVE-2024-1234",
            event_description="Apache RCE",
            article_titles=["Security Advisory", "Patch Released"],
            article_summaries=["Details here", "Patch available"]
        )
        assert len(req.article_titles) == 2
        assert len(req.article_summaries) == 2
    
    def test_empty_title_rejected(self):
        """Empty title rejected by Pydantic."""
        with pytest.raises(Exception):
            AISignalGenerationRequest(
                event_id=str(uuid4()),
                event_title="",
                event_description="Description"
            )
    
    def test_missing_description_rejected(self):
        """Missing description rejected."""
        with pytest.raises(Exception):
            AISignalGenerationRequest(
                event_id=str(uuid4()),
                event_title="Title",
                event_description=""
            )


class TestAISignalResponseValidation:
    """Response schema validation."""
    
    def test_valid_vulnerability_response(self):
        """Valid vulnerability signal."""
        resp = AISignalGenerationResponse(
            signal_title="Critical Apache RCE",
            signal_description="Apache HTTP Server RCE vulnerability requires immediate patching",
            category="insecure_design",
            ai_subcategory=None,
            confidence=0.95,
            evidence_summary="Apache released patch for CVE-2024-5678",
            secure_design_principles=[
                SecureDesignPrinciple(
                    principle="Defense in Depth",
                    connection="Multiple layers prevent RCE exploitation",
                    confidence=0.9
                )
            ]
        )
        assert resp.category == "insecure_design"
        assert resp.confidence == 0.95
        assert len(resp.secure_design_principles) == 1
    
    def test_valid_ai_security_response(self):
        """Valid AI security signal."""
        resp = AISignalGenerationResponse(
            signal_title="LLM Prompt Injection Risk",
            signal_description="Claude API vulnerable to prompt injection attacks",
            category="ai_security",
            ai_subcategory="llm_vulnerability",
            confidence=0.88,
            evidence_summary="LLM systems are vulnerable to adversarial prompts",
            secure_design_principles=[]
        )
        assert resp.category == "ai_security"
        assert resp.ai_subcategory == "llm_vulnerability"
    
    def test_valid_all_categories(self):
        """Test all valid categories."""
        categories = [
            "insecure_design", "cloud_security", "iam", "app_api", "supply_chain",
            "data_privacy", "ransomware", "threat_intel", "ai_security", "infrastructure"
        ]
        
        for cat in categories:
            ai_sub = "llm_vulnerability" if cat == "ai_security" else None
            resp = AISignalGenerationResponse(
                signal_title="Test",
                signal_description="Test",
                category=cat,
                ai_subcategory=ai_sub,
                confidence=0.75,
                evidence_summary="Test evidence",
                secure_design_principles=[]
            )
            assert resp.category == cat
    
    def test_all_ai_subcategories_valid(self):
        """Test all AI subcategories with AI_SECURITY."""
        subcats = [
            "llm_vulnerability", "agent_abuse", "ai_data_leakage", "model_poisoning",
            "ai_supply_chain", "ai_infrastructure", "ai_enabled_attacks", "misaligned_ai_permissions"
        ]
        
        for subcat in subcats:
            resp = AISignalGenerationResponse(
                signal_title="Test",
                signal_description="Test",
                category="ai_security",
                ai_subcategory=subcat,
                confidence=0.75,
                evidence_summary="Test",
                secure_design_principles=[]
            )
            assert resp.ai_subcategory == subcat
    
    def test_invalid_category_rejected(self):
        """Invalid category rejected."""
        with pytest.raises(Exception):
            AISignalGenerationResponse(
                signal_title="Title",
                signal_description="Desc",
                category="invalid_category",
                confidence=0.85,
                evidence_summary="Evidence",
                secure_design_principles=[]
            )
    
    def test_ai_security_requires_subcategory(self):
        """AI_SECURITY requires valid subcategory."""
        with pytest.raises(Exception):
            AISignalGenerationResponse(
                signal_title="Title",
                signal_description="Desc",
                category="ai_security",
                ai_subcategory=None,
                confidence=0.85,
                evidence_summary="Evidence",
                secure_design_principles=[]
            )
    
    def test_invalid_ai_subcategory_rejected(self):
        """Invalid subcategory rejected."""
        with pytest.raises(Exception):
            AISignalGenerationResponse(
                signal_title="Title",
                signal_description="Desc",
                category="ai_security",
                ai_subcategory="invalid_sub",
                confidence=0.85,
                evidence_summary="Evidence",
                secure_design_principles=[]
            )
    
    def test_subcategory_only_with_ai_security(self):
        """Subcategory only valid with AI_SECURITY."""
        with pytest.raises(Exception):
            AISignalGenerationResponse(
                signal_title="Title",
                signal_description="Desc",
                category="insecure_design",
                ai_subcategory="llm_vulnerability",
                confidence=0.85,
                evidence_summary="Evidence",
                secure_design_principles=[]
            )
    
    def test_low_confidence_rejected(self):
        """Confidence < 0.5 rejected."""
        with pytest.raises(Exception):
            AISignalGenerationResponse(
                signal_title="Title",
                signal_description="Desc",
                category="insecure_design",
                confidence=0.4,
                evidence_summary="Evidence",
                secure_design_principles=[]
            )
    
    def test_high_confidence_accepted(self):
        """High confidence accepted."""
        resp = AISignalGenerationResponse(
            signal_title="Title",
            signal_description="Description",
            category="insecure_design",
            confidence=1.0,
            evidence_summary="Evidence",
            secure_design_principles=[]
        )
        assert resp.confidence == 1.0
    
    def test_short_title_rejected(self):
        """Title < 5 chars rejected."""
        with pytest.raises(Exception):
            AISignalGenerationResponse(
                signal_title="Bad",
                signal_description="Desc",
                category="insecure_design",
                confidence=0.85,
                evidence_summary="Evidence",
                secure_design_principles=[]
            )
    
    def test_short_description_rejected(self):
        """Description < 20 chars rejected."""
        with pytest.raises(Exception):
            AISignalGenerationResponse(
                signal_title="Valid Title",
                signal_description="Too short",
                category="insecure_design",
                confidence=0.85,
                evidence_summary="Evidence",
                secure_design_principles=[]
            )
    
    def test_short_evidence_rejected(self):
        """Evidence < 10 chars rejected."""
        with pytest.raises(Exception):
            AISignalGenerationResponse(
                signal_title="Valid Title",
                signal_description="Valid description here",
                category="insecure_design",
                confidence=0.85,
                evidence_summary="Short",
                secure_design_principles=[]
            )


class TestSecureDesignPrinciple:
    """Secure design principle validation."""
    
    def test_valid_principle(self):
        """Valid principle."""
        principle = SecureDesignPrinciple(
            principle="Defense in Depth",
            connection="Multiple layers of security",
            confidence=0.9
        )
        assert principle.confidence == 0.9
    
    def test_confidence_range(self):
        """Confidence must be 0-1."""
        # Valid range
        p1 = SecureDesignPrinciple(
            principle="Test",
            connection="Test",
            confidence=0.0
        )
        assert p1.confidence == 0.0
        
        p2 = SecureDesignPrinciple(
            principle="Test",
            connection="Test",
            confidence=1.0
        )
        assert p2.confidence == 1.0
        
        # Invalid: out of range
        with pytest.raises(Exception):
            SecureDesignPrinciple(
                principle="Test",
                connection="Test",
                confidence=1.5
            )

