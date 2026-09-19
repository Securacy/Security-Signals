"""Evidence grounding validation tests."""

import pytest
import json
from uuid import uuid4
from unittest.mock import patch, MagicMock

from app.intelligence.ai_service import AISignalService, AISecurityError
from app.intelligence.schemas.signal_request import AISignalGenerationRequest


class TestEvidenceValidation:
    """Test evidence grounding in source material."""
    
    def get_valid_response_dict(self):
        """Helper: valid response dict."""
        return {
            "signal_title": "Critical Apache RCE",
            "signal_description": "Critical remote code execution requiring immediate patch for Apache HTTP Server",
            "category": "insecure_design",
            "ai_subcategory": None,
            "confidence": 0.95,
            "evidence_summary": "CVE-2024-12345 is an Apache RCE vulnerability",
            "secure_design_principles": []
        }
    
    def test_valid_evidence_grounded_in_event(self):
        """Evidence grounded in event title is valid."""
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="CVE-2024-12345 Apache RCE",
            event_description="Remote code execution vulnerability",
            article_titles=[],
            article_summaries=[]
        )
        
        valid_response = self.get_valid_response_dict()
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(valid_response))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test")
            result = service.generate_signal(request)
            
            assert "CVE-2024-12345" in result.evidence_summary
    
    def test_valid_evidence_grounded_in_article(self):
        """Evidence grounded in article is valid."""
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Security Event",
            event_description="A security incident",
            article_titles=["Apache Patch Released"],
            article_summaries=["Apache published security update"]
        )
        
        valid_response = self.get_valid_response_dict()
        valid_response["evidence_summary"] = "Apache published security update addressing the vulnerability"
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(valid_response))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test")
            result = service.generate_signal(request)
            
            assert "Apache" in result.evidence_summary
    
    def test_empty_evidence_rejected(self):
        """Empty evidence rejected."""
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="CVE-2024-12345",
            event_description="Vulnerability",
            article_titles=[],
            article_summaries=[]
        )
        
        invalid = self.get_valid_response_dict()
        invalid["evidence_summary"] = ""
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(invalid))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
    
    def test_fabricated_evidence_unnamed_sources(self):
        """Evidence citing 'unnamed sources' rejected."""
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Event",
            event_description="Description",
            article_titles=[],
            article_summaries=[]
        )
        
        invalid = self.get_valid_response_dict()
        invalid["evidence_summary"] = "According to unnamed sources, a vulnerability exists"
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(invalid))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
    
    def test_fabricated_evidence_unverified_claims(self):
        """Evidence stating 'unverified claims' rejected."""
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Event",
            event_description="Description",
            article_titles=[],
            article_summaries=[]
        )
        
        invalid = self.get_valid_response_dict()
        invalid["evidence_summary"] = "Alleged unverified claims suggest a breach"
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(invalid))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
    
    def test_fabricated_evidence_suspected_unconfirmed(self):
        """Evidence 'suspected but unconfirmed' rejected."""
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Event",
            event_description="Description",
            article_titles=[],
            article_summaries=[]
        )
        
        invalid = self.get_valid_response_dict()
        invalid["evidence_summary"] = "Suspected but unconfirmed data leakage"
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(invalid))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
    
    def test_fabricated_evidence_rumored(self):
        """Evidence 'rumored to have' rejected."""
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Event",
            event_description="Description",
            article_titles=[],
            article_summaries=[]
        )
        
        invalid = self.get_valid_response_dict()
        invalid["evidence_summary"] = "The system is rumored to have a critical flaw"
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(invalid))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
