"""AI service behavior with mocked Anthropic API."""

import pytest
import json
from uuid import uuid4
from unittest.mock import patch, MagicMock

from app.intelligence.ai_service import AISignalService, AISecurityError, _strip_markdown_json_fence
from app.intelligence.schemas.signal_request import AISignalGenerationResponse


class TestAIServiceGeneration:
    """AI signal generation with mocked API."""
    
    def get_valid_response_dict(self):
        """Helper: valid full response."""
        return {
            "signal_title": "Critical Apache RCE",
            "signal_description": "Critical remote code execution requiring immediate patch for Apache HTTP Server",
            "category": "vulnerability",
            "ai_subcategory": None,
            "confidence": 0.95,
            "evidence_summary": "Apache released security update for CVE-2024-12345",
            "secure_design_principles": []
        }
    
    def test_successful_generation(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest
        
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="CVE-2024-12345",
            event_description="Apache RCE"
        )
        
        response_dict = self.get_valid_response_dict()
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(response_dict))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test-key")
            result = service.generate_signal(request)
            
            assert isinstance(result, AISignalGenerationResponse)
            assert result.confidence == 0.95
    
    def test_malformed_json_rejected(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest
        
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Test",
            event_description="Test"
        )
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text="not valid json {")]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test-key")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
    
    def test_missing_required_field(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest
        
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Test",
            event_description="Test"
        )
        
        incomplete = {
            "signal_title": "Title",
            "category": "vulnerability"
        }
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(incomplete))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test-key")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
    
    def test_invalid_category_rejected(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest
        
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Test",
            event_description="Test"
        )
        
        invalid = self.get_valid_response_dict()
        invalid["category"] = "invalid_category"
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(invalid))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test-key")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
    
    def test_ai_security_without_subcategory_rejected(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest
        
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Test",
            event_description="Test"
        )
        
        invalid = self.get_valid_response_dict()
        invalid["category"] = "ai_security"
        invalid["ai_subcategory"] = None
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(invalid))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test-key")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
    
    def test_low_confidence_rejected(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest
        
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Test",
            event_description="Test"
        )
        
        invalid = self.get_valid_response_dict()
        invalid["confidence"] = 0.3
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(invalid))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test-key")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
    
    def test_confidence_boundary_0_5(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest
        
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Test",
            event_description="Test"
        )
        
        valid = self.get_valid_response_dict()
        valid["confidence"] = 0.5
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            
            mock_resp = MagicMock()
            mock_resp.content = [MagicMock(text=json.dumps(valid))]
            mock_inst.messages.create.return_value = mock_resp
            
            service = AISignalService(api_key="test-key")
            result = service.generate_signal(request)
            
            assert result.confidence == 0.5
    
    def test_api_timeout(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest
        
        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Test",
            event_description="Test"
        )
        
        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            mock_inst.messages.create.side_effect = TimeoutError("Timeout")
            
            service = AISignalService(api_key="test-key")
            
            with pytest.raises(AISecurityError):
                service.generate_signal(request)
    
    def test_api_connection_error(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest

        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="Test",
            event_description="Test"
        )

        with patch('app.intelligence.ai_service.Anthropic') as MockAI:
            mock_inst = MagicMock()
            MockAI.return_value = mock_inst
            mock_inst.messages.create.side_effect = ConnectionError("Network error")

            service = AISignalService(api_key="test-key")

            with pytest.raises(AISecurityError):
                service.generate_signal(request)


class TestAIServiceBedrockBackend:
    """AI signal generation via the Bedrock backend - fully mocked, no real
    AWS credentials required. Same prompt/validation logic as the Anthropic
    backend; only the model invocation differs (see AISignalService._invoke_model)."""

    def get_valid_response_dict(self):
        return {
            "signal_title": "Critical Apache RCE",
            "signal_description": "Critical remote code execution requiring immediate patch for Apache HTTP Server",
            "category": "vulnerability",
            "ai_subcategory": None,
            "confidence": 0.95,
            "evidence_summary": "Apache released security update for CVE-2024-12345",
            "secure_design_principles": []
        }

    def _make_bedrock_client(self, response_text: str):
        mock_client = MagicMock()
        mock_client.converse.return_value = {
            "output": {"message": {"content": [{"text": response_text}]}}
        }
        return mock_client

    def test_from_bedrock_generates_valid_signal(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest

        request = AISignalGenerationRequest(
            event_id=str(uuid4()),
            event_title="CVE-2024-12345",
            event_description="Apache RCE"
        )

        mock_client = self._make_bedrock_client(json.dumps(self.get_valid_response_dict()))
        service = AISignalService.from_bedrock(mock_client, "us.anthropic.claude-sonnet-5-1")

        result = service.generate_signal(request)

        assert isinstance(result, AISignalGenerationResponse)
        assert result.confidence == 0.95
        mock_client.converse.assert_called_once()
        call_kwargs = mock_client.converse.call_args.kwargs
        assert call_kwargs["modelId"] == "us.anthropic.claude-sonnet-5-1"
        assert "CVE-2024-12345" in call_kwargs["messages"][0]["content"][0]["text"]

    def test_from_bedrock_rejects_malformed_json(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest

        request = AISignalGenerationRequest(
            event_id=str(uuid4()), event_title="Test", event_description="Test"
        )
        mock_client = self._make_bedrock_client("not valid json {")
        service = AISignalService.from_bedrock(mock_client, "model-id")

        with pytest.raises(AISecurityError):
            service.generate_signal(request)

    def test_from_bedrock_rejects_fabricated_evidence(self):
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest

        request = AISignalGenerationRequest(
            event_id=str(uuid4()), event_title="Test", event_description="Test"
        )
        invalid = self.get_valid_response_dict()
        invalid["evidence_summary"] = "This is rumored to have happened, unconfirmed."
        mock_client = self._make_bedrock_client(json.dumps(invalid))
        service = AISignalService.from_bedrock(mock_client, "model-id")

        with pytest.raises(AISecurityError):
            service.generate_signal(request)

    def test_from_bedrock_propagates_client_errors_as_ai_security_error(self):
        from botocore.exceptions import ClientError
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest

        request = AISignalGenerationRequest(
            event_id=str(uuid4()), event_title="Test", event_description="Test"
        )
        mock_client = MagicMock()
        mock_client.converse.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "rate limited"}}, "Converse"
        )
        service = AISignalService.from_bedrock(mock_client, "model-id")

        with pytest.raises(AISecurityError):
            service.generate_signal(request)

    def test_from_settings_builds_bedrock_backed_service(self):
        """from_settings() wires build_bedrock_runtime_client() into
        from_bedrock() without needing real AWS credentials."""
        import types
        from pydantic import SecretStr

        fake_settings = types.SimpleNamespace(
            aws_bedrock_access_key_id=SecretStr("literal-key"),
            aws_bedrock_secret_access_key=SecretStr("literal-secret"),
            aws_region="us-east-1",
            bedrock_model_id="us.anthropic.claude-sonnet-5-1",
        )

        with patch("app.intelligence.bedrock_client.boto3.client") as mock_client_factory:
            mock_bedrock = MagicMock()
            mock_client_factory.return_value = mock_bedrock

            service = AISignalService.from_settings(fake_settings)

            assert service._backend == "bedrock"
            assert service.model == "us.anthropic.claude-sonnet-5-1"
            assert service._bedrock_client is mock_bedrock

    def test_anthropic_backend_still_works_unchanged(self):
        """Sanity check: constructing via the original __init__ still uses
        the Anthropic backend, not Bedrock - the two are independent."""
        request_service = AISignalService(api_key="test-key")
        assert request_service._backend == "anthropic"

    def test_from_bedrock_accepts_markdown_fenced_json(self):
        """Discovered via a real Bedrock call: Claude sometimes wraps its
        JSON response in a ```json ... ``` fence despite being told not to.
        This must still be accepted - not by loosening what counts as valid
        JSON, just by stripping the known wrapper before the same strict
        parse."""
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest

        request = AISignalGenerationRequest(
            event_id=str(uuid4()), event_title="Test", event_description="Test"
        )
        fenced = "```json\n" + json.dumps(self.get_valid_response_dict()) + "\n```"
        mock_client = self._make_bedrock_client(fenced)
        service = AISignalService.from_bedrock(mock_client, "model-id")

        result = service.generate_signal(request)

        assert isinstance(result, AISignalGenerationResponse)
        assert result.confidence == 0.95

    def test_from_bedrock_rejects_malformed_json_inside_fence(self):
        """Fence-stripping must not become permissive JSON repair: content
        that's still invalid JSON once unwrapped is still rejected."""
        from app.intelligence.schemas.signal_request import AISignalGenerationRequest

        request = AISignalGenerationRequest(
            event_id=str(uuid4()), event_title="Test", event_description="Test"
        )
        fenced_but_broken = "```json\nnot valid json {\n```"
        mock_client = self._make_bedrock_client(fenced_but_broken)
        service = AISignalService.from_bedrock(mock_client, "model-id")

        with pytest.raises(AISecurityError):
            service.generate_signal(request)


class TestStripMarkdownJsonFence:
    """Unit tests for the fence-stripping helper in isolation."""

    def test_leaves_plain_json_unchanged(self):
        assert _strip_markdown_json_fence('{"a": 1}') == '{"a": 1}'

    def test_strips_json_language_fence(self):
        assert _strip_markdown_json_fence('```json\n{"a": 1}\n```') == '{"a": 1}'

    def test_strips_bare_fence(self):
        assert _strip_markdown_json_fence('```\n{"a": 1}\n```') == '{"a": 1}'

    def test_leading_backticks_without_trailing_fence_left_as_is(self):
        """Only strips when there's a real closing fence - an unrelated
        string that merely starts with backticks isn't treated as fenced."""
        text = "```not actually a fence at all"
        assert _strip_markdown_json_fence(text) == text
