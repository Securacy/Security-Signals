"""Tests for the AWS Bedrock client helper - fully mocked, no real AWS
credentials or network access required."""

import types
from unittest.mock import patch, MagicMock

import pytest
from pydantic import SecretStr
from botocore.exceptions import ClientError

from app.intelligence.bedrock_client import (
    _resolve_secret_value,
    build_bedrock_runtime_client,
    invoke_claude,
    BedrockConfigurationError,
)


def _fake_settings(access_key_id=None, secret_access_key=None, region="us-east-1"):
    return types.SimpleNamespace(
        aws_bedrock_access_key_id=SecretStr(access_key_id) if access_key_id is not None else None,
        aws_bedrock_secret_access_key=SecretStr(secret_access_key) if secret_access_key is not None else None,
        aws_region=region,
    )


class TestResolveSecretValue:
    def test_literal_value_returned_unchanged(self):
        assert _resolve_secret_value("AKIAEXAMPLE", "us-east-1") == "AKIAEXAMPLE"

    def test_arn_is_resolved_via_secrets_manager(self):
        arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-abc123"
        with patch("app.intelligence.bedrock_client.boto3.client") as mock_client_factory:
            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {"SecretString": "resolved-real-value"}
            mock_client_factory.return_value = mock_sm

            result = _resolve_secret_value(arn, "us-east-1")

            assert result == "resolved-real-value"
            mock_client_factory.assert_called_once_with("secretsmanager", region_name="us-east-1")
            mock_sm.get_secret_value.assert_called_once_with(SecretId=arn)

    def test_secrets_manager_error_raises_configuration_error(self):
        arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-abc123"
        with patch("app.intelligence.bedrock_client.boto3.client") as mock_client_factory:
            mock_sm = MagicMock()
            mock_sm.get_secret_value.side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
                "GetSecretValue",
            )
            mock_client_factory.return_value = mock_sm

            with pytest.raises(BedrockConfigurationError):
                _resolve_secret_value(arn, "us-east-1")

    def test_empty_secret_string_raises_configuration_error(self):
        arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-abc123"
        with patch("app.intelligence.bedrock_client.boto3.client") as mock_client_factory:
            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {}
            mock_client_factory.return_value = mock_sm

            with pytest.raises(BedrockConfigurationError):
                _resolve_secret_value(arn, "us-east-1")


class TestBuildBedrockRuntimeClient:
    def test_literal_credentials_passed_through(self):
        settings = _fake_settings(access_key_id="AKIALITERAL", secret_access_key="secretliteral")

        with patch("app.intelligence.bedrock_client.boto3.client") as mock_client_factory:
            build_bedrock_runtime_client(settings)

            mock_client_factory.assert_called_once_with(
                "bedrock-runtime",
                region_name="us-east-1",
                aws_access_key_id="AKIALITERAL",
                aws_secret_access_key="secretliteral",
            )

    def test_arn_credentials_resolved_before_client_construction(self):
        access_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:access-key-id"
        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-key"
        settings = _fake_settings(access_key_id=access_arn, secret_access_key=secret_arn)

        with patch("app.intelligence.bedrock_client.boto3.client") as mock_client_factory:
            mock_sm = MagicMock()
            mock_sm.get_secret_value.side_effect = [
                {"SecretString": "AKIARESOLVED"},
                {"SecretString": "secretresolved"},
            ]

            def client_side_effect(service_name, **kwargs):
                if service_name == "secretsmanager":
                    return mock_sm
                return MagicMock()

            mock_client_factory.side_effect = client_side_effect

            build_bedrock_runtime_client(settings)

            bedrock_call = [
                call for call in mock_client_factory.call_args_list if call.args[0] == "bedrock-runtime"
            ]
            assert len(bedrock_call) == 1
            assert bedrock_call[0].kwargs["aws_access_key_id"] == "AKIARESOLVED"
            assert bedrock_call[0].kwargs["aws_secret_access_key"] == "secretresolved"

    def test_no_credentials_configured_falls_back_to_default_chain(self):
        """When neither credential is configured, no explicit
        aws_access_key_id/aws_secret_access_key is passed, so boto3 uses its
        own default credential resolution (env vars, IAM role, etc.)."""
        settings = _fake_settings(access_key_id=None, secret_access_key=None)

        with patch("app.intelligence.bedrock_client.boto3.client") as mock_client_factory:
            build_bedrock_runtime_client(settings)

            mock_client_factory.assert_called_once_with("bedrock-runtime", region_name="us-east-1")

    def test_never_logs_credential_values(self, caplog):
        access_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:access-key-id"
        settings = _fake_settings(access_key_id=access_arn, secret_access_key="literal-secret")

        with patch("app.intelligence.bedrock_client.boto3.client") as mock_client_factory:
            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {"SecretString": "SUPER-SECRET-RESOLVED-VALUE"}

            def client_side_effect(service_name, **kwargs):
                if service_name == "secretsmanager":
                    return mock_sm
                return MagicMock()

            mock_client_factory.side_effect = client_side_effect

            with caplog.at_level("DEBUG"):
                build_bedrock_runtime_client(settings)

            assert "SUPER-SECRET-RESOLVED-VALUE" not in caplog.text
            assert "literal-secret" not in caplog.text


class TestInvokeClaude:
    def test_extracts_text_from_converse_response(self):
        mock_client = MagicMock()
        mock_client.converse.return_value = {
            "output": {"message": {"content": [{"text": '{"signal_title": "test"}'}]}}
        }

        result = invoke_claude(mock_client, "us.anthropic.claude-sonnet-5", "prompt text", max_tokens=1500)

        assert result == '{"signal_title": "test"}'
        mock_client.converse.assert_called_once_with(
            modelId="us.anthropic.claude-sonnet-5",
            messages=[{"role": "user", "content": [{"text": "prompt text"}]}],
            inferenceConfig={"maxTokens": 1500, "temperature": 0.0},
        )

    def test_client_error_propagates(self):
        mock_client = MagicMock()
        mock_client.converse.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "rate limited"}},
            "Converse",
        )

        with pytest.raises(ClientError):
            invoke_claude(mock_client, "model-id", "prompt")
