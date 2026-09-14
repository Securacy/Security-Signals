"""AWS Bedrock Runtime client construction for Claude model invocation.

Bedrock is the production path for AI signal generation (see
AISignalService). Credentials may be configured either as literal values
(local/test convenience) or as AWS Secrets Manager ARNs (the pattern this
deployment's .env actually uses), in which case the real secret material is
resolved via Secrets Manager here, at client-construction time.

Never logs a credential value, resolved or otherwise - only ARNs/resource
identifiers (never sensitive on their own) and error codes.
"""

import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_SECRETS_MANAGER_ARN_PREFIX = "arn:aws:secretsmanager:"


class BedrockConfigurationError(Exception):
    """Raised when Bedrock credentials/configuration cannot be resolved."""
    pass


def _resolve_secret_value(value: str, region_name: str) -> str:
    """If `value` looks like a Secrets Manager ARN, fetch and return the
    real secret string from Secrets Manager. Otherwise return `value`
    unchanged - this lets literal credentials work directly for local/test
    setups without requiring Secrets Manager at all.

    The secret may live in a different region than Bedrock itself (an ARN
    embeds its own region as its 4th colon-delimited segment), so that
    region is used for the Secrets Manager call rather than assuming it
    matches `region_name` (Bedrock's configured region).
    """
    if not value.startswith(_SECRETS_MANAGER_ARN_PREFIX):
        return value

    arn_parts = value.split(":")
    secret_region = arn_parts[3] if len(arn_parts) > 3 and arn_parts[3] else region_name

    client = boto3.client("secretsmanager", region_name=secret_region)
    try:
        response = client.get_secret_value(SecretId=value)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        logger.error(f"Failed to resolve Bedrock credential from Secrets Manager: {code}")
        raise BedrockConfigurationError(
            f"Could not resolve Bedrock credential from Secrets Manager ({code})"
        ) from e

    secret = response.get("SecretString")
    if not secret:
        raise BedrockConfigurationError("Secrets Manager secret has no SecretString value")
    return secret


def build_bedrock_runtime_client(settings) -> "boto3.client":
    """Construct a boto3 bedrock-runtime client from application settings.

    If AWS_BEDROCK_ACCESS_KEY_ID / AWS_BEDROCK_SECRET_ACCESS_KEY aren't
    configured, falls back to boto3's own default credential chain
    (environment variables, IAM role, etc.) by omitting explicit
    credentials from the client call entirely.
    """
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None

    if settings.aws_bedrock_access_key_id is not None:
        access_key_id = _resolve_secret_value(
            settings.aws_bedrock_access_key_id.get_secret_value(), settings.aws_region
        )
    if settings.aws_bedrock_secret_access_key is not None:
        secret_access_key = _resolve_secret_value(
            settings.aws_bedrock_secret_access_key.get_secret_value(), settings.aws_region
        )

    client_kwargs = {"region_name": settings.aws_region}
    if access_key_id and secret_access_key:
        client_kwargs["aws_access_key_id"] = access_key_id
        client_kwargs["aws_secret_access_key"] = secret_access_key

    return boto3.client("bedrock-runtime", **client_kwargs)


def invoke_claude(client, model_id: str, prompt: str, max_tokens: int = 2000, temperature: float = 0.0) -> str:
    """Invoke a Claude model on Bedrock via the Converse API and return the
    text of the response's first content block.

    Uses the Converse API (not the older model-specific invoke_model body
    format) since it's AWS's current, provider-agnostic, documented way to
    call Claude-family models on Bedrock.
    """
    try:
        response = client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": max_tokens, "temperature": temperature},
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        logger.error(f"Bedrock converse() call failed: {code}")
        raise

    return response["output"]["message"]["content"][0]["text"]
