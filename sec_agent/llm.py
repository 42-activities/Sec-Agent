"""Bedrock-backed chat models.

langchain-aws builds a boto3 bedrock-runtime client under the hood; it reads
AWS_BEARER_TOKEN_BEDROCK (or standard SigV4 creds) from the environment.
"""

from __future__ import annotations

from langchain_aws import ChatBedrockConverse

from .config import settings


def make_executor_llm() -> ChatBedrockConverse:
    """The capable 'worker' model that plans and proposes actions."""
    return ChatBedrockConverse(
        model=settings.executor_model_id,
        region_name=settings.aws_region,
        temperature=0,
        max_tokens=1024,
    )


def make_security_llm() -> ChatBedrockConverse:
    """A separate, independent model used only for adversarial review."""
    return ChatBedrockConverse(
        model=settings.security_model_id,
        region_name=settings.aws_region,
        temperature=0,
        max_tokens=1024,
    )
