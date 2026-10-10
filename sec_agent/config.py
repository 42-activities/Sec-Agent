"""Runtime configuration.

Loads .env into the process environment so boto3 (used by langchain-aws) can read
AWS_BEARER_TOKEN_BEDROCK, and exposes typed settings for everything else.
"""

from __future__ import annotations

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# Put .env values into os.environ so boto3 picks up the Bedrock bearer token.
load_dotenv()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    aws_region: str = "us-west-2"

    # Web UI bind address. Loopback by default; the container sets WEB_HOST=0.0.0.0
    # so Docker's port mapping can reach it.
    web_host: str = "127.0.0.1"
    web_port: int = 8000

    # Two-container split. When proxy_url is set, the controller forwards
    # authorized actions to the standalone proxy service instead of executing
    # in-process. proxy_auth_token is the shared secret between them.
    proxy_url: str = ""          # e.g. http://proxy:8001
    proxy_auth_token: str = ""   # shared bearer secret; required by the proxy service

    # Executor = capable worker model. Security = cheaper, INDEPENDENT reviewer.
    # Must be inference-profile IDs ("us.anthropic.*") — bare IDs fail on-demand.
    executor_model_id: str = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
    security_model_id: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

    # --- Deterministic policy engine (the non-LLM backstop) ---
    # Substrings that must never appear in any tool argument, regardless of the
    # security LLM's verdict.
    denied_path_substrings: list[str] = [
        ".ssh", ".aws", ".env", "credentials", "secrets",
        "id_rsa", "id_ed25519", "private_key", "/etc/shadow",
    ]
    # Tools the agent is permitted to propose at all (least privilege).
    allowed_tools: list[str] = [
        "respond_to_user", "read_document", "read_file", "write_file", "send_email", "http_request",
    ]
    # Consequential tools: if influenced by untrusted data, require human approval.
    consequential_tools: list[str] = ["send_email", "http_request", "write_file"]
    # Output-only tools: they touch no resource and only reach the trusted user, so the
    # resource denylist does not apply to their free text (an answer may legitimately
    # say "this document asked me to read ~/.ssh/id_ed25519").
    output_only_tools: list[str] = ["respond_to_user"]


settings = Settings()
