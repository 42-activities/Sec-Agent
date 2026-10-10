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
        "pay_invoice",
    ]
    # Consequential tools: if influenced by untrusted data, require human approval.
    consequential_tools: list[str] = ["send_email", "http_request", "write_file", "pay_invoice"]
    # High-impact tools (money movement): ALWAYS need a human, whatever the provenance
    # and whatever the security LLM says. The LLM can tighten this to DENY, never loosen it.
    approval_required_tools: list[str] = ["pay_invoice"]
    # Vendor master data: the ONLY bank accounts payments may go to. A document claiming
    # "our bank details have changed" cannot add to this — it must be verified out of band.
    known_payees: dict[str, str] = {"Acme GmbH": "DE89370400440532013000"}
    # Outbound email only to these domains (data-egress control).
    allowed_email_domains: list[str] = ["ourco.example"]
    # read_file / write_file are confined to this directory (the proxy refuses anything
    # that resolves outside it, e.g. /proc/self/environ or ../../etc/passwd).
    files_root: str = "/tmp/sec-agent-files"

    # The lists above are only the factory defaults: the live, editable copy is a JSON
    # file (see rules.py) owned by whoever executes tools (the proxy in two-container mode).
    rules_file: str = "/tmp/sec-agent-rules.json"
    # Password for editing rules from the web UI. Empty = editing disabled.
    rules_admin_token: str = ""
    # Output-only tools: they touch no resource and only reach the trusted user, so the
    # resource denylist does not apply to their free text (an answer may legitimately
    # say "this document asked me to read ~/.ssh/id_ed25519").
    output_only_tools: list[str] = ["respond_to_user"]


settings = Settings()
