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
        "read_email",
    ]
    # Consequential tools: if influenced by untrusted data, require human approval.
    consequential_tools: list[str] = ["send_email", "http_request", "write_file"]
    # High-impact tools that ALWAYS need a human, whatever the provenance and whatever the
    # security LLM says (e.g. deletions, deploys). Empty by default; edit on the rules page.
    approval_required_tools: list[str] = []
    # Outbound email only to these domains (data-egress control).
    allowed_email_domains: list[str] = ["ourco.example"]
    # http_request only to these hosts (and their subdomains) — data-egress control.
    allowed_http_hosts: list[str] = ["ourco.example"]
    # read_file / write_file are confined to this directory (the proxy refuses anything
    # that resolves outside it, e.g. /proc/self/environ or ../../etc/passwd).
    files_root: str = "/tmp/sec-agent-files"

    # The lists above are only the factory defaults: the live, editable copy is a JSON
    # file (see rules.py) owned by whoever executes tools (the proxy in two-container mode).
    rules_file: str = "/tmp/sec-agent-rules.json"
    # Password for editing rules from the web UI. Empty = editing disabled.
    rules_admin_token: str = ""

    # SOC event log (SQLite). In Docker this lives on a volume so it survives redeploys.
    events_db: str = "/tmp/sec-agent-events.db"

    # --- Jev (TypeSafe AI): prompt-injection risk scoring of untrusted input. ---
    # Optional and advisory; empty key = not used. Untrusted content is sent to TypeSafe.
    typesafe_api_key: str = ""
    jev_model: str = ""             # empty = the SDK's default model
    jev_timeout_s: float = 10.0
    jev_suspicious_level: int = 60  # default; editable on the rules page
    jev_signal_threshold: float = 0.9  # any single decisive signal this strong -> suspicious
    # --- Gmail (read-only), per visitor via "Sign in with Google". Empty = feature off. ---
    # Each visitor connects THEIR OWN mailbox; the access token (1 h, no refresh token) lives
    # only in the controller's memory and is handed to the proxy per read_email call.
    google_client_id: str = ""
    google_client_secret: str = ""
    # Public base URL, for the OAuth redirect (https://<host>/auth/google/callback).
    public_url: str = ""
    gmail_max_results: int = 10      # per read_email call
    gmail_batch_max: int = 50        # per "load my inbox" on /batch
    gmail_body_chars: int = 8000     # body text kept per email

    # Output-only tools: they touch no resource and only reach the trusted user, so the
    # resource denylist does not apply to their free text (an answer may legitimately
    # say "this document asked me to read ~/.ssh/id_ed25519").
    output_only_tools: list[str] = ["respond_to_user"]


settings = Settings()
