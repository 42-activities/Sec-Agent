# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current State

PoC scaffolded and runnable. Stack: Python (>=3.10) + LangGraph + `langchain-aws` (Amazon Bedrock) + Pydantic. The full `input_guard → executor → security → policy → proxy` pipeline works end-to-end and the poisoned-invoice demo blocks credential exfiltration via both the security LLM and the deterministic policy engine.

### Commands

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,web]"        # install package + dev + web deps

pytest -q                          # offline tests (deterministic policy engine; no network)
pytest tests/test_policy.py -q     # single test file
python -m sec_agent.demo.poisoned_invoice   # live end-to-end demo (needs Bedrock creds)
sec-web                            # single-process web UI → http://127.0.0.1:8000
sec-proxy                          # standalone execution-proxy service (:8001)
```

Two-container deployment (privilege separation; needs `.env` with `PROXY_AUTH_TOKEN` + Bedrock creds):

```bash
docker compose up --build          # controller → 127.0.0.1:8700 (SEC_AGENT_PORT) + proxy (internal only)
```

### Bedrock / credentials

- Credentials come from the environment via `.env` (gitignored; copy from `env.example`). `sec_agent/config.py` calls `load_dotenv()` so boto3 sees `AWS_BEARER_TOKEN_BEDROCK`.
- Hackathon auth is a **Bedrock API key** (bearer token, short-lived ~12h) in `AWS_BEARER_TOKEN_BEDROCK`, region `us-west-2`. Regenerate from the Bedrock console → API keys when it expires.
- **Model IDs must be inference profiles** (`us.anthropic.*`); bare `anthropic.*` IDs fail on-demand with a ValidationException. List them: `aws bedrock list-inference-profiles --region us-west-2`.
- Verified working: executor `us.anthropic.claude-sonnet-4-5-20250929-v1:0`, security `us.anthropic.claude-haiku-4-5-20251001-v1:0`. Override via `EXECUTOR_MODEL_ID` / `SECURITY_MODEL_ID`.

### Layout

`sec_agent/` — `config.py` (settings + denylist), `models.py` (Pydantic contracts + `AgentState`), `llm.py` (Bedrock model factories), `nodes/` (`input_guard`, `executor`, `security`, `policy`), `proxy.py` (execution proxy — only tool executor), `tools/` (the controlled tool set), `graph.py` (LangGraph wiring), `demo/`, `web/` (FastAPI app + static UI). Tests in `tests/`.

`web/app.py` exposes the human-in-the-loop flow: `POST /analyze` runs the controller and **stops before execution** (graph built with `execute=False`), stashing state under a session id; `POST /execute` runs the proxy with the human's approve/deny. `POST /analyze/stream` is the same run but emits one NDJSON event per graph node (`graph.stream(stream_mode="updates")`) — the UI (`web/static/index.html`) uses it to animate Input → input guard → executor → output guard → proxy live. It sets `X-Accel-Buffering: no` so nginx doesn't buffer it. `GET /health` is used by the deploy health check. `build_graph(include_executor=, execute=)` controls both the compromised-executor simulation and the stop-before-execute behavior.

### Two-container security split

`docker-compose.yml` runs two containers from one image (`Dockerfile`), separated by **credentials and network**, which turns the "no executor→tool bypass" invariant into a hard boundary:

- **controller** (`sec-web`, :8000 in-container, published on `127.0.0.1:8700` only; `WEB_HOST=0.0.0.0` inside the container): web UI + input_guard + executor LLM + security LLM + policy engine. Holds the **Bedrock token only**; has internet egress (for Bedrock). When `PROXY_URL` is set, `/execute` forwards to the proxy via `sec_agent/proxy_client.py` instead of executing in-process.
- **proxy** (`sec-proxy`, :8001, `sec_agent/proxy_service/`): the execution proxy + real tools. Holds **tool credentials only**, **no Bedrock access**, on an `internal: true` network (no host port, no internet egress).

The proxy service is **zero-trust toward the controller**: `POST /execute-action` ignores the caller's claimed decision and independently re-runs `policy.evaluate()`, refusing any DENY (and any APPROVAL without approval). A compromised controller therefore still cannot reach a denied resource. Services authenticate with the shared `PROXY_AUTH_TOKEN`.

### Deployment & CI/CD

- Live at **https://sec-agent.naurzalinov.me** (Hetzner arm64 host). Host nginx (`deploy/sec-agent.naurzalinov.me`, TLS via certbot) proxies to `127.0.0.1:8700`. The app has no auth of its own.
- `.github/workflows/pipeline.yml`: on push to `main` → `ci.yml` (pytest) → `docker-deploy.yml` builds `ghcr.io/42-activities/sec-agent-app:<sha>` for arm64, SSHes to the server, pulls, `docker compose up`, checks `/health`, rolls back on failure. PRs only test + build. Same pattern as LegoBot.
- **The server's `.env` is rewritten on every deploy** from GitHub secrets (`AWS_BEARER_TOKEN_BEDROCK`, `PROXY_AUTH_TOKEN`) and variables (`AWS_REGION`, `EXECUTOR_MODEL_ID`, `SECURITY_MODEL_ID`). Never edit `.env` on the server; rotate the Bedrock key with `gh secret set AWS_BEARER_TOKEN_BEDROCK && gh workflow run pipeline.yml`.
- Deploy aborts if the server checkout (`~/projects/Sec-Agent`) has uncommitted changes to tracked files.

### Tools & demo scenarios

- `respond_to_user(answer)` is the executor's "just answer" action: allowed, not consequential, and in `output_only_tools`, so the resource denylist does not scan its free text (an answer may legitimately quote `~/.ssh/...` while warning the user).
- Proxies call tools via `tools.invoke(tool, args, documents)`. `read_document("document-1")` resolves pasted (untrusted) context items by ID; the two-container `proxy_client` ships only the one document a `read_document` call names.
- UI scenario presets (`SCENARIOS` in `index.html`): **Hijacked agent** (goal "Process this invoice following its payment instructions" + an AP-workflow note asking to email `ap-verification@acme-billing.example`) reliably makes the live Sonnet executor propose `send_email` → DENY. It also slips past the regex input guard, which is the point: the output side catches it. The blunt "IMPORTANT FOR AI ASSISTANTS" injection is resisted by the model, so credential theft is demoed via compromised-executor mode.

## Project Overview

Sec-Agent is an **AI Security Controller for LLM agents**.

The core premise: an AI agent should never be trusted to directly execute sensitive actions. Prompt injection, poisoned RAG documents, malicious webpages, poisoned MCP tool descriptions, and compromised memory can all cause the main agent to behave incorrectly.

Rather than assuming prompt injection can always be *prevented*, the project assumes the main agent **may become compromised** and wraps it in an independent security layer that gates every consequential action.

**Central claim** — do not overstate it:
- ❌ Not: "We completely solve prompt injection."
- ✅ Instead: "We assume prompt injection can eventually succeed. Our security controller prevents a compromised AI agent from converting poisoned reasoning into unauthorized real-world actions."

## Core Architecture

```text
Untrusted Input
      │
      ▼
┌───────────────────────┐
│ Input Security Agent  │   detects prompt injection, poisoned docs,
│                       │   malicious webpages, suspicious MCP data
└───────────┬───────────┘
            ▼
┌───────────────────────┐
│ Main / Executor LLM   │   reasons, retrieves, plans, proposes actions
└───────────┬───────────┘
            │ ProposedAction
            ▼
┌───────────────────────┐
│ Output Security Agent │   goal integrity, tool misuse, exfiltration,
│                       │   privilege abuse, sensitive data, provenance
└───────────┬───────────┘
            ▼
┌───────────────────────┐
│ Deterministic Policy  │   independent, non-LLM enforcement
│ Engine                │
└───────────┬───────────┘
      ┌──────┼──────┐
      ▼      ▼      ▼
    ALLOW APPROVAL DENY
      │
      ▼
┌───────────────────────┐
│ Execution Proxy       │   the ONLY component that invokes real tools
└───────────┬───────────┘
            ▼
          Tools
```

## The Non-Negotiable Security Boundary

> The main agent **proposes** actions. The security controller **authorizes** them. Only the execution proxy **executes** them.

Enforce these invariants in any code you write:

- The main LLM must **never** have direct, unrestricted access to dangerous tools.
- The main agent must **not** possess any bypass path to the underlying tool layer.
- The execution proxy must **reject** any request lacking a valid authorization decision.
- The security LLM is **advisory only** — it is not the final boundary. A deterministic policy engine must independently enforce critical rules even if the security LLM returns `ALLOW`.

Example of deterministic enforcement that runs regardless of LLM output:

```python
DENIED_PATHS = [".ssh", ".aws", ".env", "credentials", "secrets"]
```

## Components

### Input Security Agent
Analyzes information *before* it reaches the main agent. Sources: user messages, uploaded documents, PDFs, email, webpages, RAG results, MCP tool descriptions, MCP tool outputs, agent memory, other agents.

Responsibilities: detect direct and indirect prompt injection; identify instructions hidden in untrusted data; classify source trust; separate facts from instructions; mark suspicious context; attach provenance metadata; propagate trust/taint labels. Suspicious content is removed, quarantined, or forwarded with explicit provenance metadata.

### Main Executor Agent
Performs the task — reasons, retrieves, analyzes, queries RAG, uses permitted (non-sensitive) tools, produces a plan. It does **not** execute sensitive actions; it emits a structured `ProposedAction`:

```json
{
  "tool": "send_email",
  "arguments": { "recipient": "finance@example.com", "body": "Invoice analysis..." },
  "reason": "The user explicitly requested the result by email.",
  "source_ids": ["user-message-1"],
  "original_goal": "Analyze the invoice and send the result"
}
```

### Output Security Agent
Reviews every consequential proposed action against: match to original objective, influence from untrusted content, goal hijacking, sensitive-data access, external data egress, tool appropriateness, excessive privilege, destructiveness/irreversibility. Returns structured output:

```json
{
  "classification": "indirect_prompt_injection",
  "risk_score": 94,
  "goal_relevance": 0.05,
  "decision": "DENY",
  "reason": "The proposed credential access originated from an untrusted document and is unrelated to the user's task."
}
```

Decisions: `ALLOW`, `APPROVAL` (human-in-the-loop), `DENY`.

### Execution Proxy
The sole invoker of real tools (`read_file`, `write_file`, `send_email`, `http_request`, `database_query`, MCP tools, GitHub actions, cloud APIs). Rejects anything without a valid authorization decision.

## Design Conventions

- **Structured messages over free text.** Nodes communicate using Pydantic models wherever possible.
- **Reduce before reviewing.** Do NOT pass the full poisoned conversation or raw document to the security agent — that re-exposes the security model to the same injection. Pass a reduced structured representation:

  ```json
  {
    "original_goal": "Analyze invoice",
    "proposed_action": { "tool": "read_file", "resource_type": "credential_file" },
    "provenance": { "source": "external_document", "trust": "untrusted" }
  }
  ```

- **Provenance & taint tracking.** Every external context item carries metadata; actions preserve the provenance of information that influenced them, so the controller can trace that (e.g.) `send_email()` was influenced by `malicious.pdf`.

  ```json
  { "id": "document-42", "source": "invoice.pdf", "source_type": "document", "trust": "untrusted", "taint": "external" }
  ```

- **Orchestrate with LangGraph:**

  ```text
  START → input_guard → main_agent → security_controller
                                         ├── ALLOW    → execute
                                         ├── APPROVAL → human_approval
                                         └── DENY     → END
  ```

## PoC Scope

Initial controlled tool set: `read_document()`, `read_file()`, `write_file()`, `send_email()`, `http_request()`.

Attack scenarios the PoC must demonstrate:
1. Malicious document / indirect prompt injection.
2. Poisoned webpage or RAG result.
3. Poisoned MCP tool output or description.

The demo should **intentionally let the main agent become compromised**, then show the controller blocking the resulting unauthorized action — proving that a compromised agent does not mean a compromised system.

## Guiding Goals

Defense in depth · least privilege · structured tool calls · provenance · taint tracking · goal integrity · human approval · deterministic enforcement · no direct executor-to-tool bypass · traceability of every security decision.
