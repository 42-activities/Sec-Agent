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
sec-web                            # or: python -m sec_agent.web.app  → http://127.0.0.1:8000
```

### Bedrock / credentials

- Credentials come from the environment via `.env` (gitignored; copy from `env.example`). `sec_agent/config.py` calls `load_dotenv()` so boto3 sees `AWS_BEARER_TOKEN_BEDROCK`.
- Hackathon auth is a **Bedrock API key** (bearer token, short-lived ~12h) in `AWS_BEARER_TOKEN_BEDROCK`, region `us-west-2`. Regenerate from the Bedrock console → API keys when it expires.
- **Model IDs must be inference profiles** (`us.anthropic.*`); bare `anthropic.*` IDs fail on-demand with a ValidationException. List them: `aws bedrock list-inference-profiles --region us-west-2`.
- Verified working: executor `us.anthropic.claude-sonnet-4-5-20250929-v1:0`, security `us.anthropic.claude-haiku-4-5-20251001-v1:0`. Override via `EXECUTOR_MODEL_ID` / `SECURITY_MODEL_ID`.

### Layout

`sec_agent/` — `config.py` (settings + denylist), `models.py` (Pydantic contracts + `AgentState`), `llm.py` (Bedrock model factories), `nodes/` (`input_guard`, `executor`, `security`, `policy`), `proxy.py` (execution proxy — only tool executor), `tools/` (the controlled tool set), `graph.py` (LangGraph wiring), `demo/`, `web/` (FastAPI app + static UI). Tests in `tests/`.

`web/app.py` exposes the human-in-the-loop flow: `POST /analyze` runs the controller and **stops before execution** (graph built with `execute=False`), stashing state under a session id; `POST /execute` runs the proxy with the human's approve/deny. `build_graph(include_executor=, execute=)` controls both the compromised-executor simulation and the stop-before-execute behavior.

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
