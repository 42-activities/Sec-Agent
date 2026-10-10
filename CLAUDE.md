# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current State

Working PoC, deployed at https://sec-agent.naurzalinov.me. Stack: Python (>=3.10) + LangGraph + `langchain-aws` (Amazon Bedrock) + Pydantic + FastAPI, optional Jev (TypeSafe AI) classifier. The full `input_guard → executor → security → policy → proxy` pipeline runs end-to-end with a live-streaming UI (`/`), editable policy rules (`/rules`), human approval, and a SOC dashboard (`/soc`). Demo scenarios cover two domains (finance, recruiting).

### Commands

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,web]"        # install package + dev + web deps

pytest -q                          # offline tests: policy, tools, rules, Jev (mocked), events — no network
pytest tests/test_policy.py -q     # single test file
python -m sec_agent.demo.poisoned_invoice   # live end-to-end demo (needs Bedrock creds)
sec-web                            # single-process web UI → http://127.0.0.1:8000
sec-proxy                          # standalone execution-proxy service (:8001)
```

Two-container deployment (privilege separation; needs `.env` with `PROXY_AUTH_TOKEN` + Bedrock creds; optional `TYPESAFE_API_KEY` for Jev, `RULES_ADMIN_TOKEN` to enable rule editing):

```bash
docker compose up --build          # controller → 127.0.0.1:8700 (SEC_AGENT_PORT) + proxy (internal only)
```

### Bedrock / credentials

- Credentials come from the environment via `.env` (gitignored; copy from `env.example`). `sec_agent/config.py` calls `load_dotenv()` so boto3 sees `AWS_BEARER_TOKEN_BEDROCK`.
- Hackathon auth is a **Bedrock API key** (bearer token, short-lived ~12h) in `AWS_BEARER_TOKEN_BEDROCK`, region `us-west-2`. Regenerate from the Bedrock console → API keys when it expires.
- **Model IDs must be inference profiles** (`us.anthropic.*`); bare `anthropic.*` IDs fail on-demand with a ValidationException. List them: `aws bedrock list-inference-profiles --region us-west-2`.
- Verified working: executor `us.anthropic.claude-sonnet-4-5-20250929-v1:0`, security `us.anthropic.claude-haiku-4-5-20251001-v1:0`. Override via `EXECUTOR_MODEL_ID` / `SECURITY_MODEL_ID`.

### Layout

`sec_agent/` — `config.py` (settings; factory defaults for the rules), `models.py` (Pydantic contracts + `AgentState`), `llm.py` (Bedrock model factories), `nodes/` (`input_guard`, `executor`, `security`, `policy`), `rules.py` (editable rule lists), `jev.py` (Jev risk scoring), `events.py` (SOC event log + summary), `proxy.py` (in-process execution proxy), `proxy_client.py` + `proxy_service/` (two-container proxy), `tools/` (the controlled tool set, sandboxed), `graph.py` (LangGraph wiring), `demo/` (CLI demo), `web/` (FastAPI app; static pages `index.html` controller, `rules.html`, `soc.html`). Tests in `tests/` (`conftest.py` isolates rules/events files and disables Jev). Deployment: `Dockerfile`, `docker-compose.yml`, `deploy/` (host nginx vhost), `.github/workflows/`.

`web/app.py` exposes the human-in-the-loop flow: `POST /analyze` runs the controller and **stops before execution** (graph built with `execute=False`), stashing state under a session id; `POST /execute` runs the proxy with the human's approve/deny. `POST /analyze/stream` is the same run but emits one NDJSON event per graph node (`graph.stream(stream_mode="updates")`) — the UI (`web/static/index.html`) uses it to animate Input → input guard → executor → output guard → proxy live. It sets `X-Accel-Buffering: no` so nginx doesn't buffer it. `GET /health` is used by the deploy health check. `build_graph(include_executor=, execute=)` controls both the compromised-executor simulation and the stop-before-execute behavior.

### Two-container security split

`docker-compose.yml` runs two containers from one image (`Dockerfile`), separated by **credentials and network**, which turns the "no executor→tool bypass" invariant into a hard boundary:

- **controller** (`sec-web`, :8000 in-container, published on `127.0.0.1:8700` only; `WEB_HOST=0.0.0.0` inside the container): web UI + input_guard + executor LLM + security LLM + policy engine + SOC event log (`events-data` volume). Holds the **Bedrock token** and the optional **Jev key** — no tool credentials, no rules admin password; has internet egress (Bedrock, TypeSafe). When `PROXY_URL` is set, `/execute` forwards to the proxy via `sec_agent/proxy_client.py` instead of executing in-process.
- **proxy** (`sec-proxy`, :8001, `sec_agent/proxy_service/`): the execution proxy + real tools, and the **owner of the editable rules** (`rules-data` volume, `RULES_ADMIN_TOKEN`). Holds **tool credentials only**, **no Bedrock/Jev access**, on an `internal: true` network (no host port, no internet egress).

The proxy service is **zero-trust toward the controller**: `POST /execute-action` ignores the caller's claimed decision and independently re-runs `policy.evaluate()`, refusing any DENY (and any APPROVAL without approval). A compromised controller therefore still cannot reach a denied resource. Services authenticate with the shared `PROXY_AUTH_TOKEN`.

### Deployment & CI/CD

- Live at **https://sec-agent.naurzalinov.me** (Hetzner arm64 host). Host nginx (`deploy/sec-agent.naurzalinov.me`, TLS via certbot) proxies to `127.0.0.1:8700`. Pages are public; the only login is the admin password for editing rules.
- `.github/workflows/pipeline.yml`: on push to `main` → `ci.yml` (pytest) → `docker-deploy.yml` builds `ghcr.io/42-activities/sec-agent-app:<sha>` for arm64, SSHes to the server, pulls, `docker compose up`, checks `/health`, rolls back on failure. PRs only test + build. Same pattern as LegoBot.
- **The server's `.env` is rewritten on every deploy** from GitHub secrets (`AWS_BEARER_TOKEN_BEDROCK`, `PROXY_AUTH_TOKEN`, `TYPESAFE_API_KEY`, `RULES_ADMIN_TOKEN` — the last two optional; empty = feature off) and variables (`AWS_REGION`, `EXECUTOR_MODEL_ID`, `SECURITY_MODEL_ID`). Never edit `.env` on the server; rotate the Bedrock key with `gh secret set AWS_BEARER_TOKEN_BEDROCK && gh workflow run pipeline.yml`.
- Actions are on their Node 24 majors (checkout/setup-python v7, docker/* v4, build-push v7); runners pinned to `ubuntu-24.04`.
- Deploy aborts if the server checkout (`~/projects/Sec-Agent`) has uncommitted changes to tracked files.

### Tools & demo scenarios

- `respond_to_user(answer)` is the executor's "just answer" action: allowed, not consequential, and in `output_only_tools`, so the resource denylist does not scan its free text (an answer may legitimately quote `~/.ssh/...` while warning the user).
- Proxies call tools via `tools.invoke(tool, args, documents)`. `read_document("document-1")` resolves pasted (untrusted) context items by ID; the two-container `proxy_client` ships only the one document a `read_document` call names.
- **Human in the loop.** `APPROVAL` stops before execution; the UI shows an approval card (exact arguments + policy/LLM reasons) and `/execute` runs only with the human's answer. `DENY` can never be overridden by a human.
- **Security checklist** (`models.Check`): every run records rows P1–P9 (input guard, `state["input_checks"]`) and T1–T10 (policy node; `state["checks"]` = input + action), each with `checked_by`, `result` (pass/flag/fail/n/a/not_checked), `evidence`, `effect`. Rows go to the audit trail as `[check] …` lines, the stream (`input_guard`/`policy` events), the UI tables, SOC incidents and the SOC "criteria flagged or failed" chart. `policy.evaluate_checks()` runs every action criterion; `decide()` derives the decision (most restrictive `effect`) and reasons (evidence of rows with an effect); `evaluate()` = both, used by controller **and** proxy. T4 (security LLM) and T10 (combined) are added in `policy_node`.
- Action criteria (`nodes/policy.py`): T1 tool allow-list → T2 resource denylist (n/a for `output_only_tools`) → T3 destination: `send_email` only to `allowed_email_domains`, `http_request` only to `allowed_http_hosts` (+subdomains) — else DENY → T5 influence: **any** untrusted item in context counts, cited or not (self-reported `source_ids` can't be trusted) → T6 `approval_required_tools` always APPROVAL / consequential + influenced APPROVAL → T7 credential patterns in outbound `body`/`url`/`content` DENY → T8 unexpected/missing args flag → T9 not checked (no rate limit yet).
- Input criteria (`nodes/input_guard.py`): sensitive-word patterns are split — concrete targets (`.ssh`, `id_rsa`, `id_ed25519`, `.aws`, `.env`, `private key`, `/etc/shadow`) taint on their own; weak words (`secret`, `password`, `credential`) count only with an injection phrase, hidden text, or a role-relevant Jev signal ≥ 0.5 (user prompts: jailbreak/secrets; documents: ai_instructions/redirect/secrets/jailbreak). Otherwise P4 says "mentions … not enough on its own". This removed 22 of 25 false alarms seen on the user's labeled dataset. P8 `hidden_text()` finds zero-width/bidi/Unicode-tag characters, HTML comments, base64 that decodes to text, mixed Latin/Cyrillic/Greek words; any finding taints the item SUSPICIOUS, and the revealed text is also regex-scanned and sent to Jev. P9 (the user's own prompt) is n/a by design.
- **Editable rules** (`sec_agent/rules.py`, page `/rules`, API `GET/PUT /api/rules`, `POST /api/rules/reset`): the rule *logic* is code; the lists it checks (allowed tools, denylist, email domains, HTTP hosts, approval tools, Jev thresholds) are a JSON file. `config.py` values are only factory defaults. `policy.evaluate(action, items, rules=None)` uses `rules.active()` — the local file, or in two-container mode the **proxy's** copy via `GET /rules`. The proxy owns the file (`RULES_FILE=/data/rules.json`, `rules-data` volume) and alone holds `RULES_ADMIN_TOKEN`; the controller only relays edits carrying the human's `X-Admin-Token`, so a compromised controller can't loosen rules. Viewing is public; editing is disabled when the token is empty (GitHub secret `RULES_ADMIN_TOKEN`, written to `.env` by the pipeline). Tests use an autouse fixture (`tests/conftest.py`) that points `rules_file` at a temp path. `tests/test_rules_flow.py` wires the real controller and proxy apps together over (patched) HTTP and proves the full path: edit on `/rules` → relayed to the proxy (admin password checked there) → next controller decision changes → proxy re-checks and executes. **Rules are universal only** — no domain-specific rules (the payment tool and payee/IBAN rule were removed on purpose); `approval_required_tools` defaults to empty.
- **Jev (TypeSafe AI)** (`sec_agent/jev.py`, SDK `typesafe-sdk`): the input guard sends each *untrusted* context item (never the user's request) to Jev, which rates prompt-injection risk on a 0/20/40/60/80/100 `Score` plus five `Noul` signals (instructions to an AI, redirect of data/money, asks for secrets, pressure, jailbreak). Shown in the Input guard card. At/above `jev_suspicious_level` (editable rule, default 60), **or** when any decisive signal (AI instructions / redirect / secrets — not pressure) reaches `jev_signal_threshold` (editable, default 0.9), the item becomes `SUSPICIOUS`; Jev can only raise taint, never lower it. Advisory — no policy decision depends on it directly. Enabled only when `TYPESAFE_API_KEY` is set (controller container only; GitHub secret); API errors fall back to regex. Tests mock the client and `conftest.py` blanks the key. Note: untrusted documents (incl. CV personal data) are sent to TypeSafe.
- **SOC dashboard** (`sec_agent/events.py`, page `/soc`, API `GET /api/soc/summary?hours=`, `GET /api/soc/events/{id}`): one row per controller run in SQLite (`EVENTS_DB`, `events-data` volume on the controller), written by `/analyze`, `/analyze/stream` and updated by `/execute`; also one JSON line per event on stdout (`sec_agent.decision` / `sec_agent.execution`) for a log shipper/SIEM. The raw document is never stored (length + hash only); free text truncated. `classify()` names the attack from the deterministic rule that fired, else the security LLM's label **only if it voted DENY**, else suspicious input taint. The narrative summary is templated from the numbers (no LLM). In `web/app.py` the module is imported as `event_log` — the stream endpoint has an inner generator named `events`.
- **Batch screening** (`sec_agent/batch.py`, page `/batch`, `POST /api/batch` NDJSON stream, `mode` = `input` ≤500 prompts | `full` ≤25): each prompt becomes the *user's own request* with `state["scan_user_prompt"]=True`, so the input guard also scans the trusted user item (findings taint it SUSPICIOUS; P9 becomes a real check). `input` runs `input_guard_node` only; `full` runs the graph with `execute=False`. Jev is role-aware: for `source_type == "user_message"` only `jailbreak` and `secrets` are decisive signals (a user prompt is always "an instruction to an AI" and may legitimately ask to send things); for documents `ai_instructions`/`redirect`/`secrets`/`jailbreak`. Detector attribution uses `state["input_findings"]`. Batch runs are not written to the SOC event log. Each result carries `predicted` (1/0 = input-stage injection verdict) and a templated `explanation` (`batch.explain`). Accuracy evaluation is client-side in `batch.html`: CSV col 1 prompt, col 2 label (header optional; also JSONL `label`, or `prompt<TAB>0/1` lines) → TP/FP/TN/FN, accuracy/precision/recall/F1/FPR, export with predicted + explanation columns. `input` mode limit is 1000 prompts.
- `read_file`/`write_file`/`read_document` are confined to `settings.files_root` (`/tmp/sec-agent-files`); absolute paths are re-rooted and `..` escapes raise. This matters because the public demo lets anyone force tool calls.
- UI scenarios (`SCENARIOS` in `index.html`), two groups: **Invoices** (clean invoice, hijacked agent, credential theft) and **Recruiting** (screen a CV → approval for the summary email, candidate-data theft). Scenarios with `tool`/`args` run in compromised-executor mode for reliability; "Hijacked agent" is the one where the live Sonnet executor is genuinely fooled (it follows an AP-workflow note and proposes `send_email` to the attacker), and that injection also slips past the regex input guard — the output side catches it. The live model resists the CV-reroute injection, hence compromised mode there.

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
The sole invoker of real tools. Implemented: `respond_to_user`, `read_document`, `read_file`, `write_file`, `send_email`, `http_request` (email/HTTP are stubs; file tools are sandboxed). Planned: `database_query`, MCP tools, GitHub actions, cloud APIs. Rejects anything without a valid authorization decision.

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

- **Orchestrate with LangGraph** (`graph.py`):

  ```text
  START → input_guard → executor → security → policy ─┬─ DENY ─────────────→ END
                                                       └─ ALLOW / APPROVAL → execute (proxy)
  ```

  The web app builds the graph with `execute=False` (stops after `policy`), then `/execute` runs the proxy with the human's answer — APPROVAL is the human gate, DENY can never execute.

## PoC Scope

Tool set: `respond_to_user`, `read_document`, `read_file`, `write_file`, `send_email`, `http_request`.

Attack scenarios the PoC must demonstrate:
1. Malicious document / indirect prompt injection — **done** (invoices and CVs: credential theft, data exfiltration, a live-executor hijack).
2. Poisoned webpage or RAG result — **not yet** (the input path accepts any text, but there is no webpage/RAG source or scenario).
3. Poisoned MCP tool output or description — **not yet**.

The demo should **intentionally let the main agent become compromised**, then show the controller blocking the resulting unauthorized action — proving that a compromised agent does not mean a compromised system.

## Guiding Goals

Defense in depth · least privilege · structured tool calls · provenance · taint tracking · goal integrity · human approval · deterministic enforcement · no direct executor-to-tool bypass · traceability of every security decision.
