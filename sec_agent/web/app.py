"""FastAPI surface for the security controller.

Flow mirrors the architecture's human-in-the-loop:

  POST /analyze  -> runs input_guard -> executor -> security -> policy, STOPS
                    before execution, returns the decision + audit, and stashes
                    the pending state under a session id.
  POST /analyze/stream -> same as /analyze, but streams one NDJSON event per
                    graph node as it completes, so the UI can animate the flow live.
  POST /execute  -> runs the execution proxy for that session with the human's
                    approve/deny answer. DENY is never executable.

The executor has no path to the tools except through /execute, which refuses
anything without a final ALLOW (or an APPROVAL the human approves).
"""

from __future__ import annotations

import json
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Cookie, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..config import settings
from .. import rules as rules_store
from .. import events as event_log
from .. import gmail
from .. import screening
from .. import hr_log
from .. import jev
from ..graph import build_graph
from ..models import AgentState, ContextItem, Decision, ProposedAction, Trust
from ..nodes.input_guard import _INJECTION_RE, _SENSITIVE_RE, _WEAK_SENSITIVE_RE
from ..proxy import execution_proxy_node
from ..proxy_client import remote_execute
from ..nodes.policy import evaluate as policy_evaluate
from ..tools import REGISTRY
from ..tools import invoke as tool_invoke

app = FastAPI(title="Sec-Agent Security Controller", version="0.1.0")

# In-memory pending sessions (fine for a PoC; swap for Redis/DB in production).
_SESSIONS: dict[str, AgentState] = {}

_STATIC = Path(__file__).parent / "static"


# --------------------------- request / response models ---------------------------

class AnalyzeRequest(BaseModel):
    user_goal: str = Field(..., description="The user's actual request.")
    document: str = Field("", description="Untrusted document / webpage / RAG content.")
    document_source: str = "uploaded_document"
    document_type: str = Field("document", pattern="^(document|email|webpage)$")
    # Simulate a compromised executor that already proposed a specific action.
    force_tool: Optional[str] = None
    force_arguments: dict[str, Any] = Field(default_factory=dict)


class DecisionView(BaseModel):
    session_id: str
    final_decision: str
    proposed_action: Optional[dict] = None
    security: Optional[dict] = None
    policy_reasons: list[str] = Field(default_factory=list)
    provenance: list[dict] = Field(default_factory=list)
    audit: list[str] = Field(default_factory=list)
    executed: Optional[str] = None


class ExecuteRequest(BaseModel):
    session_id: str
    approve: bool = False


# --------------------------------- helpers ---------------------------------------

def _build_state(req: AnalyzeRequest) -> AgentState:
    items = [
        ContextItem(
            id="user-request", source="chat", source_type="user_message",
            content=req.user_goal, trust=Trust.TRUSTED,
        )
    ]
    if req.document.strip():
        items.append(
            ContextItem(
                id="document-1", source=req.document_source,
                source_type=req.document_type, content=req.document, trust=Trust.UNTRUSTED,
            )
        )
    return {"user_goal": req.user_goal, "context_items": items, "audit": []}


def _view(session_id: str, state: AgentState) -> DecisionView:
    action: Optional[ProposedAction] = state.get("proposed_action")
    sec = state.get("security_decision")
    items = {i.id: i for i in state.get("context_items", [])}
    provenance = []
    if action:
        for sid in action.source_ids:
            it = items.get(sid)
            if it:
                provenance.append(
                    {"id": it.id, "source": it.source, "trust": it.trust.value,
                     "taint": it.taint.value, "instruction_detected": it.instruction_detected}
                )
    final = state.get("final_decision")
    return DecisionView(
        session_id=session_id,
        final_decision=final.value if final else "n/a",
        proposed_action=(
            {"tool": action.tool, "arguments": action.arguments,
             "reason": action.reason, "original_goal": action.original_goal}
            if action else None
        ),
        security=(
            {"classification": sec.classification, "risk_score": sec.risk_score,
             "goal_relevance": sec.goal_relevance, "decision": sec.decision.value,
             "reason": sec.reason}
            if sec else None
        ),
        policy_reasons=state.get("policy_reasons", []),
        provenance=provenance,
        audit=state.get("audit", []),
        executed=state.get("execution_result"),
    )


# --------------------------------- endpoints -------------------------------------

def _prepare(req: AnalyzeRequest):
    """Build the initial state and the graph for a request (shared by both analyze routes)."""
    state = _build_state(req)
    if req.force_tool:
        # Simulated compromised executor: inject the action, skip the executor LLM.
        state["proposed_action"] = ProposedAction(
            tool=req.force_tool, arguments=req.force_arguments,
            reason="(injected) executor was compromised by the document",
            source_ids=["document-1"], original_goal=req.user_goal,
        )
        graph = build_graph(include_executor=False, execute=False)
    else:
        graph = build_graph(include_executor=True, execute=False)
    return state, graph


def _loggable(req: AnalyzeRequest) -> bool:
    """Runs on an email from someone's Gmail are never written to the (public) SOC log: its
    audit lines and checklist evidence can quote the email. /execute then finds no row either."""
    return req.document_source != "gmail"


def _action_view(action: Optional[ProposedAction]) -> Optional[dict]:
    if action is None:
        return None
    return {"tool": action.tool, "arguments": action.arguments, "reason": action.reason,
            "source_ids": action.source_ids, "original_goal": action.original_goal}


def _findings(text: str) -> list[str]:
    """Snippets the input guard matched, so the UI can show *why* an item was flagged."""
    hits = [m.group(0) for r in (_INJECTION_RE, _SENSITIVE_RE, _WEAK_SENSITIVE_RE) for m in r.finditer(text)]
    return list(dict.fromkeys(hits))[:8]


def _node_data(node: str, state: AgentState) -> dict:
    """The slice of state a given node produced, in a JSON-friendly shape."""
    if node == "input_guard":
        return {"items": [
            {"id": i.id, "source": i.source, "source_type": i.source_type,
             "trust": i.trust.value, "taint": i.taint.value, "risk": i.risk,
             "instruction_detected": i.instruction_detected,
             "findings": _findings(i.content) if i.trust != Trust.TRUSTED else [],
             "jev": state.get("jev_input", {}).get(i.id)}
            for i in state.get("context_items", [])
        ], "jev_enabled": jev.enabled(),
            "checks": [c.model_dump(mode="json") for c in state.get("input_checks", [])]}
    if node == "executor":
        return {"proposed_action": _action_view(state.get("proposed_action"))}
    if node == "security":
        return {"security": _view("", state).security}
    if node == "policy":
        pd, fd = state.get("policy_decision"), state.get("final_decision")
        return {"policy_decision": pd.value if pd else None,
                "final_decision": fd.value if fd else None,
                "reasons": state.get("policy_reasons", []),
                "checks": [c.model_dump(mode="json") for c in state.get("checks", []) if c.stage == "action"]}
    return {}


@app.post("/analyze", response_model=DecisionView)
def analyze(req: AnalyzeRequest) -> DecisionView:
    state, graph = _prepare(req)
    result = graph.invoke(state)
    session_id = uuid.uuid4().hex
    _SESSIONS[session_id] = result
    if _loggable(req):
        event_log.record_analysis(session_id, result, compromised=bool(req.force_tool))
    return _view(session_id, result)


@app.post("/analyze/stream")
def analyze_stream(req: AnalyzeRequest) -> StreamingResponse:
    state, graph = _prepare(req)
    session_id = uuid.uuid4().hex

    def line(event: dict) -> str:
        return json.dumps(event, default=str) + "\n"

    def events():
        merged: AgentState = dict(state)  # type: ignore[assignment]
        yield line({"type": "start", "session_id": session_id,
                    "executor_skipped": bool(req.force_tool),
                    "injected_action": _action_view(state.get("proposed_action"))})
        t0 = time.perf_counter()
        try:
            for chunk in graph.stream(state, stream_mode="updates"):
                for node, update in chunk.items():
                    seen = len(merged.get("audit", []))
                    merged.update(update or {})
                    now = time.perf_counter()
                    yield line({"type": "node", "node": node,
                                "ms": round((now - t0) * 1000),
                                "data": _node_data(node, merged),
                                "audit": merged.get("audit", [])[seen:]})
                    t0 = now
        except Exception as exc:  # surface model/credential errors to the UI
            yield line({"type": "error", "detail": f"{type(exc).__name__}: {exc}"})
            return
        _SESSIONS[session_id] = merged
        if _loggable(req):
            event_log.record_analysis(session_id, merged, compromised=bool(req.force_tool))
        yield line({"type": "done", "view": _view(session_id, merged).model_dump()})

    # X-Accel-Buffering: tell nginx not to buffer, so events reach the browser as they happen.
    return StreamingResponse(events(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/execute", response_model=DecisionView)
def execute(req: ExecuteRequest, sa_gmail: str = Cookie(default="")) -> DecisionView:
    state = _SESSIONS.get(req.session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="unknown or expired session")

    # The user's own Gmail token, only for read_email. It is never in the agent's state.
    action = state.get("proposed_action")
    conn = _gmail_conn(sa_gmail) if action is not None and action.tool == "read_email" else None
    credentials = {"gmail": conn["token"]} if conn else None
    if settings.proxy_url:
        # Two-container mode: forward to the isolated proxy service.
        updated = remote_execute(state, approve=req.approve, credentials=credentials)
    else:
        # Single-process mode: execute in-process.
        updated = execution_proxy_node(state, approval_fn=lambda _s: req.approve, credentials=credentials)
    merged: AgentState = {**state, **updated}
    _SESSIONS[req.session_id] = merged
    event_log.record_execution(req.session_id, merged, req.approve)
    hr_log.on_execute(req.session_id, req.approve, merged.get("execution_result") is not None)
    return _view(req.session_id, merged)


# ------------------------------------ Gmail --------------------------------------
# Each visitor signs in with Google and connects their own mailbox, read-only. The access
# token stays in this process's memory (keyed by a random HttpOnly cookie) and expires
# with Google's token (~1 h); there is no refresh token. Redeploy = everyone reconnects.

_GMAIL: dict[str, dict] = {}
_GMAIL_LOCK = threading.Lock()
_COOKIE, _STATE_COOKIE = "sa_gmail", "sa_oauth_state"


def _gmail_conn(sid: str) -> Optional[dict]:
    with _GMAIL_LOCK:
        conn = _GMAIL.get(sid or "")
        if conn and conn["expires"] <= time.time():
            _GMAIL.pop(sid, None)
            return None
        return conn


def _base_url(request: Request) -> str:
    # Behind nginx the app sees http://127.0.0.1; prefer the configured public URL.
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return settings.public_url or f"{proto}://{request.headers.get('host', request.url.netloc)}"


def _secure(request: Request) -> bool:
    return _base_url(request).startswith("https://")


@app.get("/api/gmail/status")
def gmail_status(sa_gmail: str = Cookie(default="")) -> dict:
    conn = _gmail_conn(sa_gmail)
    return {"configured": gmail.enabled(), "connected": bool(conn),
            "email": conn["email"] if conn else None,
            "expires_in": round(conn["expires"] - time.time()) if conn else None}


@app.get("/auth/google/start")
def gmail_start(request: Request, next: str = "/") -> Response:
    if not gmail.enabled():
        raise HTTPException(status_code=404, detail="Gmail is not configured on this server")
    state = secrets.token_urlsafe(24)
    page = {"/batch": "batch", "/demo-hr": "hr"}.get(next, "home")  # where to land afterwards (cookie-safe word)
    resp = RedirectResponse(gmail.auth_url(gmail.redirect_uri(_base_url(request)), state), status_code=302)
    resp.set_cookie(_STATE_COOKIE, f"{state}.{page}", max_age=600, httponly=True, samesite="lax",
                    secure=_secure(request), path="/auth/google")
    return resp


@app.get("/auth/google/callback")
def gmail_callback(request: Request, state: str = "", code: str = "", error: str = "",
                   sa_oauth_state: str = Cookie(default="")) -> Response:
    expected, _, page = sa_oauth_state.partition(".")
    if not expected or not secrets.compare_digest(expected, state):  # CSRF: must be our own sign-in
        raise HTTPException(status_code=400, detail="sign-in expired or not started here — try again")
    nxt = {"batch": "/batch", "hr": "/demo-hr"}.get(page, "/")
    if error or not code:
        resp = RedirectResponse(f"{nxt}?gmail=denied", status_code=302)
    else:
        try:
            tok = gmail.exchange(code, gmail.redirect_uri(_base_url(request)))
        except gmail.GmailError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        sid = secrets.token_urlsafe(32)
        with _GMAIL_LOCK:
            _GMAIL[sid] = {"token": tok["access_token"], "email": tok["email"],
                           "expires": time.time() + tok["expires_in"] - 60}
        resp = RedirectResponse(f"{nxt}?gmail=connected", status_code=302)
        resp.set_cookie(_COOKIE, sid, max_age=tok["expires_in"], httponly=True, samesite="lax",
                        secure=_secure(request))
    resp.delete_cookie(_STATE_COOKIE, path="/auth/google")
    return resp


@app.post("/auth/google/logout")
def gmail_logout(sa_gmail: str = Cookie(default="")) -> Response:
    with _GMAIL_LOCK:
        conn = _GMAIL.pop(sa_gmail or "", None)
    if conn:
        gmail.revoke(conn["token"])  # also withdraw the grant at Google
    resp = Response(status_code=204)
    resp.delete_cookie(_COOKIE)
    return resp


@app.get("/api/gmail/messages")
def gmail_messages(q: str = "", n: int = 25, sa_gmail: str = Cookie(default="")) -> dict:
    """The user loading their own inbox as INPUT for /batch (like uploading a file) — not an
    agent action, so it does not go through the proxy. Nothing is stored server-side."""
    conn = _gmail_conn(sa_gmail)
    if not conn:
        raise HTTPException(status_code=401, detail="Gmail is not connected")
    try:
        emails = gmail.list_messages(conn["token"], q, n, limit=settings.gmail_batch_max)
    except gmail.GmailError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"emails": [{**e, "text": gmail.as_text(e)} for e in emails]}


# ------------------------------------ rules --------------------------------------
# Viewing is public; editing needs the admin password (X-Admin-Token). In two-container
# mode the proxy owns the rules and checks the password itself — we only relay.

def _relay(method: str, path: str, admin_token: str, body: Optional[dict] = None) -> dict:
    import requests

    try:
        r = requests.request(method, f"{settings.proxy_url}{path}", json=body, timeout=10,
                             headers=rules_store._proxy_headers(admin_token))
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"proxy unreachable: {exc}")
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=r.json().get("detail", r.text))
    return r.json()


@app.get("/api/rules")
def api_get_rules() -> dict:
    if settings.proxy_url:
        rules, editable = rules_store.fetch_remote()
    else:
        rules, editable = rules_store.load_local(), bool(settings.rules_admin_token)
    return {"rules": rules.model_dump(), "editable": editable,
            "defaults": rules_store.defaults().model_dump(), "tools": sorted(REGISTRY)}


@app.put("/api/rules")
def api_put_rules(new: rules_store.Rules, x_admin_token: str = Header(default="")) -> dict:
    if settings.proxy_url:
        return _relay("PUT", "/rules", x_admin_token, new.model_dump())
    if not rules_store.admin_ok(x_admin_token):
        raise HTTPException(status_code=403, detail="wrong admin password, or editing disabled")
    return {"rules": rules_store.save_local(new).model_dump(), "editable": True}


@app.post("/api/rules/reset")
def api_reset_rules(x_admin_token: str = Header(default="")) -> dict:
    if settings.proxy_url:
        return _relay("POST", "/rules/reset", x_admin_token)
    if not rules_store.admin_ok(x_admin_token):
        raise HTTPException(status_code=403, detail="wrong admin password, or editing disabled")
    return {"rules": rules_store.reset_local().model_dump(), "editable": True}


@app.get("/rules")
def rules_page() -> FileResponse:
    return FileResponse(_STATIC / "rules.html")


# ------------------------------------ batch --------------------------------------

class BatchRequest(BaseModel):
    prompts: list[str]
    mode: str = Field("input", pattern="^(input|full)$")
    llm: bool = False  # also ask the LLM to classify each prompt (for comparison)
    # "prompt" = the user's own request (direct injection); "email" = untrusted content the
    # user received (indirect injection), scanned as a document.
    kind: str = Field("prompt", pattern="^(prompt|email)$")


@app.post("/api/batch")
def batch_run(req: BatchRequest) -> StreamingResponse:
    from .. import batch

    prompts = [p.strip() for p in req.prompts if p and p.strip()]
    if not prompts:
        raise HTTPException(status_code=400, detail="no prompts")
    limit = min(batch.MAX_PROMPTS[req.mode], batch.MAX_LLM_PROMPTS) if req.llm else batch.MAX_PROMPTS[req.mode]
    if len(prompts) > limit:
        raise HTTPException(status_code=400, detail=f"at most {limit} prompts per batch in '{req.mode}' mode"
                                                    + (" with the LLM classifier" if req.llm else ""))
    if any(len(p) > batch.MAX_CHARS for p in prompts):
        raise HTTPException(status_code=400, detail=f"each prompt must be at most {batch.MAX_CHARS} characters")

    def stream():
        yield json.dumps({"type": "start", "total": len(prompts), "mode": req.mode, "jev": jev.enabled(),
                          "llm": req.llm, "kind": req.kind}) + "\n"
        for result in batch.run(prompts, req.mode, req.llm, req.kind):
            yield json.dumps({"type": "result", **result}, default=str) + "\n"
        yield json.dumps({"type": "done"}) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/batch")
def batch_page() -> FileResponse:
    return FileResponse(_STATIC / "batch.html")


@app.get("/demo-hr")
def demo_hr_page() -> FileResponse:
    return FileResponse(_STATIC / "demo-hr.html")


# ------------------------------------- SOC ---------------------------------------

@app.get("/api/soc/summary")
def soc_summary(hours: int = 24) -> dict:
    return event_log.summary(max(1, min(hours, 24 * 30)))


@app.get("/api/soc/events/{session_id}")
def soc_event(session_id: str) -> dict:
    ev = event_log.get(session_id)
    if ev is None:
        raise HTTPException(status_code=404, detail="unknown event")
    return ev


@app.get("/soc")
def soc_page() -> FileResponse:
    return FileResponse(_STATIC / "soc.html")


@app.get("/hr-dashboard")
def hr_dashboard_page() -> FileResponse:
    return FileResponse(_STATIC / "hr-dashboard.html")


@app.get("/api/hr/summary")
def hr_summary(hours: int = 168) -> dict:
    """Totals and the latest runs for the HR review dashboard (hours <= 0: all time)."""
    return hr_log.summary(hours, _HR_PENDING.keys())


@app.get("/api/hr/runs/{run_id}")
def hr_run_detail(run_id: str) -> dict:
    rec = hr_log.get(run_id, _HR_PENDING.keys())
    if rec is None:
        raise HTTPException(status_code=404, detail="unknown run")
    return rec


@app.post("/api/hr/reset")
def hr_reset(x_admin_token: str = Header(default="")) -> dict:
    """Clear the HR run log. Needs the admin password; in two-container mode the proxy checks it."""
    if settings.proxy_url:
        _relay("POST", "/admin/verify", x_admin_token)
    elif not rules_store.admin_ok(x_admin_token):
        raise HTTPException(status_code=403, detail="wrong admin password, or admin actions disabled")
    return {"cleared": hr_log.clear()}


@app.get("/api/hr/export")
def hr_export(hours: int = 168, format: str = "csv") -> Response:
    """One row per run, as CSV or JSON. Gmail runs carry counts only."""
    rows = hr_log.export_rows(hours, _HR_PENDING.keys())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    if format == "json":
        return Response(json.dumps(rows, indent=1), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="hr-runs-{stamp}.json"'})
    import csv
    import io
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=hr_log.EXPORT_COLUMNS)
    w.writeheader()
    w.writerows(rows)
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="hr-runs-{stamp}.csv"'})


# ------------------------------------ Demo HR -------------------------------------
# CV screening from email, run with Sec-Agent protection ON or OFF (see screening.py).

class HRRunRequest(BaseModel):
    goal: str = screening.DEFAULT_GOAL
    protection: bool = True
    source: str = Field("sample", pattern="^(sample|gmail)$")   # synthetic sample inbox, or the Gmail label
    sample: str = Field("poisoned", pattern="^(clean|poisoned)$")
    compromised: bool = False   # scripted compromised agent (obeys the injected email) instead of the live LLM
    review: bool = True         # ON: pause for a human decision on each flagged application


def _hr_tool(tool: str, args: dict, goal: str, protection: bool,
             credentials: Optional[dict] = None) -> tuple[str, list[str]]:
    """A fixed workflow step. ON: policy check + execution proxy, like any action. OFF: direct call."""
    if not protection:
        return tool_invoke(tool, args, credentials=credentials), [f"[unprotected] {tool} called directly, no checks"]
    action = ProposedAction(tool=tool, arguments=args, reason="screening workflow step",
                            source_ids=["user-request"], original_goal=goal)
    decision, reasons = policy_evaluate(action, [])
    if decision != Decision.ALLOW:
        raise RuntimeError(f"workflow step {tool} not allowed: {'; '.join(reasons)}")
    st: AgentState = {"proposed_action": action, "final_decision": Decision.ALLOW, "context_items": [], "audit": []}
    out = (remote_execute(st, approve=True, credentials=credentials) if settings.proxy_url
           else execution_proxy_node(st, approval_fn=lambda _s: True, credentials=credentials))
    if out.get("execution_result") is None:
        raise RuntimeError((out.get("audit") or [f"{tool} failed"])[-1])
    return out["execution_result"], out.get("audit", [])


# Runs paused for a human review of flagged applications (session id -> what is needed to resume).
_HR_PENDING: dict[str, dict] = {}


def _hr_finish(rec: dict, merged: AgentState) -> None:
    """Record the agent's proposal and the decision on the HR dashboard."""
    act, fd, sec = merged.get("proposed_action"), merged.get("final_decision"), merged.get("security_decision")
    reasons = merged.get("policy_reasons", [])
    if act is not None:
        rec["action"] = _hr_action(act)
    rec["final_decision"] = fd.value if fd else None
    rec["attack_type"] = event_log.classify(reasons, sec.classification if sec else "",
                                            bool(sec and sec.decision == Decision.DENY), rec.get("flagged", 0) > 0)
    rec["top_reason"] = reasons[0] if reasons else None
    rec["decided_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rec["executed"] = False if rec["final_decision"] == "DENY" else None
    rec["status"] = "done"
    hr_log.save(rec)


def _hr_action(act: ProposedAction) -> dict:
    to = act.arguments.get("recipient") or act.arguments.get("url") or ""
    internal = to.rsplit("@", 1)[-1].lower() in settings.allowed_email_domains if "@" in to else None
    return {"tool": act.tool, "recipient": to or None, "internal": internal}


def _hr_decide(line, session_id: str, merged: AgentState, emails: list[dict], candidates: list[dict],
               goal: str, compromised: bool, source: str, rec: dict):
    """After screening (and any human review): agent -> security LLM -> policy, streamed."""
    if compromised:
        act = (screening.scripted_attack(goal, emails, candidates)
               or screening.scripted_shortlist(goal, emails, candidates))
        merged["proposed_action"] = act
        yield line({"type": "action", "scripted": True, "action": _action_view(act)})
    graph = build_graph(include_executor=not compromised, execute=False, include_input_guard=False)
    for chunk in graph.stream(merged, stream_mode="updates"):
        for node, update in chunk.items():
            merged.update(update or {})
            if node == "executor":
                yield line({"type": "action", "scripted": False, "action": _action_view(merged.get("proposed_action"))})
            elif node == "security":
                yield line({"type": "security", "security": _view("", merged).security})
            elif node == "policy":
                fd, pd = merged.get("final_decision"), merged.get("policy_decision")
                yield line({"type": "decision", "final_decision": fd.value if fd else None,
                            "policy_decision": pd.value if pd else None,
                            "reasons": merged.get("policy_reasons", []),
                            "checks": [c.model_dump(mode="json") for c in merged.get("checks", [])
                                       if c.stage == "action"]})
    _SESSIONS[session_id] = merged
    if source == "sample":  # synthetic data only in the public SOC log
        event_log.record_analysis(session_id, merged, compromised=compromised)
        rec["soc"] = True
    _hr_finish(rec, merged)
    fd = merged.get("final_decision")
    yield line({"type": "done", "session_id": session_id, "final_decision": fd.value if fd else None,
                "audit": merged.get("audit", [])})


class HRContinueRequest(BaseModel):
    session_id: str
    include: list[str] = Field(default_factory=list)       # application ids the human keeps
    seconds: dict[str, float] = Field(default_factory=dict)  # per application: time to decide
    acknowledged: list[str] = Field(default_factory=list)  # flagged ids included after the impact popup (client-reported)


@app.post("/api/hr/continue")
def hr_continue(req: HRContinueRequest) -> StreamingResponse:
    """Resume a paused screening run with the human's decision on each application. Excluded
    applications are removed from the agent's context entirely (quarantined)."""
    pending = _HR_PENDING.pop(req.session_id, None)
    if pending is None:
        raise HTTPException(status_code=404, detail="unknown or expired review")
    keep = set(req.include)
    merged: AgentState = pending["state"]
    flagged = {i.id for i in merged.get("context_items", []) if i.taint.value == "suspicious"}
    audit = list(merged.get("audit", []))
    for e in pending["emails"]:
        verdict = "kept" if e["_id"] in keep else "excluded"
        if e["_id"] in flagged:
            verdict = "included anyway" if e["_id"] in keep else "excluded"
        secs = req.seconds.get(e["_id"])
        who = f"[human] {e['_id']} ({screening.candidate_name(e)}): "
        if verdict == "included anyway" and e["_id"] in req.acknowledged:
            audit.append(who + "included anyway after flagged-content review"
                         + (f" ({secs:.1f} s)" if secs is not None else ""))
        else:
            audit.append(who + verdict + (f" after {secs:.1f} s" if secs is not None else ""))
    merged["audit"] = audit
    rec = pending["rec"]
    ids = [e["_id"] for e in pending["emails"]]
    rec["review"] = {"excluded": sum(1 for i in ids if i not in keep),
                     "included_anyway": sum(1 for i in ids if i in flagged and i in keep),
                     "acknowledged": sum(1 for i in ids if i in flagged and i in keep and i in req.acknowledged),
                     "seconds": [round(req.seconds[i], 1) for i in ids if i in flagged and i in req.seconds]}
    for a in rec["apps"]:
        a["outcome"] = ("included anyway" if a["id"] in flagged else "kept") if a["id"] in keep else "excluded"
        a["seconds"] = req.seconds.get(a["id"]) if a["id"] in flagged else None
    rec["status"] = "running"
    merged["context_items"] = [i for i in merged.get("context_items", [])
                               if not i.id.startswith("email-") or i.id in keep]
    emails = [e for e in pending["emails"] if e["_id"] in keep]

    def line(event: dict) -> str:
        return json.dumps(event, default=str) + "\n"

    def stream():
        yield line({"type": "reviewed", "kept": [e["_id"] for e in emails],
                    "excluded": [e["_id"] for e in pending["emails"] if e["_id"] not in keep]})
        if not emails:
            rec.update(final_decision="NONE", status="done")
            hr_log.save(rec)
            yield line({"type": "done", "session_id": None, "final_decision": "NONE",
                        "audit": audit + ["[human] every application excluded — nothing to screen"]})
            return
        try:
            yield from _hr_decide(line, req.session_id, merged, emails, pending["candidates"],
                                  pending["goal"], pending["compromised"], pending["source"], rec)
        except Exception as exc:
            rec["status"] = "error"
            hr_log.save(rec)
            yield line({"type": "error", "detail": f"{type(exc).__name__}: {exc}"[:400]})

    return StreamingResponse(stream(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/hr/run")
def hr_run(req: HRRunRequest, sa_gmail: str = Cookie(default="")) -> StreamingResponse:
    conn = _gmail_conn(sa_gmail) if req.source == "gmail" else None
    if req.source == "gmail" and not conn:
        raise HTTPException(status_code=401, detail="Gmail is not connected")
    creds = {"gmail": conn["token"]} if conn else None
    session_id = uuid.uuid4().hex
    goal = req.goal.strip() or screening.DEFAULT_GOAL

    def line(event: dict) -> str:
        return json.dumps(event, default=str) + "\n"

    rec = hr_log.new_run(session_id, protection=req.protection, source=req.source, scenario=req.sample,
                         compromised=req.compromised)

    def stream():
        yield line({"type": "start", "session_id": session_id, "protection": req.protection, "source": req.source,
                    "label": settings.gmail_screening_label if req.source == "gmail" else None})
        try:
            # 1. the applications
            if req.source == "gmail":
                raw, audit = _hr_tool("read_email", {"query": f"label:{settings.gmail_screening_label}",
                                                     "max_results": settings.gmail_max_results},
                                      goal, req.protection, creds)
                emails = json.loads(raw).get("emails", [])
            else:
                emails, audit = screening.sample_emails(req.sample), []
            for n, e in enumerate(emails, 1):
                e["_id"] = f"email-{n}"   # stable id, kept even if a human excludes other emails
            limit = settings.gmail_max_results if req.source == "gmail" else None
            yield line({"type": "fetched", "via": "proxy" if req.protection else "direct", "limit": limit, "emails": [
                {"id": f"email-{n}", "subject": e.get("subject", ""), "from": e.get("from", ""), "date": e.get("date", ""),
                 "candidate": screening.candidate_name(e), "preview": e.get("body", "")}
                for n, e in enumerate(emails, 1)]})
            rec["applications"] = len(emails)
            rec["apps"] = [{"id": e["_id"], "candidate": screening.candidate_name(e), "status": "pending",
                            "categories": [], "outcome": None, "seconds": None} for e in emails]
            if not emails:
                rec["status"] = "empty"
                hr_log.save(rec)
                yield line({"type": "error", "detail": f"No emails under the Gmail label '{settings.gmail_screening_label}'."})
                return
            # 2. the existing candidates
            raw_db, audit_db = _hr_tool("query_candidates_db", {"role": "Senior Backend Engineer"}, goal, req.protection)
            candidates = screening.parse_candidates(raw_db)
            yield line({"type": "candidates", "via": "proxy" if req.protection else "direct",
                        "count": len(candidates), "names": [c["name"] for c in candidates]})

            state: AgentState = {"user_goal": goal, "audit": [*audit, *audit_db],
                                 "context_items": screening.context_items(goal, emails, raw_db)}
            if req.compromised and not req.protection:
                act = screening.scripted_attack(goal, emails, candidates)
                if act is None:
                    rec["status"] = "error"
                    hr_log.save(rec)
                    yield line({"type": "error", "detail": "No email here instructs the agent to send data anywhere — "
                                                           "nothing for a compromised agent to follow. Untick 'compromised'."})
                    return
                state["proposed_action"] = act
                yield line({"type": "action", "scripted": True, "action": _action_view(act)})

            if req.protection:
                from ..nodes.input_guard import input_guard_node
                merged: AgentState = dict(state)  # type: ignore[assignment]
                merged.update(input_guard_node(merged))
                by_id = {i.id: i for i in merged.get("context_items", [])}
                screened = [{"id": e["_id"], "flagged": by_id[e["_id"]].taint.value == "suspicious",
                             "reasons": screening.flag_reasons(e["_id"], merged),
                             "jev_level": ((merged.get("jev_input") or {}).get(e["_id"]) or {}).get("level")}
                            for e in emails]
                yield line({"type": "screened", "emails": screened})
                flagged = [x["id"] for x in screened if x["flagged"]]
                rec["flagged"], rec["clean"] = len(flagged), len(emails) - len(flagged)
                for a in rec["apps"]:
                    a["status"] = "flagged" if a["id"] in flagged else "clean"
                    a["categories"] = screening.flag_categories(a["id"], merged) if a["id"] in flagged else []
                    for c in a["categories"]:
                        rec["categories"][c] = rec["categories"].get(c, 0) + 1
                    a["outcome"] = None if a["id"] in flagged and req.review else "kept"
                if flagged and req.review:
                    rec["status"] = "review"
                    hr_log.save(rec)
                    _HR_PENDING[session_id] = {"state": merged, "emails": emails, "candidates": candidates,
                                               "goal": goal, "compromised": req.compromised, "source": req.source,
                                               "rec": rec}
                    yield line({"type": "review", "session_id": session_id, "flagged": flagged})
                    yield line({"type": "done", "session_id": session_id, "final_decision": "REVIEW",
                                "audit": merged.get("audit", [])})
                    return
                yield from _hr_decide(line, session_id, merged, emails, candidates, goal,
                                      req.compromised, req.source, rec)
            else:
                yield line({"type": "screened", "unchecked": True})
                rec["unchecked"] = len(emails)
                for a in rec["apps"]:
                    a["status"], a["outcome"] = "unchecked", "kept"
                if not req.compromised:
                    from ..nodes.executor import executor_node
                    state.update(executor_node(state))
                    yield line({"type": "action", "scripted": False, "action": _action_view(state.get("proposed_action"))})
                act = state["proposed_action"]
                if act.tool not in screening.OFF_TOOLS:
                    result, ok = f"'{act.tool}' is not available in the unprotected demo", False
                else:
                    result, ok = tool_invoke(act.tool, act.arguments), True
                yield line({"type": "executed", "ok": ok, "tool": act.tool, "arguments": act.arguments, "result": result})
                rec.update(action=_hr_action(act), final_decision="EXECUTED" if ok else "NONE",
                           executed=ok, status="done")
                hr_log.save(rec)
                yield line({"type": "done", "session_id": None, "final_decision": "EXECUTED" if ok else None,
                            "audit": state.get("audit", [])})
        except Exception as exc:  # surface tool/model errors to the page
            rec["status"] = "error"
            hr_log.save(rec)
            yield line({"type": "error", "detail": f"{type(exc).__name__}: {exc}"[:400]})

    return StreamingResponse(stream(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ------------------------------- legal pages -------------------------------------

def _legal_page(name: str) -> HTMLResponse:
    contact = settings.contact_email
    link = (f'<a href="mailto:{contact}">{contact}</a>' if contact else
            '<a href="https://github.com/42-activities/Sec-Agent/issues">github.com/42-activities/Sec-Agent/issues</a>')
    return HTMLResponse((_STATIC / name).read_text(encoding="utf-8").replace("{{CONTACT}}", link))


@app.get("/privacy")
def privacy_page() -> HTMLResponse:
    return _legal_page("privacy.html")


@app.get("/terms")
def terms_page() -> HTMLResponse:
    return _legal_page("terms.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


app.mount("/static", StaticFiles(directory=_STATIC), name="static")


def run() -> None:
    """Entry point: `sec-web` (or `python -m sec_agent.web.app`)."""
    import uvicorn

    uvicorn.run("sec_agent.web.app:app", host=settings.web_host, port=settings.web_port, reload=False)


if __name__ == "__main__":
    run()
