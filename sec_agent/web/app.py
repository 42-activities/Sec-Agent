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
from pathlib import Path
from typing import Any, Optional

from fastapi import Cookie, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..config import settings
from .. import rules as rules_store
from .. import events as event_log
from .. import gmail
from .. import jev
from ..graph import build_graph
from ..models import AgentState, ContextItem, Decision, ProposedAction, Trust
from ..nodes.input_guard import _INJECTION_RE, _SENSITIVE_RE, _WEAK_SENSITIVE_RE
from ..proxy import execution_proxy_node
from ..proxy_client import remote_execute
from ..tools import REGISTRY

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
    page = "batch" if next == "/batch" else "home"  # where to land afterwards (cookie-safe word)
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
    nxt = "/batch" if page == "batch" else "/"
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
