"""FastAPI surface for the security controller.

Flow mirrors the architecture's human-in-the-loop:

  POST /analyze  -> runs input_guard -> executor -> security -> policy, STOPS
                    before execution, returns the decision + audit, and stashes
                    the pending state under a session id.
  POST /execute  -> runs the execution proxy for that session with the human's
                    approve/deny answer. DENY is never executable.

The executor has no path to the tools except through /execute, which refuses
anything without a final ALLOW (or an APPROVAL the human approves).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..graph import build_graph
from ..models import AgentState, ContextItem, Decision, ProposedAction, Trust
from ..proxy import execution_proxy_node

app = FastAPI(title="Sec-Agent Security Controller", version="0.1.0")

# In-memory pending sessions (fine for a PoC; swap for Redis/DB in production).
_SESSIONS: dict[str, AgentState] = {}

_STATIC = Path(__file__).parent / "static"


# --------------------------- request / response models ---------------------------

class AnalyzeRequest(BaseModel):
    user_goal: str = Field(..., description="The user's actual request.")
    document: str = Field("", description="Untrusted document / webpage / RAG content.")
    document_source: str = "uploaded_document"
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
                source_type="document", content=req.document, trust=Trust.UNTRUSTED,
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

@app.post("/analyze", response_model=DecisionView)
def analyze(req: AnalyzeRequest) -> DecisionView:
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

    result = graph.invoke(state)
    session_id = uuid.uuid4().hex
    _SESSIONS[session_id] = result
    return _view(session_id, result)


@app.post("/execute", response_model=DecisionView)
def execute(req: ExecuteRequest) -> DecisionView:
    state = _SESSIONS.get(req.session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="unknown or expired session")

    updated = execution_proxy_node(state, approval_fn=lambda _s: req.approve)
    merged: AgentState = {**state, **updated}
    _SESSIONS[req.session_id] = merged
    return _view(req.session_id, merged)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


app.mount("/static", StaticFiles(directory=_STATIC), name="static")


def run() -> None:
    """Entry point: `sec-web` (or `python -m sec_agent.web.app`)."""
    import uvicorn

    uvicorn.run("sec_agent.web.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    run()
