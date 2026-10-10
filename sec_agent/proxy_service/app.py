"""Standalone Execution Proxy service (runs in its own container).

This is the ONLY component that holds tool credentials and the ONLY one that
invokes real tools. It is zero-trust toward its caller: it does not believe the
controller's claimed decision, it RE-RUNS the deterministic policy engine on every
request and refuses anything that fails. A fully compromised controller therefore
still cannot make the proxy touch a denied resource.

Network posture (see docker-compose.yml): this service sits on an internal-only
network with no host port, and requires a shared bearer secret. The controller is
the only workload that can reach it.
"""

from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from ..config import settings
from ..models import ContextItem, Decision, ProposedAction, Taint, Trust
from ..nodes.policy import evaluate
from .. import rules as rules_store
from ..tools import REGISTRY, invoke, summarize

app = FastAPI(title="Sec-Agent Execution Proxy", version="0.1.0")


class ContextRef(BaseModel):
    """Only the provenance fields the policy engine needs — never raw content."""

    id: str
    trust: Trust = Trust.UNTRUSTED
    taint: Taint = Taint.NONE


class ExecuteActionRequest(BaseModel):
    action: ProposedAction
    context: list[ContextRef] = Field(default_factory=list)
    approve: bool = False
    # The controller's claimed decision — advisory only; we re-decide below.
    claimed_decision: str = "ALLOW"
    # Pasted document content, only for a read_document call that names it by ID.
    documents: dict[str, str] = Field(default_factory=dict)
    # Per-user credentials for this one call (``gmail`` -> the user's read-only access token).
    # Used, never stored or logged.
    credentials: dict[str, str] = Field(default_factory=dict)


class ExecuteActionResponse(BaseModel):
    executed: bool
    result: str | None = None
    proxy_decision: str
    audit: list[str]


def _check_auth(authorization: str) -> None:
    expected = settings.proxy_auth_token
    if not expected:
        raise HTTPException(status_code=500, detail="proxy missing PROXY_AUTH_TOKEN")
    if authorization != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="unauthorized")


# ------------------------------- rules (owned here) -------------------------------

@app.get("/rules")
def get_rules(authorization: str = Header(default="")) -> dict:
    _check_auth(authorization)
    return {"rules": rules_store.load_local().model_dump(), "editable": bool(settings.rules_admin_token)}


@app.put("/rules")
def put_rules(
    new: rules_store.Rules,
    authorization: str = Header(default=""),
    x_admin_token: str = Header(default=""),
) -> dict:
    # Two keys: the caller must be the controller AND carry the human admin's password,
    # which the controller itself never stores.
    _check_auth(authorization)
    if not rules_store.admin_ok(x_admin_token):
        raise HTTPException(status_code=403, detail="wrong admin password, or editing disabled")
    return {"rules": rules_store.save_local(new).model_dump(), "editable": True}


@app.post("/rules/reset")
def reset_rules(authorization: str = Header(default=""), x_admin_token: str = Header(default="")) -> dict:
    _check_auth(authorization)
    if not rules_store.admin_ok(x_admin_token):
        raise HTTPException(status_code=403, detail="wrong admin password, or editing disabled")
    return {"rules": rules_store.reset_local().model_dump(), "editable": True}


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.post("/execute-action", response_model=ExecuteActionResponse)
def execute_action(
    req: ExecuteActionRequest, authorization: str = Header(default="")
) -> ExecuteActionResponse:
    _check_auth(authorization)

    # Rebuild just enough ContextItem state for the policy engine.
    items = [
        ContextItem(
            id=c.id, source="", source_type="", content="",
            trust=c.trust, taint=c.taint,
        )
        for c in req.context
    ]

    # ZERO TRUST: independently re-evaluate, ignoring the controller's claim.
    decision, reasons = evaluate(req.action, items)
    audit = [
        f"[proxy-service] claimed={req.claimed_decision} "
        f"independent_reeval={decision.value} ({'; '.join(reasons)})"
    ]

    if decision == Decision.DENY:
        audit.append(
            f"[proxy-service] BLOCKED {req.action.tool} — independent policy said DENY"
        )
        return ExecuteActionResponse(
            executed=False, proxy_decision=decision.value, audit=audit
        )

    if decision == Decision.APPROVAL and not req.approve:
        audit.append(
            f"[proxy-service] BLOCKED {req.action.tool} — approval required, not granted"
        )
        return ExecuteActionResponse(
            executed=False, proxy_decision=decision.value, audit=audit
        )

    if req.action.tool not in REGISTRY:
        audit.append(f"[proxy-service] refused: unknown tool '{req.action.tool}'")
        return ExecuteActionResponse(
            executed=False, proxy_decision="DENY", audit=audit
        )

    try:
        result = invoke(req.action.tool, req.action.arguments, req.documents, req.credentials)
    except Exception as exc:  # report, never silently drop
        audit.append(f"[proxy-service] tool '{req.action.tool}' errored: {exc}")
        return ExecuteActionResponse(
            executed=False, proxy_decision=decision.value, audit=audit
        )

    audit.append(f"[proxy-service] EXECUTED {req.action.tool} -> {summarize(req.action.tool, result)}")
    return ExecuteActionResponse(
        executed=True, result=result, proxy_decision=decision.value, audit=audit
    )


def run() -> None:
    """Entry point: `sec-proxy` (or `python -m sec_agent.proxy_service.app`)."""
    import uvicorn

    uvicorn.run("sec_agent.proxy_service.app:app", host="0.0.0.0", port=8001)


if __name__ == "__main__":
    run()
