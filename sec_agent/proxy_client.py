"""Controller-side client for the remote Execution Proxy service.

Used by the web app when PROXY_URL is configured (the two-container deployment).
The controller never executes tools itself in that mode — it forwards an
authorized action to the proxy service, which re-authorizes and executes.
"""

from __future__ import annotations

import requests

from .config import settings
from .models import AgentState, Decision


def remote_execute(state: AgentState, approve: bool = False) -> AgentState:
    action = state.get("proposed_action")
    final = state.get("final_decision")
    audit = list(state.get("audit", []))

    if action is None or final is None:
        audit.append("[proxy-client] refused: no authorized action")
        return {"execution_result": None, "audit": audit}

    # Controller-side short-circuit: never even forward a DENY.
    if final == Decision.DENY:
        audit.append(f"[proxy-client] not forwarding {action.tool} — controller DENY")
        return {"execution_result": None, "audit": audit}

    payload = {
        "action": action.model_dump(),
        "context": [
            {"id": i.id, "trust": i.trust.value, "taint": i.taint.value}
            for i in state.get("context_items", [])
        ],
        "approve": approve,
        "claimed_decision": final.value,
    }
    try:
        resp = requests.post(
            f"{settings.proxy_url}/execute-action",
            json=payload,
            headers={"Authorization": f"Bearer {settings.proxy_auth_token}"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        audit.append(f"[proxy-client] proxy service unreachable/error: {exc}")
        return {"execution_result": None, "audit": audit}

    audit.extend(data.get("audit", []))
    return {"execution_result": data.get("result"), "audit": audit}
