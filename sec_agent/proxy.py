"""Execution Proxy.

The ONLY component that invokes real tools. It refuses to execute anything that
did not arrive with a final ALLOW decision. APPROVAL is routed to a human gate;
DENY stops. The executor has no other path to the tool registry.
"""

from __future__ import annotations

from typing import Callable, Optional

from .models import AgentState, Decision
from .tools import REGISTRY

# A human-approval callback: given the state, return True to proceed. Default
# denies (fail-closed). The demo/CLI can inject an interactive prompt.
ApprovalFn = Callable[[AgentState], bool]


def _deny_by_default(_: AgentState) -> bool:
    return False


def execution_proxy_node(
    state: AgentState, approval_fn: Optional[ApprovalFn] = None
) -> AgentState:
    approval_fn = approval_fn or _deny_by_default
    final = state.get("final_decision")
    action = state.get("proposed_action")
    audit = list(state.get("audit", []))

    if action is None or final is None:
        audit.append("[proxy] refused: no authorized action")
        return {"execution_result": None, "audit": audit}

    if final == Decision.DENY:
        audit.append(f"[proxy] BLOCKED {action.tool} — decision was DENY")
        return {"execution_result": None, "audit": audit}

    if final == Decision.APPROVAL:
        approved = approval_fn(state)
        if not approved:
            audit.append(f"[proxy] BLOCKED {action.tool} — human approval withheld")
            return {"execution_result": None, "audit": audit}
        audit.append(f"[proxy] human approved {action.tool}")

    fn = REGISTRY.get(action.tool)
    if fn is None:
        audit.append(f"[proxy] refused: unknown tool '{action.tool}'")
        return {"execution_result": None, "audit": audit}

    try:
        result = fn(**action.arguments)
    except Exception as exc:  # tool errors are reported, never silently dropped
        audit.append(f"[proxy] tool '{action.tool}' errored: {exc}")
        return {"execution_result": None, "audit": audit}

    audit.append(f"[proxy] EXECUTED {action.tool} -> {result}")
    return {"execution_result": result, "audit": audit}
