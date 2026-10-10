"""Deterministic Policy Engine.

The security LLM is advisory. This engine is the hard boundary: pure code, no
model, fully testable. The final decision is the MOST RESTRICTIVE of the policy
engine and the security LLM, so an incorrect ALLOW from the model can never
loosen a deterministic rule.
"""

from __future__ import annotations

from ..config import settings
from ..models import (
    AgentState,
    ContextItem,
    Decision,
    ProposedAction,
    Taint,
    most_restrictive,
)


def _touches_denied_path(action: ProposedAction) -> list[str]:
    hits = []
    blob = " ".join(str(v) for v in action.arguments.values()).lower()
    for needle in settings.denied_path_substrings:
        if needle in blob:
            hits.append(needle)
    return hits


def _influenced_by_untrusted(action: ProposedAction, items: list[ContextItem]) -> bool:
    by_id = {i.id: i for i in items}
    for sid in action.source_ids:
        item = by_id.get(sid)
        if item is not None and item.taint in (Taint.EXTERNAL, Taint.SUSPICIOUS):
            return True
    return False


def evaluate(action: ProposedAction, items: list[ContextItem]) -> tuple[Decision, list[str]]:
    """Return (decision, reasons). Pure function — unit-tested without network."""
    reasons: list[str] = []

    # 1. Least privilege: unknown tools are refused outright.
    if action.tool not in settings.allowed_tools:
        reasons.append(f"tool '{action.tool}' is not in the allow-list")
        return Decision.DENY, reasons

    # 2. Hard denylist: sensitive resources are never reachable, whatever the LLM says.
    denied = _touches_denied_path(action)
    if denied:
        reasons.append(f"argument references denied resource(s): {', '.join(denied)}")
        return Decision.DENY, reasons

    decision = Decision.ALLOW
    influenced = _influenced_by_untrusted(action, items)

    # 3. Consequential action influenced by untrusted data -> human approval.
    if action.tool in settings.consequential_tools and influenced:
        reasons.append(
            f"consequential tool '{action.tool}' was influenced by untrusted/tainted "
            f"context -> requires human approval"
        )
        decision = most_restrictive(decision, Decision.APPROVAL)

    if not reasons:
        reasons.append("no deterministic rule triggered")
    return decision, reasons


def policy_node(state: AgentState) -> AgentState:
    action = state["proposed_action"]
    items = state.get("context_items", [])
    sec = state.get("security_decision")

    policy_decision, reasons = evaluate(action, items)

    # Final = most restrictive of deterministic policy and advisory LLM.
    final = policy_decision
    if sec is not None:
        final = most_restrictive(policy_decision, sec.decision)

    audit = list(state.get("audit", []))
    for r in reasons:
        audit.append(f"[policy] {r}")
    audit.append(
        f"[policy] deterministic={policy_decision.value} "
        f"security_llm={(sec.decision.value if sec else 'n/a')} "
        f"-> FINAL={final.value}"
    )
    return {
        "policy_decision": policy_decision,
        "policy_reasons": reasons,
        "final_decision": final,
        "audit": audit,
    }
