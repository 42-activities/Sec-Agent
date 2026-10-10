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


def _norm_iban(value: object) -> str:
    return "".join(str(value).split()).upper()


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
    #    Output-only tools reach no resource, so their text is not a resource reference.
    denied = [] if action.tool in settings.output_only_tools else _touches_denied_path(action)
    if denied:
        reasons.append(f"argument references denied resource(s): {', '.join(denied)}")
        return Decision.DENY, reasons

    # 3. Payments only to bank details on file (vendor master data), never to ones
    #    taken from a document — the classic "our bank account changed" fraud.
    if action.tool == "pay_invoice":
        payee = str(action.arguments.get("payee", "")).strip()
        on_file = _norm_iban(settings.known_payees.get(payee, ""))
        if not on_file:
            reasons.append(f"payee '{payee}' is not in the vendor master data")
            return Decision.DENY, reasons
        if _norm_iban(action.arguments.get("iban", "")) != on_file:
            reasons.append(f"IBAN does not match the account on file for '{payee}' "
                           f"-> possible bank-details fraud; verify out of band")
            return Decision.DENY, reasons

    # Outbound email only to company domains — no exfiltration to arbitrary inboxes.
    if action.tool == "send_email":
        recipient = str(action.arguments.get("recipient", "")).strip().lower()
        domain = recipient.rsplit("@", 1)[-1] if "@" in recipient else ""
        if domain not in settings.allowed_email_domains:
            reasons.append(f"recipient domain '{domain or recipient}' is outside the allowed "
                           f"email domains -> external data egress")
            return Decision.DENY, reasons

    decision = Decision.ALLOW
    influenced = _influenced_by_untrusted(action, items)

    # 4. High-impact actions (payments) always go to a human, even from a clean request.
    if action.tool in settings.approval_required_tools:
        reasons.append(f"'{action.tool}' is a high-impact action -> always requires human approval")
        decision = most_restrictive(decision, Decision.APPROVAL)

    # 5. Consequential action influenced by untrusted data -> human approval.
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
