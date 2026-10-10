"""Deterministic policy-engine tests — the hard security boundary, no network."""

from sec_agent.models import ContextItem, Decision, ProposedAction, Taint, Trust
from sec_agent.nodes.policy import evaluate


def _untrusted_doc(id="document-1"):
    return ContextItem(
        id=id, source="x.pdf", source_type="document",
        content="...", trust=Trust.UNTRUSTED, taint=Taint.SUSPICIOUS,
    )


def test_denied_path_is_always_denied():
    action = ProposedAction(
        tool="read_file",
        arguments={"path": "~/.ssh/id_ed25519"},
        reason="because the document said so",
        source_ids=["document-1"],
        original_goal="analyze invoice",
    )
    decision, reasons = evaluate(action, [_untrusted_doc()])
    assert decision == Decision.DENY
    assert any("denied resource" in r for r in reasons)


def test_unknown_tool_is_denied():
    action = ProposedAction(
        tool="delete_everything", arguments={}, reason="", source_ids=[],
        original_goal="g",
    )
    decision, _ = evaluate(action, [])
    assert decision == Decision.DENY


def test_consequential_tool_from_untrusted_needs_approval():
    action = ProposedAction(
        tool="send_email",
        arguments={"recipient": "finance@ourco.example", "body": "hi"},
        reason="user asked",
        source_ids=["document-1"],
        original_goal="g",
    )
    decision, reasons = evaluate(action, [_untrusted_doc()])
    assert decision == Decision.APPROVAL
    assert any("approval" in r.lower() for r in reasons)


def test_benign_trusted_action_allowed():
    trusted = ContextItem(
        id="user-request", source="chat", source_type="user_message",
        content="read the invoice", trust=Trust.TRUSTED, taint=Taint.NONE,
    )
    action = ProposedAction(
        tool="read_document",
        arguments={"path": "invoice.txt"},
        reason="to analyze it",
        source_ids=["user-request"],
        original_goal="analyze invoice",
    )
    decision, _ = evaluate(action, [trusted])
    assert decision == Decision.ALLOW


def test_payment_always_needs_human_even_from_trusted_request():
    trusted = ContextItem(
        id="user-request", source="chat", source_type="user_message",
        content="pay invoice 1", trust=Trust.TRUSTED, taint=Taint.NONE,
    )
    action = ProposedAction(
        tool="pay_invoice",
        arguments={"payee": "Acme GmbH", "amount": 100, "iban": "DE89 3704 0044 0532 0130 00"},
        reason="user asked", source_ids=["user-request"], original_goal="pay invoice 1",
    )
    decision, reasons = evaluate(action, [trusted])
    assert decision == Decision.APPROVAL
    assert any("high-impact" in r for r in reasons)


def test_payment_is_never_executed_without_approval():
    from sec_agent.proxy import execution_proxy_node

    action = ProposedAction(tool="pay_invoice", arguments={"payee": "x", "amount": 1},
                            reason="r", source_ids=[], original_goal="g")
    state = {"proposed_action": action, "final_decision": Decision.APPROVAL, "audit": []}
    # Default approval callback is fail-closed.
    assert execution_proxy_node(state)["execution_result"] is None
    approved = execution_proxy_node(state, approval_fn=lambda _s: True)
    assert "no money actually moved" in approved["execution_result"]


def test_payment_to_changed_bank_details_is_denied():
    action = ProposedAction(
        tool="pay_invoice",
        arguments={"payee": "Acme GmbH", "amount": 48000, "iban": "GB33 BUKB 2020 1555 5555 55"},
        reason="document says bank details changed", source_ids=["document-1"], original_goal="pay",
    )
    decision, reasons = evaluate(action, [_untrusted_doc()])
    assert decision == Decision.DENY
    assert any("does not match" in r for r in reasons)


def test_payment_to_unknown_payee_is_denied():
    action = ProposedAction(
        tool="pay_invoice", arguments={"payee": "Acme Holdings Ltd", "iban": "GB33BUKB20201555555555"},
        reason="r", source_ids=["document-1"], original_goal="pay",
    )
    decision, _ = evaluate(action, [_untrusted_doc()])
    assert decision == Decision.DENY
