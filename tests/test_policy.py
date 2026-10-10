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
        arguments={"recipient": "x@y.com", "body": "hi"},
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
