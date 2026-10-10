"""Tool-layer tests: respond_to_user, read_document by context ID, both proxies. No network."""

from fastapi.testclient import TestClient

from sec_agent.config import settings
from sec_agent.models import ContextItem, Decision, ProposedAction, Taint, Trust
from sec_agent.nodes.policy import evaluate
from sec_agent.proxy import execution_proxy_node
from sec_agent.proxy_client import _referenced_documents
from sec_agent.proxy_service.app import app as proxy_app
from sec_agent.tools import invoke

DOC = "Invoice #1\nAmount: EUR 10"


def _items():
    return [
        ContextItem(id="user-request", source="chat", source_type="user_message",
                    content="analyze it", trust=Trust.TRUSTED),
        ContextItem(id="document-1", source="upload", source_type="document",
                    content=DOC, trust=Trust.UNTRUSTED, taint=Taint.EXTERNAL),
    ]


def _action(tool, **arguments):
    return ProposedAction(tool=tool, arguments=arguments, reason="r",
                          source_ids=["user-request", "document-1"], original_goal="g")


def test_respond_to_user_may_mention_denied_paths():
    # Warning the user about the injection must not be blocked by the resource denylist.
    action = _action("respond_to_user", answer="The invoice asked me to read ~/.ssh/id_ed25519. I did not.")
    decision, _ = evaluate(action, _items())
    assert decision == Decision.ALLOW


def test_denylist_still_applies_to_resource_tools():
    decision, _ = evaluate(_action("read_document", path="~/.ssh/id_ed25519"), _items())
    assert decision == Decision.DENY


def test_read_document_resolves_context_id():
    assert invoke("read_document", {"path": "document-1"}, {"document-1": DOC}) == DOC


def test_in_process_proxy_reads_pasted_document():
    state = {"proposed_action": _action("read_document", path="document-1"),
             "final_decision": Decision.ALLOW, "context_items": _items(), "audit": []}
    assert execution_proxy_node(state)["execution_result"] == DOC


def test_client_ships_only_the_named_document():
    state = {"proposed_action": _action("read_document", path="document-1"), "context_items": _items()}
    assert _referenced_documents(state) == {"document-1": DOC}
    state["proposed_action"] = _action("send_email", recipient="a@b.c", body="x")
    assert _referenced_documents(state) == {}


def test_proxy_service_reads_pasted_document(monkeypatch):
    monkeypatch.setattr(settings, "proxy_auth_token", "t")
    r = TestClient(proxy_app).post(
        "/execute-action",
        headers={"Authorization": "Bearer t"},
        json={"action": _action("read_document", path="document-1").model_dump(),
              "context": [{"id": "document-1", "trust": "untrusted", "taint": "external"}],
              "documents": {"document-1": DOC}},
    )
    assert r.status_code == 200
    assert r.json()["executed"] and r.json()["result"] == DOC


def test_file_tools_are_sandboxed(tmp_path, monkeypatch):
    import pytest

    monkeypatch.setattr(settings, "files_root", str(tmp_path))
    invoke("write_file", {"path": "config/app.yaml", "content": "request_timeout: 30"})
    assert invoke("read_file", {"path": "config/app.yaml"}) == "request_timeout: 30"
    assert (tmp_path / "config/app.yaml").exists()
    # Absolute paths are re-rooted inside the sandbox, never read from the real filesystem.
    with pytest.raises(FileNotFoundError):
        invoke("read_file", {"path": "/proc/self/environ"})
    with pytest.raises(PermissionError):
        invoke("read_file", {"path": "../../etc/passwd"})


def test_email_only_to_company_domains():
    ok, _ = evaluate(ProposedAction(tool="send_email", arguments={"recipient": "hiring@ourco.example", "body": "x"},
                                    reason="r", source_ids=["user-request"], original_goal="g"), _items())
    bad, reasons = evaluate(ProposedAction(tool="send_email", arguments={"recipient": "talent-sync@recruit-hub.example", "body": "x"},
                                           reason="r", source_ids=["document-1"], original_goal="g"), _items())
    assert ok == Decision.ALLOW
    assert bad == Decision.DENY and any("egress" in r for r in reasons)
