"""Editable rules: persistence, admin gate, and that edits change policy decisions."""

from fastapi.testclient import TestClient

from sec_agent import rules as rules_store
from sec_agent.config import settings
from sec_agent.models import ContextItem, Decision, ProposedAction, Trust
from sec_agent.nodes.policy import evaluate
from sec_agent.proxy_service.app import app as proxy_app
from sec_agent.web.app import app as web_app

USER = ContextItem(id="user-request", source="chat", source_type="user_message",
                   content="g", trust=Trust.TRUSTED)


def _email(to):
    return ProposedAction(tool="send_email", arguments={"recipient": to, "body": "x"},
                          reason="r", source_ids=["user-request"], original_goal="g")


def test_edited_rules_change_the_decision():
    assert evaluate(_email("a@partner.example"), [USER])[0] == Decision.DENY
    r = rules_store.load_local()
    rules_store.save_local(r.model_copy(update={"allowed_email_domains": [*r.allowed_email_domains, "partner.example"]}))
    assert evaluate(_email("a@partner.example"), [USER])[0] == Decision.ALLOW
    rules_store.reset_local()
    assert evaluate(_email("a@partner.example"), [USER])[0] == Decision.DENY


def test_rules_are_normalized():
    r = rules_store.Rules(**{**rules_store.defaults().model_dump(),
                             "allowed_email_domains": [" @OurCo.Example ", "ourco.example", ""],
                             "known_payees": {" Acme GmbH ": "de89 3704 0044 0532 0130 00"}})
    assert r.allowed_email_domains == ["ourco.example"]
    assert r.known_payees == {"Acme GmbH": "DE89370400440532013000"}


def test_web_editing_requires_admin_password(monkeypatch):
    c = TestClient(web_app)
    body = c.get("/api/rules").json()
    assert body["editable"] is False
    new = {**body["rules"], "allowed_email_domains": ["evil.example"]}
    # Disabled when no admin password is configured — fail closed.
    assert c.put("/api/rules", json=new, headers={"X-Admin-Token": ""}).status_code == 403
    monkeypatch.setattr(settings, "rules_admin_token", "s3cret")
    assert c.put("/api/rules", json=new, headers={"X-Admin-Token": "wrong"}).status_code == 403
    r = c.put("/api/rules", json=new, headers={"X-Admin-Token": "s3cret"})
    assert r.status_code == 200 and r.json()["rules"]["allowed_email_domains"] == ["evil.example"]
    assert c.post("/api/rules/reset", headers={"X-Admin-Token": "s3cret"}).json()["rules"]["allowed_email_domains"] == ["ourco.example"]


def test_proxy_needs_both_service_token_and_admin_password(monkeypatch):
    monkeypatch.setattr(settings, "proxy_auth_token", "svc")
    monkeypatch.setattr(settings, "rules_admin_token", "adm")
    c = TestClient(proxy_app)
    rules = rules_store.defaults().model_dump()
    assert c.get("/rules").status_code == 401
    assert c.put("/rules", json=rules, headers={"Authorization": "Bearer svc"}).status_code == 403
    assert c.put("/rules", json=rules, headers={"Authorization": "Bearer svc", "X-Admin-Token": "adm"}).status_code == 200
