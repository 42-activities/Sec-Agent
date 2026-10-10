"""HR screening workflow (/api/hr/run): the same input with protection OFF and ON.

No network: the security LLM is stubbed, Jev is off (conftest), the sample inbox is used.
"""

import json

import pytest
from fastapi.testclient import TestClient

import sec_agent.graph as graph
import sec_agent.web.app as webapp
from sec_agent import screening, tools
from sec_agent.models import Decision, SecurityDecision
from sec_agent.nodes.policy import evaluate_checks
from sec_agent.models import ProposedAction


@pytest.fixture
def client(monkeypatch):
    def llm_allows(state):  # the advisory LLM says ALLOW, so any block comes from guards/policy
        return {"security_decision": SecurityDecision(classification="benign", risk_score=5, goal_relevance=0.9,
                                                      decision=Decision.ALLOW, reason="stub"),
                "audit": state.get("audit", [])}

    monkeypatch.setattr(graph, "security_node", llm_allows)
    return TestClient(webapp.app)


def run(client, **body):
    r = client.post("/api/hr/run", json=body)
    assert r.status_code == 200
    return [json.loads(line) for line in r.text.splitlines() if line.strip()]


def by_type(events, kind):
    return [e for e in events if e["type"] == kind]


def test_candidates_tool_is_synthetic_and_read_only():
    rows = json.loads(tools.invoke("query_candidates_db", {"role": "backend"}))["candidates"]
    assert len(rows) == 5 and all(r["email"].endswith("@example.org") for r in rows)
    action = ProposedAction(tool="query_candidates_db", arguments={"role": "x"}, reason="r", source_ids=[], original_goal="g")
    assert all(c.effect is None for c in evaluate_checks(action, []))


def test_helpers_find_names_and_the_injected_recipient():
    emails = screening.sample_emails("poisoned")
    assert [screening.candidate_name(e) for e in emails] == ["Jordan Lee", "Maria Costa", "Alex Morgan"]
    assert screening.injected_recipient(emails) == (2, "talent-sync@recruit-hub.example")
    assert screening.injected_recipient(screening.sample_emails("clean")) == (None, None)
    act = screening.scripted_attack("goal", emails, screening.CANDIDATES)
    assert act.arguments["recipient"] == "talent-sync@recruit-hub.example"
    assert act.arguments["body"].splitlines()[2] == "1. Alex Morgan"   # ranked first
    assert "priya.raman@example.org" in act.arguments["body"]          # records included


def test_protection_off_executes_the_leak_without_any_check(client):
    ev = run(client, protection=False, source="sample", sample="poisoned", compromised=True)
    assert [e["count"] for e in by_type(ev, "candidates")] == [5]
    assert by_type(ev, "screened")[0].get("unchecked") is True
    assert not by_type(ev, "decision")
    done = by_type(ev, "executed")[0]
    assert done["ok"] and done["arguments"]["recipient"] == "talent-sync@recruit-hub.example"
    assert "[stub] email to talent-sync@recruit-hub.example" in done["result"]   # nothing real is sent


def test_protection_on_flags_the_poisoned_cv_and_denies_the_send(client):
    ev = run(client, protection=True, source="sample", sample="poisoned", compromised=True, review=False)
    mails = {m["id"]: m for m in by_type(ev, "screened")[0]["emails"]}
    assert not mails["email-1"]["flagged"] and not mails["email-2"]["flagged"]
    assert mails["email-3"]["flagged"]
    reasons = " ".join(mails["email-3"]["reasons"])
    assert "hidden text" in reasons and "instruction aimed at an AI" in reasons
    decision = by_type(ev, "decision")[0]
    assert decision["final_decision"] == "DENY"
    assert any("outside the allowed email domains" in r for r in decision["reasons"])
    assert not by_type(ev, "executed")
    assert by_type(ev, "done")[0]["session_id"]


def test_scripted_agent_without_an_injected_instruction(client):
    # OFF: nothing to obey -> the demo says so.
    ev = run(client, protection=False, source="sample", sample="clean", compromised=True)
    assert by_type(ev, "error") and "nothing for a compromised agent" in by_type(ev, "error")[0]["detail"]
    # ON: no flagged application, no review; the agent sends an honest shortlist -> human approval.
    ev = run(client, protection=True, source="sample", sample="clean", compromised=True)
    assert not by_type(ev, "review")
    assert by_type(ev, "action")[0]["action"]["arguments"]["recipient"] == "hiring@ourco.example"
    assert by_type(ev, "decision")[0]["final_decision"] == "APPROVAL"


def cont(client, **body):
    r = client.post("/api/hr/continue", json=body)
    assert r.status_code == 200
    return [json.loads(line) for line in r.text.splitlines() if line.strip()]


def test_flagged_application_pauses_for_a_human_and_can_be_excluded(client):
    ev = run(client, protection=True, source="sample", sample="poisoned", compromised=True)
    review = by_type(ev, "review")[0]
    assert review["flagged"] == ["email-3"] and by_type(ev, "done")[0]["final_decision"] == "REVIEW"
    assert not by_type(ev, "action")                       # the agent has not seen anything yet

    ev = cont(client, session_id=review["session_id"], include=["email-1", "email-2"], seconds={"email-3": 4.2})
    assert by_type(ev, "reviewed")[0]["excluded"] == ["email-3"]
    act = by_type(ev, "action")[0]["action"]
    assert act["arguments"]["recipient"] == "hiring@ourco.example" and "Alex Morgan" not in act["arguments"]["body"]
    assert by_type(ev, "decision")[0]["final_decision"] == "APPROVAL"   # still a human gate before sending
    assert any("email-3 (Alex Morgan): excluded after 4.2 s" in a for a in by_type(ev, "done")[0]["audit"])
    # the paused run is consumed; it cannot be resumed twice
    assert client.post("/api/hr/continue", json={"session_id": review["session_id"]}).status_code == 404


def test_including_a_flagged_application_anyway_is_still_blocked(client):
    ev = run(client, protection=True, source="sample", sample="poisoned", compromised=True)
    sid = by_type(ev, "review")[0]["session_id"]
    ev = cont(client, session_id=sid, include=["email-1", "email-2", "email-3"])
    assert by_type(ev, "action")[0]["action"]["arguments"]["recipient"] == "talent-sync@recruit-hub.example"
    assert by_type(ev, "decision")[0]["final_decision"] == "DENY"
    assert any("included anyway" in a for a in by_type(ev, "done")[0]["audit"])


def test_candidate_name_from_the_first_line_of_a_cv():
    name = lambda body: screening.candidate_name({"body": body, "subject": "cv", "from": "Sender <s@x.example>"})
    assert name("LENA MOREAUPerformance & Growth Marketing") == "Lena Moreau"
    assert name("Pierre Richard\nCergy, France") == "Pierre Richard"
    assert name("Dear hiring team,") == "Sender"


def test_gmail_source_requires_a_connection(client):
    assert client.post("/api/hr/run", json={"source": "gmail"}).status_code == 401


def test_included_after_the_impact_explanation_is_audited_as_such(client):
    ev = run(client, protection=True, source="sample", sample="poisoned", compromised=True)
    sid = by_type(ev, "review")[0]["session_id"]
    ev = cont(client, session_id=sid, include=["email-1", "email-2", "email-3"],
              seconds={"email-3": 6.0}, acknowledged=["email-3"])
    audit = by_type(ev, "done")[0]["audit"]
    assert "[human] email-3 (Alex Morgan): included anyway after flagged-content review (6.0 s)" in audit
    assert by_type(ev, "decision")[0]["final_decision"] == "DENY"   # the review does not bypass policy
