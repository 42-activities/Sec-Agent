"""HR runs dashboard (/hr-dashboard): only real (Gmail) runs are recorded, counts only; admin reset."""

import csv
import io
import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import sec_agent.graph as graph
import sec_agent.web.app as webapp
from sec_agent import gmail, hr_log, screening
from sec_agent.config import settings
from sec_agent.models import Decision, SecurityDecision

SID = "test-gmail-session"


@pytest.fixture
def client(monkeypatch):
    def llm_allows(state):
        return {"security_decision": SecurityDecision(classification="benign", risk_score=5, goal_relevance=0.9,
                                                      decision=Decision.ALLOW, reason="stub"),
                "audit": state.get("audit", [])}

    monkeypatch.setattr(graph, "security_node", llm_allows)
    # A connected Gmail whose application label holds the (synthetic) poisoned sample inbox.
    monkeypatch.setattr(gmail, "list_messages", lambda *a, **k: screening.sample_emails("poisoned"))
    monkeypatch.setitem(webapp._GMAIL, SID, {"token": "tok", "email": "me@example.org", "expires": time.time() + 3600})
    webapp._HR_PENDING.clear()
    return TestClient(webapp.app, base_url="https://testserver", cookies={"sa_gmail": SID})


def stream(client, path, **body):
    r = client.post(path, json=body)
    assert r.status_code == 200
    return [json.loads(line) for line in r.text.splitlines() if line.strip()]


def gmail_review_run(client):
    ev = stream(client, "/api/hr/run", protection=True, source="gmail", compromised=True)
    return next(e for e in ev if e["type"] == "review")["session_id"]


def test_gmail_run_is_recorded_with_counts_categories_and_decision_time(client):
    sid = gmail_review_run(client)
    rec = client.get(f"/api/hr/runs/{sid}").json()
    assert rec["status"] == "review" and rec["source"] == "gmail" and rec["flagged"] == 1 and rec["clean"] == 2
    assert {"ai_instructions", "hidden_text"} <= set(rec["categories"])

    stream(client, "/api/hr/continue", session_id=sid, include=["email-1", "email-2", "email-3"],
           seconds={"email-3": 4.0}, acknowledged=["email-3"])
    rec = client.get(f"/api/hr/runs/{sid}").json()
    assert rec["status"] == "done" and rec["final_decision"] == "DENY"
    assert rec["review"] == {"excluded": 0, "included_anyway": 1, "acknowledged": 1, "seconds": [4.0]}
    assert rec["attack_type"] == "data_exfiltration" and rec["executed"] is False
    # counts only: no names, no per-application rows, no recipient, no reasons
    raw = json.dumps(rec)
    assert rec["apps"] == [] and rec["top_reason"] is None
    assert "Alex Morgan" not in raw and "recruit-hub" not in raw and "Jordan" not in raw

    s = client.get("/api/hr/summary").json()
    assert s["runs"] == 1 and s["included_anyway"] == 1 and s["median_decision_s"] == 4.0
    assert s["decisions"] == {"DENY": 1} and s["by_source"] == {"gmail": 1}


def test_sample_inbox_runs_are_not_recorded(client):
    ev = stream(client, "/api/hr/run", protection=True, source="sample", sample="poisoned", compromised=True)
    sid = next(e for e in ev if e["type"] == "review")["session_id"]
    stream(client, "/api/hr/run", protection=False, source="sample", sample="poisoned", compromised=True)
    assert client.get("/api/hr/summary").json()["runs"] == 0
    assert client.get(f"/api/hr/runs/{sid}").status_code == 404


def test_unprotected_runs_count_as_unchecked_never_clean(client):
    stream(client, "/api/hr/run", protection=False, source="gmail", compromised=True)
    s = client.get("/api/hr/summary").json()
    assert s["runs_off"] == 1 and s["unchecked"] == 3 and s["clean"] == 0 and s["flagged"] == 0
    assert s["decisions"] == {"EXECUTED": 1}


def test_a_review_nobody_continues_becomes_abandoned(client):
    sid = gmail_review_run(client)
    assert client.get("/api/hr/summary").json()["awaiting_review"] == 1
    webapp._HR_PENDING.clear()                       # e.g. a redeploy: the paused run can't be resumed
    s = client.get("/api/hr/summary").json()
    assert s["awaiting_review"] == 0 and s["abandoned"] == 1
    rec = hr_log.load(sid)                           # a stale review is abandoned even while held in memory
    rec["ts"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds")
    hr_log.save(rec)
    assert hr_log.get(sid, [sid])["status"] == "abandoned"


def test_human_approval_of_the_shortlist_is_recorded(client):
    sid = gmail_review_run(client)
    stream(client, "/api/hr/continue", session_id=sid, include=["email-1", "email-2"], seconds={"email-3": 2.0})
    assert client.get(f"/api/hr/runs/{sid}").json()["final_decision"] == "APPROVAL"
    assert client.post("/execute", json={"session_id": sid, "approve": True}).status_code == 200
    rec = client.get(f"/api/hr/runs/{sid}").json()
    assert rec["human_approval"] == "approved" and rec["executed"] is True


def test_stored_record_never_holds_names_or_recipients():
    rec = hr_log.new_run("g1", protection=True, source="gmail", scenario="poisoned", compromised=False)
    rec.update(applications=2, flagged=1, clean=1, categories={"ai_instructions": 1}, status="done",
               final_decision="DENY", top_reason="recipient domain 'evil.example' is outside the allowed domains",
               action={"tool": "send_email", "recipient": "x@evil.example", "internal": False},
               apps=[{"id": "email-1", "candidate": "Real Person", "status": "flagged"}])
    hr_log.save(rec)
    stored = hr_log.load("g1")
    raw = json.dumps(stored)
    assert "Real Person" not in raw and "evil.example" not in raw
    assert stored["apps"] == [] and stored["scenario"] is None and stored["action"] == {"tool": "send_email", "internal": False}
    assert stored["applications"] == 2 and stored["categories"] == {"ai_instructions": 1}


def test_export_is_one_row_per_run(client):
    gmail_review_run(client)
    stream(client, "/api/hr/run", protection=False, source="gmail", compromised=True)
    r = client.get("/api/hr/export?format=csv")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 2 and list(rows[0]) == hr_log.EXPORT_COLUMNS
    assert {row["protection"] for row in rows} == {"ON", "OFF"}
    assert len(client.get("/api/hr/export?format=json").json()) == 2


def test_reset_needs_the_admin_password(client, monkeypatch):
    gmail_review_run(client)
    # no admin password configured: admin actions are disabled (fail closed)
    assert client.post("/api/hr/reset", headers={"X-Admin-Token": "anything"}).status_code == 403
    monkeypatch.setattr(settings, "rules_admin_token", "s3cret")
    assert client.post("/api/hr/reset", headers={"X-Admin-Token": "wrong"}).status_code == 403
    assert client.get("/api/hr/summary").json()["runs"] == 1
    r = client.post("/api/hr/reset", headers={"X-Admin-Token": "s3cret"})
    assert r.status_code == 200 and r.json() == {"cleared": 1}
    assert client.get("/api/hr/summary").json()["runs"] == 0


def test_proxy_verifies_the_admin_password_for_controller_admin_actions(monkeypatch):
    from sec_agent.proxy_service.app import app as proxy_app

    monkeypatch.setattr(settings, "proxy_auth_token", "svc")
    monkeypatch.setattr(settings, "rules_admin_token", "s3cret")
    proxy = TestClient(proxy_app)
    assert proxy.post("/admin/verify", headers={"X-Admin-Token": "s3cret"}).status_code == 401   # not the controller
    ok = {"Authorization": "Bearer svc"}
    assert proxy.post("/admin/verify", headers={**ok, "X-Admin-Token": "wrong"}).status_code == 403
    assert proxy.post("/admin/verify", headers={**ok, "X-Admin-Token": "s3cret"}).json() == {"ok": True}


def test_categories_have_labels():
    assert set(screening.CATEGORIES) >= {"ai_instructions", "hidden_text", "redirect", "jev"}
