"""Security event log for the SOC dashboard.

One row per controller run (a "session"): what came in, what the guards saw,
what the agent proposed, what was decided, and — after /execute — what the human
and the proxy did. Stored in SQLite (a Docker volume in production) and also
written to stdout as one JSON line per event, so any log shipper / SIEM can
collect it.

Privacy: the untrusted document itself is never stored (only its length and a
hash), and free text is truncated.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .config import settings
from .models import AgentState

log = logging.getLogger("sec_agent.events")
_lock = threading.Lock()
_MAX_ROWS = 20_000
_TXT = 200


def _now() -> datetime:
    return datetime.now(timezone.utc)


@contextmanager
def _db():
    path = Path(settings.events_db)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS events (
            session_id TEXT PRIMARY KEY, ts TEXT NOT NULL, updated_at TEXT NOT NULL,
            final_decision TEXT, attack_type TEXT, data TEXT NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)")
        yield conn
        conn.commit()
    finally:
        conn.close()


def _short(v: Any, n: int = _TXT) -> str:
    s = v if isinstance(v, str) else json.dumps(v, default=str)
    return s if len(s) <= n else s[: n - 1] + "…"


# Most specific first: the deterministic rule that fired names the attack best.
_RULE_TYPES = [
    ("IBAN does not match", "bank_details_fraud"),
    ("not in the vendor master data", "bank_details_fraud"),
    ("external data egress", "data_exfiltration"),
    ("denied resource", "credential_access"),
    ("not in the allow-list", "unauthorized_tool"),
]


def classify(policy_reasons: list[str], sec_classification: str, sec_denied: bool, injected_input: bool) -> str:
    """Name the attack, or "none". A deterministic rule names it best; the security LLM's
    label only counts when it actually voted DENY (it also labels legitimate payments
    'exfiltration' while merely asking for approval)."""
    for needle, kind in _RULE_TYPES:
        if any(needle in r for r in policy_reasons):
            return kind
    c = (sec_classification or "").lower()
    if sec_denied and "exfil" in c:
        return "data_exfiltration"
    if sec_denied and ("inject" in c or "hijack" in c):
        return "prompt_injection"
    if injected_input:
        return "prompt_injection"
    return "none"


def _from_state(session_id: str, state: AgentState, compromised: bool) -> dict:
    action = state.get("proposed_action")
    sec = state.get("security_decision")
    items = state.get("context_items", [])
    jev_input = state.get("jev_input") or {}
    docs = []
    for i in items:
        if i.trust.value == "trusted":
            continue
        j = jev_input.get(i.id) or {}
        docs.append({
            "id": i.id, "source_type": i.source_type, "chars": len(i.content),
            "sha256": hashlib.sha256(i.content.encode()).hexdigest()[:16],
            "taint": i.taint.value, "regex_flagged": i.instruction_detected,
            "jev_level": j.get("level"), "jev_signals": j.get("signals"),
            "jev_suspicious": j.get("suspicious"), "jev_ms": j.get("ms"),
        })
    reasons = state.get("policy_reasons", [])
    final = state.get("final_decision")
    injected = any(d["taint"] == "suspicious" for d in docs)
    return {
        "session_id": session_id,
        "goal": _short(state.get("user_goal", "")),
        "executor": "compromised (simulated)" if compromised else "live LLM",
        "documents": docs,
        "tool": action.tool if action else None,
        "arguments": _short(action.arguments if action else {}),
        "security_llm": ({"decision": sec.decision.value, "classification": sec.classification,
                          "risk_score": sec.risk_score, "reason": _short(sec.reason, 400)} if sec else None),
        "policy_decision": (state.get("policy_decision").value if state.get("policy_decision") else None),
        "policy_reasons": reasons,
        "final_decision": final.value if final else None,
        "attack_type": classify(reasons, sec.classification if sec else "",
                                bool(sec and sec.decision.value == "DENY"), injected),
        "detected_by": _detected_by(docs, sec, state.get("policy_decision")),
        "human": None, "executed": None, "outcome": None, "approval_seconds": None,
        "checks": [c.model_dump(mode="json") for c in state.get("checks", [])],
        "audit": state.get("audit", []),
    }


def _detected_by(docs: list[dict], sec, policy) -> list[str]:
    out = []
    if any(d["regex_flagged"] for d in docs):
        out.append("regex")
    if any(d.get("jev_suspicious") for d in docs):
        out.append("jev")
    if sec is not None and sec.decision.value != "ALLOW":
        out.append("security_llm")
    if policy is not None and policy.value != "ALLOW":
        out.append("policy")
    return out


def _emit(kind: str, data: dict) -> None:
    # One JSON line per event on stdout — the hook for a log shipper / SIEM.
    print(json.dumps({"event": kind, **{k: v for k, v in data.items() if k != "audit"}}, default=str), flush=True)


def record_analysis(session_id: str, state: AgentState, compromised: bool) -> None:
    """Called once the controller has decided (before any execution)."""
    try:
        data = _from_state(session_id, state, compromised)
        ts = _now().isoformat(timespec="seconds")
        data["ts"] = ts
        with _lock, _db() as db:
            db.execute("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?)",
                       (session_id, ts, ts, data["final_decision"], data["attack_type"], json.dumps(data, default=str)))
            db.execute("DELETE FROM events WHERE session_id IN (SELECT session_id FROM events "
                       "ORDER BY ts DESC LIMIT -1 OFFSET ?)", (_MAX_ROWS,))
        _emit("sec_agent.decision", data)
    except Exception:  # the event log must never break the request
        log.exception("failed to record analysis event")


def record_execution(session_id: str, state: AgentState, approve: bool) -> None:
    """Called after /execute: the human's answer and what the proxy did."""
    try:
        with _lock, _db() as db:
            row = db.execute("SELECT data FROM events WHERE session_id=?", (session_id,)).fetchone()
            if row is None:
                return
            data = json.loads(row["data"])
            now = _now()
            if data["final_decision"] == "APPROVAL":
                data["human"] = "approved" if approve else "rejected"
                data["approval_seconds"] = round((now - datetime.fromisoformat(data["ts"])).total_seconds())
            result = state.get("execution_result")
            data["executed"] = result is not None
            data["outcome"] = _short(result if result is not None else (state.get("audit") or [""])[-1])
            data["audit"] = state.get("audit", [])
            db.execute("UPDATE events SET updated_at=?, data=? WHERE session_id=?",
                       (now.isoformat(timespec="seconds"), json.dumps(data, default=str), session_id))
        _emit("sec_agent.execution", data)
    except Exception:
        log.exception("failed to record execution event")


def get(session_id: str) -> Optional[dict]:
    with _db() as db:
        row = db.execute("SELECT data FROM events WHERE session_id=?", (session_id,)).fetchone()
    return json.loads(row["data"]) if row else None


ATTACK_LABELS = {
    "prompt_injection": "Prompt injection", "data_exfiltration": "Data exfiltration",
    "bank_details_fraud": "Bank-details fraud", "credential_access": "Credential access",
    "unauthorized_tool": "Unauthorized tool",
}


def summary(hours: int) -> dict:
    """Everything the SOC dashboard shows for the last ``hours``."""
    since = _now() - timedelta(hours=hours)
    with _db() as db:
        rows = [json.loads(r["data"]) for r in
                db.execute("SELECT data FROM events WHERE ts >= ? ORDER BY ts", (since.isoformat(timespec="seconds"),))]

    total = len(rows)
    by_decision = {d: sum(1 for r in rows if r["final_decision"] == d) for d in ("ALLOW", "APPROVAL", "DENY")}
    attacks = [r for r in rows if r["attack_type"] != "none"]
    blocked_attacks = [r for r in attacks if r["final_decision"] == "DENY"]
    approvals = [r for r in rows if r["final_decision"] == "APPROVAL"]
    decided = [r for r in approvals if r["human"]]
    pending = [r for r in approvals if not r["human"]]
    # An attack "got through" only if it was executed — the number a SOC cares about most.
    executed_attacks = [r for r in attacks if r["executed"]]

    # Time buckets: hourly up to 2 days, otherwise daily.
    step = timedelta(hours=1) if hours <= 48 else timedelta(days=1)
    start = since.replace(minute=0, second=0, microsecond=0)
    if step.days:
        start = start.replace(hour=0)
    buckets = []
    t = start
    while t <= _now():
        buckets.append({"t": t.isoformat(timespec="minutes"), "ALLOW": 0, "APPROVAL": 0, "DENY": 0})
        t += step
    for r in rows:
        idx = int((datetime.fromisoformat(r["ts"]) - start) / step)
        if 0 <= idx < len(buckets) and r["final_decision"] in ("ALLOW", "APPROVAL", "DENY"):
            buckets[idx][r["final_decision"]] += 1

    def count(key_fn) -> list[dict]:
        out: dict[str, int] = {}
        for r in rows:
            for k in key_fn(r):
                out[k] = out.get(k, 0) + 1
        return [{"label": k, "count": v} for k, v in sorted(out.items(), key=lambda kv: -kv[1])]

    # Rules that changed a decision, and criteria that flagged or failed — from the checklist.
    def fired(r):
        return list(dict.fromkeys(f"{c['id']} · {c['criterion']}" for c in r.get("checks", [])
                                  if c.get("effect") and c["checked_by"] == "policy"))

    def failed(r):
        return [f"{c['id']} · {c['criterion']}" for c in r.get("checks", []) if c["result"] in ("fail", "flag")
                # T5 flags every run that had a document and T10 restates the verdict — bookkeeping, not signal.
                and c["id"] not in ("T5", "T10")]

    rules_fired = count(fired)
    criteria_failed = count(failed)
    jev_levels = [d["jev_level"] for r in rows for d in r["documents"] if d.get("jev_level") is not None]
    jev_ms = [d["jev_ms"] for r in rows for d in r["documents"] if d.get("jev_ms")]

    incidents = [
        {k: r[k] for k in ("session_id", "ts", "attack_type", "tool", "arguments", "final_decision",
                           "detected_by", "human", "executed", "executor")}
        | {"jev_level": max((d["jev_level"] for d in r["documents"] if d.get("jev_level") is not None), default=None)}
        for r in reversed(rows) if r["attack_type"] != "none" or r["final_decision"] != "ALLOW"
    ][:100]

    return {
        "hours": hours, "generated_at": _now().isoformat(timespec="seconds"),
        "kpis": {
            "total": total, **by_decision,
            "attacks": len(attacks), "attacks_blocked": len(blocked_attacks),
            "attacks_executed": len(executed_attacks),
            "approvals_pending": len(pending),
            "approved": sum(1 for r in decided if r["human"] == "approved"),
            "rejected": sum(1 for r in decided if r["human"] == "rejected"),
            "median_approval_s": _median([r["approval_seconds"] for r in decided if r["approval_seconds"] is not None]),
            "jev_median_ms": _median(jev_ms),
        },
        "timeline": buckets, "bucket": "hour" if not step.days else "day",
        "attack_types": [{"label": ATTACK_LABELS.get(x["label"], x["label"]), "count": x["count"]}
                         for x in count(lambda r: [r["attack_type"]] if r["attack_type"] != "none" else [])],
        "rules_fired": rules_fired,
        "criteria_failed": criteria_failed[:12],
        "detected_by": count(lambda r: r["detected_by"] if r["attack_type"] != "none" else []),
        "jev_distribution": [{"label": str(lv), "count": sum(1 for x in jev_levels if x == lv)}
                             for lv in (0, 20, 40, 60, 80, 100)],
        "incidents": incidents,
        "narrative": _narrative(hours, total, by_decision, attacks, blocked_attacks, executed_attacks,
                                pending, rules_fired),
    }


def _median(xs: list) -> Optional[float]:
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else round((xs[m - 1] + xs[m]) / 2, 1)


def _narrative(hours, total, by_decision, attacks, blocked, executed, pending, rules_fired) -> list[str]:
    """Plain-language SOC summary, built from the numbers (no LLM — it can't hallucinate)."""
    span = f"the last {hours} hours" if hours < 48 else f"the last {hours // 24} days"
    if total == 0:
        return [f"No agent activity in {span}."]
    lines = [f"In {span} the controller reviewed {total} agent action{'s' * (total != 1)}: "
             f"{by_decision['ALLOW']} allowed, {by_decision['APPROVAL']} sent to a human, "
             f"{by_decision['DENY']} blocked."]
    if attacks:
        kinds: dict[str, int] = {}
        for r in attacks:
            kinds[r["attack_type"]] = kinds.get(r["attack_type"], 0) + 1
        top = ", ".join(f"{n} {ATTACK_LABELS.get(k, k).lower()}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1]))
        lines.append(f"{len(attacks)} attack attempt{'s' * (len(attacks) != 1)} detected ({top}); "
                     f"{len(blocked)} blocked outright.")
        live = sum(1 for r in attacks if r["executor"] == "live LLM")
        if live:
            lines.append(f"In {live} of them the live LLM agent itself was manipulated into proposing the action — "
                         f"the controller stopped it anyway.")
    n = len(executed)
    lines.append("No attack reached a real tool." if not n else
                 f"⚠ {n} flagged action{'s were' if n != 1 else ' was'} executed after human approval — review "
                 f"{'them' if n != 1 else 'it'}.")
    if pending:
        lines.append(f"{len(pending)} action{'s' * (len(pending) != 1)} still waiting for a human decision.")
    if rules_fired:
        lines.append(f"Most active rule: “{rules_fired[0]['label']}” ({rules_fired[0]['count']}×).")
    return lines
