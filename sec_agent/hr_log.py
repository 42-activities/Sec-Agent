"""Run log for the HR review dashboard (/hr-dashboard).

One row per Demo HR screening run: how many applications came in, what the input guard
flagged (as categories), what the human reviewer excluded or included anyway and how long
each decision took, what the agent proposed, the decision, and — after /execute — the
human approval and whether the action ran. Stored in the same SQLite file as the SOC log
(table `hr_runs`), but separate from it: the SOC log is about security events, this one is
about the review workflow.

Only runs on real input — the user's connected Gmail — are recorded; runs on the synthetic
sample inbox are demo traffic and are not.

Privacy: the dashboard is public, so a run keeps COUNTS ONLY — no names, subjects, senders,
recipients, reasons, per-application rows or content. Only numbers and category keys.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

from .config import settings
from .screening import CATEGORIES

log = logging.getLogger("sec_agent.hr_log")
_lock = threading.Lock()
_MAX_ROWS = 5_000
ABANDON_AFTER = timedelta(hours=1)   # a review nobody continued within an hour counts as abandoned

EXPORT_COLUMNS = ["run_id", "ts", "protection", "source", "scenario", "agent", "status", "applications",
                  "clean", "flagged", "unchecked", "excluded", "included_anyway", "median_decision_s",
                  "final_decision", "attack_type", "human_approval", "executed", "categories"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


@contextmanager
def _db():
    path = Path(settings.events_db)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS hr_runs (
            run_id TEXT PRIMARY KEY, ts TEXT NOT NULL, updated_at TEXT NOT NULL, data TEXT NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS hr_runs_ts ON hr_runs(ts)")
        yield conn
        conn.commit()
    finally:
        conn.close()


def new_run(run_id: str, *, protection: bool, source: str, scenario: Optional[str], compromised: bool) -> dict:
    return {"run_id": run_id, "ts": _now().isoformat(timespec="seconds"), "protection": protection,
            "source": source, "scenario": scenario if source == "sample" else None,
            "agent": "scripted" if compromised else "live", "status": "running",
            "applications": 0, "clean": 0, "flagged": 0, "unchecked": 0, "categories": {},
            "review": None, "action": None, "final_decision": None, "attack_type": None, "top_reason": None,
            "human_approval": None, "approval_seconds": None, "executed": None, "soc": False, "apps": []}


def _private(rec: dict) -> dict:
    """What may be stored for a run: everything but numbers and categories is dropped."""
    out = dict(rec, apps=[], top_reason=None)
    if out.get("action"):
        out["action"] = {"tool": out["action"].get("tool"), "internal": out["action"].get("internal")}
    return out


def recorded(source: str) -> bool:
    return source == "gmail"


def save(rec: dict) -> None:
    if not recorded(rec.get("source", "")):
        return
    try:
        data = _private(rec)
        now = _now().isoformat(timespec="seconds")
        with _lock, _db() as db:
            db.execute("INSERT OR REPLACE INTO hr_runs VALUES (?,?,?,?)",
                       (data["run_id"], data["ts"], now, json.dumps(data, default=str)))
            db.execute("DELETE FROM hr_runs WHERE run_id IN (SELECT run_id FROM hr_runs "
                       "ORDER BY ts DESC LIMIT -1 OFFSET ?)", (_MAX_ROWS,))
    except Exception:  # the run log must never break a run
        log.exception("failed to record HR run")


def load(run_id: str) -> Optional[dict]:
    with _db() as db:
        row = db.execute("SELECT data FROM hr_runs WHERE run_id=?", (run_id,)).fetchone()
    return json.loads(row["data"]) if row else None


def on_execute(run_id: str, approve: bool, executed: bool) -> None:
    """After /execute on an HR run: the human approval of the proposed action and its outcome."""
    try:
        rec = load(run_id)
        if rec is None or rec.get("final_decision") not in ("ALLOW", "APPROVAL"):
            return
        if rec["final_decision"] == "APPROVAL":
            rec["human_approval"] = "approved" if approve else "rejected"
            decided = _now() - datetime.fromisoformat(rec.get("decided_at") or rec["ts"])
            rec["approval_seconds"] = round(decided.total_seconds(), 1)
        rec["executed"] = executed
        save(rec)
    except Exception:
        log.exception("failed to record HR execution")


def _status(rec: dict, pending: Iterable[str]) -> str:
    """A paused review counts as abandoned once it can no longer be resumed (restart) or is stale."""
    if rec.get("status") == "review":
        stale = _now() - datetime.fromisoformat(rec["ts"]) > ABANDON_AFTER
        if stale or rec["run_id"] not in set(pending):
            return "abandoned"
    return rec.get("status", "done")


def clear() -> int:
    """Delete every recorded run (admin reset). Returns how many were removed."""
    with _lock, _db() as db:
        return db.execute("DELETE FROM hr_runs").rowcount


def get(run_id: str, pending: Iterable[str] = ()) -> Optional[dict]:
    rec = load(run_id)
    if rec is not None and not recorded(rec.get("source", "")):
        return None
    if rec is not None:
        rec["status"] = _status(rec, pending)
    return rec


def runs(hours: int, pending: Iterable[str] = ()) -> list[dict]:
    """Runs in the window (hours <= 0: all), newest first."""
    pending = set(pending)
    with _db() as db:
        if hours > 0:
            since = (_now() - timedelta(hours=hours)).isoformat(timespec="seconds")
            rows = db.execute("SELECT data FROM hr_runs WHERE ts >= ? ORDER BY ts DESC", (since,)).fetchall()
        else:
            rows = db.execute("SELECT data FROM hr_runs ORDER BY ts DESC").fetchall()
    out = []
    for r in rows:
        rec = json.loads(r["data"])
        if not recorded(rec.get("source", "")):   # sample runs recorded before Gmail-only
            continue
        rec["status"] = _status(rec, pending)
        out.append(rec)
    return out


def _median(xs: list) -> Optional[float]:
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    m = len(xs) // 2
    return round(xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2, 1)


def summary(hours: int, pending: Iterable[str] = ()) -> dict:
    rs = runs(hours, pending)
    total = lambda k: sum(r.get(k) or 0 for r in rs)
    rv = lambda k: sum((r.get("review") or {}).get(k) or 0 for r in rs)
    count = lambda key: {v: sum(1 for r in rs if key(r) == v) for v in sorted({key(r) for r in rs} - {None})}
    cats = {k: sum((r.get("categories") or {}).get(k, 0) for r in rs) for k in CATEGORIES}
    return {
        "hours": hours, "runs": len(rs),
        "runs_on": sum(1 for r in rs if r.get("protection")), "runs_off": sum(1 for r in rs if not r.get("protection")),
        "by_source": count(lambda r: r.get("source")),
        "applications": total("applications"), "clean": total("clean"), "flagged": total("flagged"),
        "unchecked": total("unchecked"), "excluded": rv("excluded"), "included_anyway": rv("included_anyway"),
        "awaiting_review": sum(1 for r in rs if r["status"] == "review"),
        "abandoned": sum(1 for r in rs if r["status"] == "abandoned"),
        "median_decision_s": _median([s for r in rs for s in (r.get("review") or {}).get("seconds", [])]),
        "median_approval_s": _median([r.get("approval_seconds") for r in rs]),
        "decisions": count(lambda r: r.get("final_decision")),
        "approvals": count(lambda r: r.get("human_approval")),
        "categories": {k: n for k, n in cats.items() if n},
        "category_labels": CATEGORIES,
        "recent": [_row(r) for r in rs[:100]],
    }


def _row(rec: dict) -> dict:
    """One flat line per run — the run list on the page and the export."""
    review = rec.get("review") or {}
    return {
        "run_id": rec["run_id"], "ts": rec["ts"], "protection": "ON" if rec.get("protection") else "OFF",
        "source": rec.get("source"), "scenario": rec.get("scenario") or "", "agent": rec.get("agent"),
        "status": rec.get("status"), "applications": rec.get("applications", 0), "clean": rec.get("clean", 0),
        "flagged": rec.get("flagged", 0), "unchecked": rec.get("unchecked", 0),
        "excluded": review.get("excluded", 0), "included_anyway": review.get("included_anyway", 0),
        "median_decision_s": _median(review.get("seconds", [])),
        "final_decision": rec.get("final_decision") or "", "attack_type": rec.get("attack_type") or "",
        "human_approval": rec.get("human_approval") or "",
        "executed": "" if rec.get("executed") is None else ("yes" if rec["executed"] else "no"),
        "categories": ";".join(f"{k}={n}" for k, n in sorted((rec.get("categories") or {}).items())),
    }


def export_rows(hours: int, pending: Iterable[str] = ()) -> list[dict]:
    return [_row(r) for r in runs(hours, pending)]
