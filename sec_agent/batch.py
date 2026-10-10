"""Batch screening: run many prompts through the same Sec-Agent flow.

Each prompt is treated as the **user's own request** (direct prompt injection /
jailbreak screening), so the input guard is told to scan the user prompt too.

Two depths:
  * "input" — input guard only (patterns, hidden text, Jev): fast, no Bedrock.
  * "full"  — the whole controller (input guard → executor → security LLM → policy),
              stopped before execution: nothing is ever executed.

Batch runs are NOT written to the SOC event log (a dataset of hundreds of prompts
would drown the live picture); results are returned to the caller to export.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Iterator

from .graph import build_graph
from .models import AgentState, ContextItem, Trust
from .nodes.input_guard import input_guard_node

MAX_PROMPTS = {"input": 500, "full": 25}
MAX_CHARS = 20_000
WORKERS = {"input": 8, "full": 3}


def _state(prompt: str) -> AgentState:
    return {
        "user_goal": prompt,
        "context_items": [ContextItem(id="user-request", source="batch", source_type="user_message",
                                      content=prompt, trust=Trust.TRUSTED)],
        "scan_user_prompt": True,
        "audit": [],
    }


def _summary(index: int, prompt: str, state: AgentState, ms: int) -> dict:
    item = state["context_items"][0]
    jev = (state.get("jev_input") or {}).get(item.id) or {}
    checks = state.get("checks") or state.get("input_checks") or []
    flagged = [f"{c.id} {c.criterion}" for c in checks
               if c.result.value in ("flag", "fail") and c.id not in ("T5", "T10", "P9")]
    found = (state.get("input_findings") or {}).get(item.id) or {}
    detectors = []
    if found.get("injection") or found.get("sensitive") or found.get("secrecy"):
        detectors.append("pattern")
    if found.get("hidden"):
        detectors.append("hidden text")
    if jev.get("suspicious"):
        detectors.append("Jev")
    action = state.get("proposed_action")
    sec = state.get("security_decision")
    final = state.get("final_decision")
    return {
        "index": index,
        "prompt": prompt[:300],
        "chars": len(prompt),
        "injection": item.taint.value == "suspicious",
        "detectors": detectors,
        "jev_level": jev.get("level"), "jev_confidence": jev.get("confidence"),
        "jev_signals": jev.get("signals"), "jev_status": jev.get("status"), "jev_reasons": jev.get("reasons"),
        "matched": [*found.get("injection", []), *found.get("sensitive", []), *found.get("secrecy", [])][:8],
        "hidden": found.get("hidden", []),
        "flagged_checks": flagged,
        "checks": [c.model_dump(mode="json") for c in checks],
        "tool": action.tool if action else None,
        "arguments": action.arguments if action else None,
        "security_llm": ({"decision": sec.decision.value, "classification": sec.classification,
                          "risk_score": sec.risk_score} if sec else None),
        "final_decision": final.value if final else None,
        "ms": ms,
    }


def _run_one(index: int, prompt: str, mode: str) -> dict:
    t0 = time.perf_counter()
    try:
        state = _state(prompt)
        if mode == "full":
            state = build_graph(include_executor=True, execute=False).invoke(state)
        else:
            state.update(input_guard_node(state))
        return _summary(index, prompt, state, round((time.perf_counter() - t0) * 1000))
    except Exception as exc:  # one bad prompt must not stop the batch
        return {"index": index, "prompt": prompt[:300], "chars": len(prompt),
                "error": f"{type(exc).__name__}: {exc}"[:300], "ms": round((time.perf_counter() - t0) * 1000)}


def run(prompts: list[str], mode: str) -> Iterator[dict]:
    """Yield one result per prompt as it finishes (order of completion; ``index`` keeps position)."""
    with ThreadPoolExecutor(max_workers=WORKERS[mode]) as pool:
        futures = [pool.submit(_run_one, i, p, mode) for i, p in enumerate(prompts)]
        for f in futures:  # in submission order, so progress reads top-down
            yield f.result()
