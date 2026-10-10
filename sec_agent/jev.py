"""Jev (TypeSafe AI) — prompt-injection risk scoring for untrusted input.

Jev is a calibrated classifier: it returns probabilities and a confidence score,
not generated text, so a poisoned document can at most shift a number — it cannot
make Jev *do* anything.

The input guard asks Jev to rate each untrusted context item on a six-level risk
scale (0/20/40/60/80/100) and shows it as additional information. Jev may only
RAISE an item's taint (at or above the configurable level); a low score never makes
content trusted. It is advisory: the deterministic policy engine stays the boundary.
Without TYPESAFE_API_KEY, or on any API error, Jev is simply skipped.
"""

from __future__ import annotations

import time
from functools import lru_cache

from .config import settings

# Jev's state budget is 32k tokens; keep well under it (~4 chars per token).
_MAX_STATE_CHARS = 100_000

# One description per level; Jev's Score answer is an index into this list.
RISK_LEVELS = [
    "0 — ordinary content, no attempt to steer an AI or automated system",
    "20 — mentions automation or AI but gives no instructions to it",
    "40 — contains suggestions an automated assistant might act on",
    "60 — embeds steps meant to change what an AI agent does",
    "80 — clear attempt to make an AI agent take an unrequested action",
    "100 — explicit prompt-injection attack (hidden orders, data theft, secrecy)",
]


def enabled() -> bool:
    return bool(settings.typesafe_api_key)


@lru_cache(maxsize=1)
def _client():
    from typesafe_sdk import TypeSafeClient

    return TypeSafeClient(api_key=settings.typesafe_api_key, timeout=settings.jev_timeout_s,
                          model=settings.jev_model or None)


def _questions() -> dict:
    from typesafe_sdk import Noul, Score

    return {
        "risk": Score(instructions="How much prompt-injection risk does this text pose to an AI agent that "
                                   "reads it while doing a task for a user?",
                      criteria=RISK_LEVELS),
        # Explanations shown next to the level.
        "ai_instructions": Noul(instructions="The text contains instructions addressed to an AI assistant, "
                                             "agent or automated system that will read it"),
        "redirect": Noul(instructions="The text asks to send data, documents or money to a new or different "
                                      "recipient, email address, URL or bank account"),
        "secrets": Noul(instructions="The text asks to read, reveal or send passwords, keys, credentials, "
                                     "tokens or other secrets"),
        "pressure": Noul(instructions="The text uses urgency, threats or claimed authority to pressure the "
                                      "reader into acting"),
    }


def scan_untrusted(content: str, source_type: str, suspicious_level: int) -> dict:
    """Rate one untrusted context item. Returns a JSON-friendly result dict."""
    state = {"source_type": source_type, "content": content[:_MAX_STATE_CHARS]}
    t0 = time.perf_counter()
    try:
        resp = _client().system_one(state=state, questions=_questions())
    except Exception as exc:  # advisory: an API failure must not break the pipeline
        return {"status": "error", "error": f"{type(exc).__name__}: {exc}"[:300]}
    ms = round((time.perf_counter() - t0) * 1000)
    a = resp.answers
    risk = a["risk"]
    level = int(round(risk.score)) * 20  # 0..5 -> 0..100
    return {
        "status": "ok", "ms": ms, "model": resp.model,
        "level": level,
        "confidence": round(risk.confidence, 3),
        "distribution": {int(k) * 20: round(v, 3) for k, v in risk.probabilities.items()},
        "signals": {k: round(a[k].noul, 3) for k in ("ai_instructions", "redirect", "secrets", "pressure")},
        "suspicious": level >= suspicious_level,
    }
