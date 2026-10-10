"""Input Security Agent.

Inspects context *before* it reaches the executor. This reference implementation
uses fast deterministic heuristics to flag likely injection and to propagate
trust/taint labels. It is intentionally cheap and explainable; an LLM-based
detector can be layered on top (see README -> Extending).

Note: this layer does NOT sanitize the executor's input — by design we let the
executor see (and potentially be fooled by) untrusted content, then rely on the
output-side controller. The guard's job here is to *label* provenance so the
downstream policy engine can reason about influence.
"""

from __future__ import annotations

import re

from ..models import AgentState, ContextItem, Taint, Trust

# Phrases that commonly appear in prompt-injection payloads.
_INJECTION_PATTERNS = [
    r"ignore (all )?(your |the )?(previous|prior|above) instructions",
    r"disregard (the )?(previous|prior|above)",
    r"do not (tell|inform|reveal|mention).{0,30}(user|anyone)",
    r"instead (of|,)",
    r"new instructions?:",
    r"system prompt",
    r"you are now",
    r"important for (ai|assistants?|llms?)",
    r"before (you )?(analy|answer|respond|process)",
    r"exfiltrat|send (it|them|the contents?).{0,30}(to|server|http)",
]

# Hints that untrusted content is steering toward sensitive resources.
_SENSITIVE_HINTS = [r"\.ssh", r"id_ed25519", r"id_rsa", r"\.aws", r"\.env",
                    r"credential", r"secret", r"private key", r"password"]

_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)
_SENSITIVE_RE = re.compile("|".join(_SENSITIVE_HINTS), re.IGNORECASE)


def scan_item(item: ContextItem) -> ContextItem:
    """Return a copy of ``item`` with taint/risk/instruction flags filled in."""
    # Trusted first-party content is never tainted by this guard.
    if item.trust == Trust.TRUSTED:
        return item.model_copy(update={"taint": Taint.NONE})

    has_injection = bool(_INJECTION_RE.search(item.content))
    has_sensitive = bool(_SENSITIVE_RE.search(item.content))

    risk = 0.1
    taint = Taint.EXTERNAL
    if has_injection:
        risk = max(risk, 0.9)
        taint = Taint.SUSPICIOUS
    if has_sensitive:
        risk = max(risk, 0.7)
        taint = Taint.SUSPICIOUS

    return item.model_copy(
        update={
            "instruction_detected": has_injection,
            "risk": risk,
            "taint": taint,
        }
    )


def input_guard_node(state: AgentState) -> AgentState:
    items = [scan_item(i) for i in state.get("context_items", [])]
    audit = list(state.get("audit", []))
    flagged = [i for i in items if i.instruction_detected or i.taint == Taint.SUSPICIOUS]
    for i in flagged:
        audit.append(
            f"[input_guard] {i.id} ({i.source}): trust={i.trust.value} "
            f"taint={i.taint.value} risk={i.risk:.2f} "
            f"instruction_detected={i.instruction_detected}"
        )
    if not flagged:
        audit.append("[input_guard] no suspicious context detected")
    return {"context_items": items, "audit": audit}
