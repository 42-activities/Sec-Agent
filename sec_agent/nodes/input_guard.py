"""Input Security Agent.

Inspects context *before* it reaches the executor, and records one checklist row
per input criterion (P1–P9, see models.Check). Detectors:

  * pattern matching — fast, explainable regexes for known injection phrasing;
  * hidden-text detection — invisible / bidi / Unicode-tag characters, HTML
    comments, base64 blobs and mixed-script look-alike words. Hidden content is
    revealed and scanned too, so an instruction smuggled in base64 is still caught;
  * Jev (TypeSafe AI), optional — calibrated 0–100 prompt-injection risk + signals.

Note: this layer does NOT sanitize the executor's input — by design we let the
executor see (and potentially be fooled by) untrusted content, then rely on the
output-side controller. The guard's job is to *label* provenance and taint so the
downstream reviewers can reason about influence. Detectors only ever raise taint.
"""

from __future__ import annotations

import base64
import binascii
import re
from concurrent.futures import ThreadPoolExecutor

from .. import jev
from ..models import AgentState, Check, CheckResult, ContextItem, Taint, Trust
from ..rules import active

R = CheckResult

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

# Concrete sensitive targets — enough on their own to mark content suspicious.
_SENSITIVE_HINTS = [r"\.ssh", r"id_ed25519", r"id_rsa", r"\.aws", r"\.env", r"private key", r"/etc/shadow"]
# Everyday words ("a secret recipe", "memories, like passwords") — they only count when the
# same text also has an injection phrase, hidden text, or a Jev attack signal ≥ 0.5.
_WEAK_SENSITIVE_HINTS = [r"credential", r"secret", r"password"]

_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)
_SENSITIVE_RE = re.compile("|".join(_SENSITIVE_HINTS), re.IGNORECASE)
_WEAK_SENSITIVE_RE = re.compile("|".join(_WEAK_SENSITIVE_HINTS), re.IGNORECASE)
# Jev signals that corroborate a weak word (by role: a user prompt always "instructs the AI").
_CORROBORATING = {"user_message": ("jailbreak", "secrets"),
                  None: ("ai_instructions", "redirect", "secrets", "jailbreak")}
_SECRECY_RE = re.compile(r"do not (tell|inform|reveal|mention)|don't (tell|mention)|keep (this|it) (secret|hidden)",
                         re.IGNORECASE)

# --- P8: hidden / obfuscated text ---
_ZERO_WIDTH = re.compile("[​-‏⁠-⁤﻿]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]+")  # "ASCII smuggling"
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_WORD = re.compile(r"\w+", re.UNICODE)
_LATIN = re.compile(r"[A-Za-z]")
_LOOKALIKE = re.compile(r"[Ͱ-ϿЀ-ӿ]")  # Greek / Cyrillic


def hidden_text(content: str) -> tuple[list[str], str]:
    """Return (findings, revealed text). Revealed text is what the hidden parts say."""
    findings, revealed = [], []
    if n := len(_ZERO_WIDTH.findall(content)):
        findings.append(f"{n} zero-width character(s)")
    if n := len(_BIDI.findall(content)):
        findings.append(f"{n} bidirectional-override character(s)")
    for run in _TAG_CHARS.findall(content):
        text = "".join(chr(ord(c) - 0xE0000) for c in run if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        findings.append(f"invisible Unicode-tag text: “{text[:60]}”")
        revealed.append(text)
    for comment in _HTML_COMMENT.findall(content):
        if comment.strip():
            findings.append(f"HTML comment: “{comment.strip()[:60]}”")
            revealed.append(comment)
    for blob in _B64.findall(content):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.9 and " " in decoded:
            findings.append(f"base64 text: “{decoded[:60]}”")
            revealed.append(decoded)
    mixed = sorted({w for w in _WORD.findall(content) if _LATIN.search(w) and _LOOKALIKE.search(w)})
    if mixed:
        findings.append(f"look-alike mixed-script word(s): {', '.join(mixed[:5])}")
        revealed.append(" ".join(mixed))
    return findings, "\n".join(revealed)


def _scan_text(item: ContextItem) -> dict:
    """Everything the deterministic detectors see in one untrusted item."""
    hidden, revealed = hidden_text(item.content)
    text = item.content + ("\n" + revealed if revealed else "")
    return {
        "injection": list(dict.fromkeys(m.group(0) for m in _INJECTION_RE.finditer(text))),
        "sensitive": list(dict.fromkeys(m.group(0) for m in _SENSITIVE_RE.finditer(text))),
        "weak": list(dict.fromkeys(m.group(0).lower() for m in _WEAK_SENSITIVE_RE.finditer(text))),
        "secrecy": list(dict.fromkeys(m.group(0) for m in _SECRECY_RE.finditer(text))),
        "hidden": hidden,
        "revealed": revealed,
    }


def scan_item(item: ContextItem, scan: dict | None = None) -> ContextItem:
    """Return a copy of ``item`` with taint/risk/instruction flags filled in.

    Trusted first-party content is not scanned (``scan`` is None) and stays untainted —
    unless the caller asked to scan the user's own prompt, in which case findings taint it.
    """
    if item.trust == Trust.TRUSTED and scan is None:
        return item.model_copy(update={"taint": Taint.NONE})
    scan = scan or _scan_text(item)

    risk, taint = (0.0, Taint.NONE) if item.trust == Trust.TRUSTED else (0.1, Taint.EXTERNAL)
    if scan["injection"]:
        risk, taint = max(risk, 0.9), Taint.SUSPICIOUS
    if scan["sensitive"]:
        risk, taint = max(risk, 0.7), Taint.SUSPICIOUS
    if scan["weak"] and (scan["injection"] or scan["hidden"]):
        # A weak word counts only when the text is already doing something injection-like.
        scan["sensitive"] = [*scan["sensitive"], *scan["weak"]]
        scan["weak"] = []
        risk, taint = max(risk, 0.7), Taint.SUSPICIOUS
    if scan["hidden"]:
        # Content deliberately hidden from human readers is suspicious by itself.
        risk, taint = max(risk, 0.8), Taint.SUSPICIOUS
    return item.model_copy(update={"instruction_detected": bool(scan["injection"]), "risk": risk, "taint": taint})


def _apply_jev(item: ContextItem, result: dict) -> ContextItem:
    """Jev can only RAISE taint/risk — a low score never makes content trusted."""
    if result.get("status") != "ok" or not result["suspicious"]:
        return item
    return item.model_copy(update={"taint": Taint.SUSPICIOUS, "risk": max(item.risk, result["level"] / 100)})


def _row(id: str, criterion: str, by: str, result: CheckResult, evidence: str) -> Check:
    return Check(id=id, stage="input", criterion=criterion, checked_by=by, result=result, evidence=evidence)


def _input_checks(items: list[ContextItem], scans: dict, jev_input: dict, jev_on: bool,
                  user_scanned: bool = False) -> list[Check]:
    untrusted = [i for i in items if i.id in scans]
    checks = [_row("P1", "Source trust", "provenance", R.PASS,
                   "; ".join(f"{i.id}: {i.trust.value} ({i.source_type})" for i in items))]
    if not untrusted:
        na = "no untrusted content in this request"
        for pid, name in [("P2", "Instructions aimed at an AI"), ("P3", "Redirects data or money"),
                          ("P4", "Requests for secrets"), ("P5", "Pressure / urgency"), ("P6", "Secrecy"),
                          ("P7", "Overall injection risk"), ("P8", "Hidden or obfuscated text")]:
            checks.append(_row(pid, name, "-", R.NA, na))
    else:
        jev_ok = {k: v for k, v in jev_input.items() if v.get("status") == "ok"}
        is_user = {i.id for i in items if i.source_type == "user_message"}
        # For a user's own prompt, "instructions to an AI" is normal (look for jailbreaks instead)
        # and asking to send something somewhere is a legitimate request (skip "redirect").
        user_key = {"ai_instructions": "jailbreak", "redirect": None}

        def signal(key: str) -> list[str]:
            out = []
            for iid, r in jev_ok.items():
                k = user_key.get(key, key) if iid in is_user else key
                if k and r["signals"].get(k, 0) >= 0.5:
                    out.append(f"{iid}: Jev {k} {r['signals'][k]:.0%}")
            return out

        def regex(kind: str) -> list[str]:
            return [f"{iid}: “{', '.join(s[kind][:3])}”" for iid, s in scans.items() if s[kind]]

        for pid, name, kind, key in [("P2", "Instructions aimed at an AI", "injection", "ai_instructions"),
                                     ("P3", "Redirects data or money", None, "redirect"),
                                     ("P4", "Requests for secrets", "sensitive", "secrets")]:
            hits = (regex(kind) if kind else []) + signal(key)
            by = "regex+jev" if kind and jev_ok else ("regex" if kind else "jev")
            if not kind and not jev_ok:
                checks.append(_row(pid, name, "jev", R.NOT_CHECKED, "only Jev checks this; Jev is off/unavailable"))
            else:
                note = ""
                if pid == "P4":
                    weak = [f"{iid}: “{', '.join(s['weak'][:3])}”" for iid, s in scans.items() if s["weak"]]
                    if weak:
                        note = (" | " if hits else "") + "mentions " + "; ".join(weak) + \
                               " — a common word, not enough on its own"
                checks.append(_row(pid, name, by, R.FLAG if hits else R.PASS,
                                   ("; ".join(hits) + note) if hits else (note.lstrip(" |") or "nothing found")))
        hits = signal("pressure")
        checks.append(_row("P5", "Pressure / urgency", "jev", R.FLAG if hits else R.PASS,
                           ("; ".join(hits) + " (informs only, never decides)") if hits else "nothing found")
                      if jev_ok else _row("P5", "Pressure / urgency", "jev", R.NOT_CHECKED, "Jev is off/unavailable"))
        hits = regex("secrecy")
        checks.append(_row("P6", "Secrecy", "regex", R.FLAG if hits else R.PASS, "; ".join(hits) or "nothing found"))
        if jev_ok:
            parts = [f"{iid}: {r['level']}/100 (confidence {r['confidence']:.0%})" for iid, r in jev_ok.items()]
            sus = any(r["suspicious"] for r in jev_ok.values())
            checks.append(_row("P7", "Overall injection risk", "jev", R.FLAG if sus else R.PASS, "; ".join(parts)))
        else:
            why = "Jev unavailable" if jev_input else ("Jev is off (no API key)" if not jev_on else "Jev not run")
            checks.append(_row("P7", "Overall injection risk", "jev", R.NOT_CHECKED, why))
        hidden = [f"{iid}: {'; '.join(s['hidden'])}" for iid, s in scans.items() if s["hidden"]]
        checks.append(_row("P8", "Hidden or obfuscated text", "regex", R.FLAG if hidden else R.PASS,
                           " | ".join(hidden) or "no invisible characters, comments, encoded or look-alike text"))
    users = [i for i in items if i.trust == Trust.TRUSTED and i.id in scans]
    if user_scanned and users:
        sus = [i for i in users if i.taint == Taint.SUSPICIOUS]
        checks.append(_row("P9", "User's own prompt", "regex+jev" if jev_input else "regex",
                           R.FLAG if sus else R.PASS,
                           (f"{', '.join(i.id for i in sus)} looks like prompt injection (see P2–P8)" if sus
                            else "user prompt scanned — no injection found")))
    else:
        checks.append(_row("P9", "User's own prompt", "-", R.NA,
                           "the user's request is trusted by design and not scanned for injection"))
    return checks


def input_guard_node(state: AgentState) -> AgentState:
    raw = state.get("context_items", [])
    scan_user = bool(state.get("scan_user_prompt"))
    scans = {i.id: _scan_text(i) for i in raw
             if i.trust != Trust.TRUSTED or (scan_user and i.source_type == "user_message")}
    items = [scan_item(i, scans.get(i.id)) for i in raw]
    audit = list(state.get("audit", []))

    jev_input: dict = {}
    untrusted = [i for i in items if i.id in scans]  # everything we scan, incl. a scanned user prompt
    if jev.enabled() and untrusted:
        rules = active()

        def score(i: ContextItem) -> dict:
            # Let Jev see what the hidden parts say, not only the visible text.
            revealed = scans[i.id]["revealed"]
            text = i.content + (f"\n\n[hidden text revealed by the input guard]\n{revealed}" if revealed else "")
            return jev.scan_untrusted(text, i.source_type, rules.jev_suspicious_level, rules.jev_signal_threshold)

        with ThreadPoolExecutor(max_workers=min(4, len(untrusted))) as pool:
            results = list(pool.map(score, untrusted))
        jev_input = {i.id: r for i, r in zip(untrusted, results)}
        items = [_apply_jev(i, jev_input[i.id]) if i.id in jev_input else i for i in items]
        # A weak word ("secret", "password") counts once Jev also sees an attack signal ≥ 0.5.
        for n, i in enumerate(items):
            s, r = scans.get(i.id), jev_input.get(i.id) or {}
            if s and s["weak"] and r.get("status") == "ok":
                keys = _CORROBORATING.get(i.source_type, _CORROBORATING[None])
                hits = [k for k in keys if r["signals"].get(k, 0) >= 0.5]
                if hits:
                    s["sensitive"], s["weak"] = [*s["sensitive"], *s["weak"]], []
                    items[n] = i.model_copy(update={"taint": Taint.SUSPICIOUS, "risk": max(i.risk, 0.7)})
        for item_id, r in jev_input.items():
            if r["status"] == "ok":
                audit.append(f"[jev] {item_id}: prompt-injection risk {r['level']}/100 "
                             f"(confidence {r['confidence']:.2f}, {r['ms']} ms) signals={r['signals']}"
                             + (f" -> SUSPICIOUS ({'; '.join(r['reasons'])})" if r["suspicious"] else ""))
            else:
                audit.append(f"[jev] {item_id}: unavailable ({r['error']}) — regex guard only")

    flagged = [i for i in items if i.instruction_detected or i.taint == Taint.SUSPICIOUS]
    for i in flagged:
        audit.append(
            f"[input_guard] {i.id} ({i.source}): trust={i.trust.value} "
            f"taint={i.taint.value} risk={i.risk:.2f} "
            f"instruction_detected={i.instruction_detected}"
        )
    if not flagged:
        audit.append("[input_guard] no suspicious context detected")

    checks = _input_checks(items, scans, jev_input, jev.enabled(), user_scanned=scan_user)
    for c in checks:
        audit.append(f"[check] {c.id} {c.criterion}: {c.result.value} ({c.checked_by}) — {c.evidence}")
    findings = {iid: {k: s[k] for k in ("injection", "sensitive", "weak", "secrecy", "hidden")} for iid, s in scans.items()}
    return {"context_items": items, "audit": audit, "jev_input": jev_input, "input_checks": checks,
            "input_findings": findings}
