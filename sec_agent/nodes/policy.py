"""Deterministic Policy Engine.

The security LLM is advisory. This engine is the hard boundary: pure code, no
model, fully testable. The final decision is the MOST RESTRICTIVE of the policy
engine and the security LLM, so an incorrect ALLOW from the model can never
loosen a deterministic rule.

Every action criterion produces one checklist row (T1–T9, see models.Check), so
the audit trail records what was checked and why — not only the outcome. The
decision is derived from those rows.
"""

from __future__ import annotations

import inspect
import re
from urllib.parse import urlparse

from ..rules import Rules, active
from ..models import (
    AgentState,
    Check,
    CheckResult,
    ContextItem,
    Decision,
    ProposedAction,
    Taint,
    Trust,
    most_restrictive,
)

R = CheckResult

# Credentials that must never leave in an outbound payload (T7).
_SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS secret": re.compile(r"aws_secret_access_key\s*[=:]", re.IGNORECASE),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "password assignment": re.compile(r"\bpass(word|wd)?\s*[=:]\s*\S{4,}", re.IGNORECASE),
}
# Arguments that carry data out of the system, per tool.
_OUTBOUND_FIELDS = {"send_email": ("body",), "http_request": ("body", "url"), "write_file": ("content",)}


def _check(id: str, criterion: str, result: CheckResult, evidence: str = "",
           effect: Decision | None = None, by: str = "policy") -> Check:
    return Check(id=id, stage="action", criterion=criterion, checked_by=by,
                 result=result, evidence=evidence, effect=effect)


def _touches_denied_path(action: ProposedAction, rules: Rules) -> list[str]:
    blob = " ".join(str(v) for v in action.arguments.values()).lower()
    return [needle for needle in rules.denied_path_substrings if needle in blob]



def _host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").lower()


def _host_allowed(host: str, allowed: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in allowed)


def influence(action: ProposedAction, items: list[ContextItem]) -> tuple[bool, str]:
    """Was this action influenced by untrusted content?

    The executor's ``source_ids`` are self-reported, so a compromised agent could simply
    not cite the poisoned document. We therefore treat the action as influenced whenever
    ANY untrusted content was in its context — citing it only adds detail.
    """
    untrusted = [i for i in items if i.trust != Trust.TRUSTED or i.taint in (Taint.EXTERNAL, Taint.SUSPICIOUS)]
    if not untrusted:
        return False, "only trusted context — no untrusted influence possible"
    cited = {s for s in action.source_ids}
    parts = []
    for i in untrusted:
        tag = f"{i.id} ({i.trust.value}, {i.taint.value})"
        parts.append(f"cites {tag}" if i.id in cited else f"did not cite {tag}, but it was in context")
    return True, "; ".join(parts) + " -> treated as influenced"


def _expected_args(tool: str) -> tuple[set[str], set[str]] | None:
    from ..tools import INJECTED_ARGS, REGISTRY

    fn = REGISTRY.get(tool)
    if fn is None:
        return None
    params = inspect.signature(fn).parameters.values()
    named = {p.name for p in params if p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL)}
    required = {p.name for p in params if p.default is p.empty and p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL)}
    if tool == "read_document":
        named.add("document_id")
    injected = INJECTED_ARGS.get(tool, set())  # filled in by the proxy, never by the agent
    return named - injected, required - injected


def evaluate_checks(action: ProposedAction, items: list[ContextItem], rules: Rules | None = None) -> list[Check]:
    """Run every deterministic action criterion (T1–T3, T5–T9). Pure function."""
    rules = rules or active()
    tool, args = action.tool, action.arguments
    out: list[Check] = []

    # T1 — least privilege: unknown tools are refused outright.
    if tool in rules.allowed_tools:
        out.append(_check("T1", "Tool allowed", R.PASS, f"'{tool}' is on the allow-list"))
    else:
        out.append(_check("T1", "Tool allowed", R.FAIL, f"tool '{tool}' is not in the allow-list", Decision.DENY))

    # T2 — forbidden resources, whatever the LLM says. Output-only tools reach no resource.
    if tool in rules.output_only_tools:
        out.append(_check("T2", "No forbidden resources", R.NA, f"'{tool}' is output-only and touches no resource"))
    else:
        denied = _touches_denied_path(action, rules)
        out.append(_check("T2", "No forbidden resources", R.FAIL if denied else R.PASS,
                          f"argument references denied resource(s): {', '.join(denied)}" if denied
                          else "no argument references a forbidden resource",
                          Decision.DENY if denied else None))

    # T3 — destination allowed: email domain, HTTP host.
    if tool == "send_email":
        recipient = str(args.get("recipient", "")).strip().lower()
        domain = recipient.rsplit("@", 1)[-1] if "@" in recipient else ""
        if domain in rules.allowed_email_domains:
            out.append(_check("T3", "Destination allowed", R.PASS, f"'{domain}' is an allowed email domain"))
        else:
            out.append(_check("T3", "Destination allowed", R.FAIL,
                              f"recipient domain '{domain or recipient}' is outside the allowed "
                              f"email domains -> external data egress", Decision.DENY))
    elif tool == "http_request":
        host = _host(str(args.get("url", "")))
        if host and _host_allowed(host, rules.allowed_http_hosts):
            out.append(_check("T3", "Destination allowed", R.PASS, f"'{host}' is an allowed HTTP host"))
        else:
            out.append(_check("T3", "Destination allowed", R.FAIL,
                              f"host '{host or args.get('url', '')}' is not in the allowed HTTP hosts "
                              f"-> external data egress", Decision.DENY))
    else:
        out.append(_check("T3", "Destination allowed", R.NA, f"'{tool}' sends nothing to a destination"))

    # T5 — provenance: influenced by untrusted content? (never trust self-reported sources)
    influenced, why = influence(action, items)
    out.append(_check("T5", "Untrusted influence", R.FLAG if influenced else R.PASS, why))

    # T6 — impact & reversibility -> human approval.
    reasons, effect = [], None
    if tool in rules.approval_required_tools:
        reasons.append(f"'{tool}' is a high-impact action -> always requires human approval")
    if tool in rules.consequential_tools and influenced:
        reasons.append(f"consequential tool '{tool}' was influenced by untrusted/tainted context "
                       f"-> requires human approval")
    if reasons:
        effect = Decision.APPROVAL
        out.append(_check("T6", "Impact & reversibility", R.FLAG, "; ".join(reasons), effect))
    elif tool in rules.consequential_tools:
        out.append(_check("T6", "Impact & reversibility", R.PASS, f"consequential, but not influenced by untrusted content"))
    else:
        out.append(_check("T6", "Impact & reversibility", R.PASS, f"'{tool}' has no external side effects"))

    # T7 — what's being sent: credentials inside an outbound payload.
    fields = _OUTBOUND_FIELDS.get(tool)
    if not fields:
        out.append(_check("T7", "No secrets in outbound data", R.NA, f"'{tool}' sends no payload out"))
    else:
        hits = sorted({name for f in fields for name, rx in _SECRET_PATTERNS.items() if rx.search(str(args.get(f, "")))})
        out.append(_check("T7", "No secrets in outbound data", R.FAIL if hits else R.PASS,
                          f"outbound {'/'.join(fields)} contains: {', '.join(hits)}" if hits
                          else f"no credentials found in {'/'.join(fields)}",
                          Decision.DENY if hits else None))

    # T8 — argument sanity: expected fields only.
    spec = _expected_args(tool)
    if spec is None:
        out.append(_check("T8", "Arguments sane", R.NA, "unknown tool"))
    else:
        named, required = spec
        unexpected, missing = sorted(set(args) - named), sorted(required - set(args))
        problems = ([f"unexpected: {', '.join(unexpected)}"] if unexpected else []) + \
                   ([f"missing: {', '.join(missing)}"] if missing else [])
        out.append(_check("T8", "Arguments sane", R.FLAG if problems else R.PASS,
                          "; ".join(problems) or "arguments match the tool's signature"))

    # T9 — rate & volume. Honest about what isn't enforced yet.
    out.append(_check("T9", "Rate & volume", R.NOT_CHECKED, "no per-session rate limit is enforced yet"))
    return out


def decide(checks: list[Check]) -> tuple[Decision, list[str]]:
    """Decision = most restrictive effect; reasons = evidence of every row that had an effect."""
    decision, reasons = Decision.ALLOW, []
    for c in checks:
        if c.effect is not None:
            decision = most_restrictive(decision, c.effect)
            reasons.append(c.evidence)
    return decision, reasons or ["no deterministic rule triggered"]


def evaluate(
    action: ProposedAction, items: list[ContextItem], rules: Rules | None = None
) -> tuple[Decision, list[str]]:
    """Return (decision, reasons). Used by the controller and, independently, by the proxy."""
    return decide(evaluate_checks(action, items, rules))


def _llm_check(sec) -> Check:
    if sec is None:
        return Check(id="T4", stage="action", criterion="Goal alignment", checked_by="security_llm",
                     result=R.NOT_CHECKED, evidence="no security LLM verdict")
    result = {Decision.ALLOW: R.PASS, Decision.APPROVAL: R.FLAG, Decision.DENY: R.FAIL}[sec.decision]
    if result == R.PASS and sec.goal_relevance < 0.5:
        result = R.FLAG
    return Check(id="T4", stage="action", criterion="Goal alignment", checked_by="security_llm", result=result,
                 evidence=f"goal relevance {sec.goal_relevance:.0%}, {sec.classification}, risk {sec.risk_score}/100 — "
                          f"{sec.reason[:200]}",
                 effect=sec.decision if sec.decision != Decision.ALLOW else None)


def policy_node(state: AgentState) -> AgentState:
    action = state["proposed_action"]
    items = state.get("context_items", [])
    sec = state.get("security_decision")

    action_checks = evaluate_checks(action, items)
    policy_decision, reasons = decide(action_checks)

    # Final = most restrictive of deterministic policy and the advisory LLM.
    final = policy_decision
    if sec is not None:
        final = most_restrictive(policy_decision, sec.decision)

    combined = Check(id="T10", stage="action", criterion="Combined verdict", checked_by="combined",
                     result={Decision.ALLOW: R.PASS, Decision.APPROVAL: R.FLAG, Decision.DENY: R.FAIL}[final],
                     evidence=f"policy={policy_decision.value}, security LLM={sec.decision.value if sec else 'n/a'} "
                              f"-> stricter wins: {final.value}", effect=final)
    action_checks = sorted([*action_checks, _llm_check(sec), combined], key=lambda c: int(c.id[1:]))

    audit = list(state.get("audit", []))
    for r in reasons:
        audit.append(f"[policy] {r}")
    for c in action_checks:
        audit.append(f"[check] {c.id} {c.criterion}: {c.result.value} ({c.checked_by}) — {c.evidence}")
    audit.append(
        f"[policy] deterministic={policy_decision.value} "
        f"security_llm={(sec.decision.value if sec else 'n/a')} "
        f"-> FINAL={final.value}"
    )
    return {
        "policy_decision": policy_decision,
        "policy_reasons": reasons,
        "final_decision": final,
        "checks": [*state.get("input_checks", []), *action_checks],
        "audit": audit,
    }
