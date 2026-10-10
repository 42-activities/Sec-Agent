"""Editable parameters of the deterministic policy engine.

The rule *logic* lives in code (nodes/policy.py) and cannot be changed at runtime;
these are the lists and tables it checks against (allowed tools, denied paths,
known payees, ...). They are stored as JSON so an admin can edit them from the
web UI without a redeploy.

Ownership: in the two-container deployment the PROXY owns the rules file. The
controller only reads it (GET /rules on the proxy) and forwards edits that carry
the admin token, which the controller itself never holds. A compromised controller
therefore cannot loosen the rules the proxy enforces.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from pydantic import BaseModel, Field, field_validator

from .config import settings

_MAX_ITEMS = 200
_MAX_LEN = 200


class Rules(BaseModel):
    allowed_tools: list[str]
    denied_path_substrings: list[str]
    output_only_tools: list[str]
    known_payees: dict[str, str]
    allowed_email_domains: list[str]
    # Default lets rule files saved before this field existed still load.
    allowed_http_hosts: list[str] = Field(default_factory=lambda: list(settings.allowed_http_hosts))
    approval_required_tools: list[str]
    consequential_tools: list[str]
    # Jev risk level (0/20/.../100) at which untrusted content is marked suspicious.
    # Has a default so rule files saved before this field existed still load.
    jev_suspicious_level: int = Field(default=60, ge=0, le=100, multiple_of=20)
    # A single decisive Jev signal (AI instructions / redirect / secrets) at or above this.
    jev_signal_threshold: float = Field(default=0.9, ge=0.5, le=1.0)
    updated_at: Optional[str] = Field(default=None, description="Set on every save.")

    @field_validator("allowed_tools", "denied_path_substrings", "output_only_tools",
                     "allowed_email_domains", "allowed_http_hosts", "approval_required_tools",
                     "consequential_tools")
    @classmethod
    def _clean_list(cls, v: list[str]) -> list[str]:
        out = list(dict.fromkeys(s.strip() for s in v if s and s.strip()))
        if len(out) > _MAX_ITEMS or any(len(s) > _MAX_LEN for s in out):
            raise ValueError(f"at most {_MAX_ITEMS} entries of at most {_MAX_LEN} characters")
        return out

    @field_validator("allowed_email_domains", "allowed_http_hosts")
    @classmethod
    def _lower_domains(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(d.lower().lstrip("@") for d in v))

    @field_validator("known_payees")
    @classmethod
    def _clean_payees(cls, v: dict[str, str]) -> dict[str, str]:
        out = {k.strip(): "".join(str(iban).split()).upper() for k, iban in v.items() if k and k.strip()}
        if any(not iban for iban in out.values()):
            raise ValueError("every payee needs an IBAN")
        if len(out) > _MAX_ITEMS or any(len(k) > _MAX_LEN or len(i) > 34 for k, i in out.items()):
            raise ValueError("too many payees, or a name/IBAN is too long")
        return out


def defaults() -> Rules:
    """Factory defaults, from config.py (overridable by environment)."""
    return Rules(
        allowed_tools=settings.allowed_tools,
        denied_path_substrings=settings.denied_path_substrings,
        output_only_tools=settings.output_only_tools,
        known_payees=settings.known_payees,
        allowed_email_domains=settings.allowed_email_domains,
        allowed_http_hosts=settings.allowed_http_hosts,
        approval_required_tools=settings.approval_required_tools,
        consequential_tools=settings.consequential_tools,
        jev_suspicious_level=settings.jev_suspicious_level,
        jev_signal_threshold=settings.jev_signal_threshold,
    )


def load_local() -> Rules:
    path = Path(settings.rules_file)
    if not path.is_file():
        return defaults()
    return Rules.model_validate_json(path.read_text(encoding="utf-8"))


def save_local(rules: Rules) -> Rules:
    rules = rules.model_copy(update={"updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    path = Path(settings.rules_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replace: a reader never sees a half-written file.
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".rules-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(rules.model_dump_json(indent=2))
    os.replace(tmp, path)
    return rules


def reset_local() -> Rules:
    Path(settings.rules_file).unlink(missing_ok=True)
    return defaults()


def _proxy_headers(admin_token: str = "") -> dict[str, str]:
    h = {"Authorization": f"Bearer {settings.proxy_auth_token}"}
    if admin_token:
        h["X-Admin-Token"] = admin_token
    return h


def fetch_remote() -> tuple[Rules, bool]:
    """Rules as the proxy enforces them, plus whether the proxy allows editing."""
    r = requests.get(f"{settings.proxy_url}/rules", headers=_proxy_headers(), timeout=5)
    r.raise_for_status()
    data = r.json()
    return Rules.model_validate(data["rules"]), bool(data.get("editable"))


def active() -> Rules:
    """The rules the policy engine must use in this process."""
    return fetch_remote()[0] if settings.proxy_url else load_local()


def admin_ok(token: str) -> bool:
    """Editing is disabled (fail closed) unless RULES_ADMIN_TOKEN is configured."""
    import hmac

    expected = settings.rules_admin_token
    return bool(expected) and hmac.compare_digest(token or "", expected)
