"""The controlled tool set. Only the execution proxy may call into this module.

These are deliberately small, local, side-effect-light reference implementations.
Swap send_email for SES and http_request for a real client when you wire up AWS.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable


def read_document(path: str) -> str:
    return Path(path).expanduser().read_text(encoding="utf-8", errors="replace")


def read_file(path: str) -> str:
    return Path(path).expanduser().read_text(encoding="utf-8", errors="replace")


def write_file(path: str, content: str = "") -> str:
    p = Path(path).expanduser()
    p.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} bytes to {p}"


def send_email(recipient: str, body: str = "", **_: Any) -> str:
    # Stub: in production, back this with Amazon SES (boto3 'sesv2').
    return f"[stub] email to {recipient} ({len(body)} bytes) — not actually sent"


def http_request(method: str = "GET", url: str = "", body: str = "", **_: Any) -> str:
    # Stub: avoid making real network calls from the reference PoC.
    return f"[stub] {method} {url} ({len(body)} bytes) — not actually sent"


REGISTRY: dict[str, Callable[..., str]] = {
    "read_document": read_document,
    "read_file": read_file,
    "write_file": write_file,
    "send_email": send_email,
    "http_request": http_request,
}
