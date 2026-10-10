"""The controlled tool set. Only the execution proxy may call into this module.

These are deliberately small, local, side-effect-light reference implementations.
Swap send_email for SES and http_request for a real client when you wire up AWS.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional


def read_document(path: str) -> str:
    return Path(path).expanduser().read_text(encoding="utf-8", errors="replace")


def respond_to_user(answer: str = "", **_: Any) -> str:
    # Output to the (trusted) user who asked — no resource access, no egress.
    return answer


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
    "respond_to_user": respond_to_user,
    "read_document": read_document,
    "read_file": read_file,
    "write_file": write_file,
    "send_email": send_email,
    "http_request": http_request,
}


def invoke(tool: str, arguments: dict[str, Any], documents: Optional[dict[str, str]] = None) -> str:
    """Run a registered tool. Called only by the execution proxies.

    ``documents`` maps context-item IDs (e.g. "document-1") to the content the user
    pasted, so ``read_document`` can resolve an uploaded document by its ID instead
    of treating the ID as a path on disk.
    """
    if tool == "read_document" and documents:
        ref = str(arguments.get("path") or arguments.get("document_id") or "")
        if ref in documents:
            return documents[ref]
    fn = REGISTRY.get(tool)
    if fn is None:
        raise KeyError(f"unknown tool '{tool}'")
    return fn(**arguments)

