"""Gmail, read-only, for whoever is using the page.

Each visitor signs in with Google (OAuth, scope ``gmail.readonly``) and connects THEIR
OWN mailbox. We ask for an access token only (no refresh token, ~1 h), keep it in the
controller's memory keyed by a random cookie, and hand it to the execution proxy only
for a ``read_email`` call. The agent never sees the token: the proxy injects it.

Everything read from a mailbox is untrusted — an email is the classic indirect
prompt-injection vector — so it goes through the input guard like any document.
"""

from __future__ import annotations

import base64
import html
import json
import re
from urllib.parse import urlencode

import requests

from .config import settings

SCOPES = "openid email https://www.googleapis.com/auth/gmail.readonly"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
API = "https://gmail.googleapis.com/gmail/v1/users/me"
TIMEOUT = 15


class GmailError(RuntimeError):
    pass


def enabled() -> bool:
    return bool(settings.google_client_id and settings.google_client_secret)


def redirect_uri(base: str) -> str:
    return (settings.public_url or base).rstrip("/") + "/auth/google/callback"


def auth_url(redirect: str, state: str, login_hint: str = "") -> str:
    q = {"client_id": settings.google_client_id, "redirect_uri": redirect, "response_type": "code",
         "scope": SCOPES, "state": state, "access_type": "online", "include_granted_scopes": "true",
         "prompt": "select_account"}
    if login_hint:
        q["login_hint"] = login_hint
    return f"{AUTH_URL}?{urlencode(q)}"


def _email_from_id_token(id_token: str) -> str:
    # Received straight from Google's token endpoint over TLS, so no signature check is needed
    # just to display the address (it is never used for authorization).
    try:
        part = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).get("email", "")
    except Exception:
        return ""


def exchange(code: str, redirect: str) -> dict:
    """Authorization code -> {access_token, expires_in, email, scope}."""
    r = requests.post(TOKEN_URL, timeout=TIMEOUT, data={
        "code": code, "client_id": settings.google_client_id, "client_secret": settings.google_client_secret,
        "redirect_uri": redirect, "grant_type": "authorization_code"})
    if r.status_code != 200:
        raise GmailError(f"token exchange failed: {r.text[:200]}")
    tok = r.json()
    if "gmail.readonly" not in tok.get("scope", ""):
        raise GmailError("Gmail read access was not granted (tick the Gmail box on Google's consent screen)")
    return {"access_token": tok["access_token"], "expires_in": int(tok.get("expires_in", 3600)),
            "email": _email_from_id_token(tok.get("id_token", "")), "scope": tok.get("scope", "")}


def revoke(token: str) -> None:
    try:
        requests.post(REVOKE_URL, params={"token": token}, timeout=TIMEOUT)
    except requests.RequestException:
        pass  # best effort; the token expires within the hour anyway


# ------------------------------------ reading ------------------------------------

def _b64(data: str) -> str:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="replace")


def _html_to_text(s: str) -> str:
    # Drop scripts/styles, keep HTML comments (a favourite hiding place — the input guard
    # flags them), turn the other tags into whitespace. Text hidden with CSS stays visible here.
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", s)
    s = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>", "\n", s)
    s = re.sub(r"<(?!!--)[^>]+>", " ", s)
    s = html.unescape(s)
    return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", s)).strip()


def _body(payload: dict) -> str:
    """Prefer text/plain; fall back to text/html converted to text."""
    plain, rich = [], []

    def walk(part: dict) -> None:
        mime, data = part.get("mimeType", ""), (part.get("body") or {}).get("data")
        if data and mime == "text/plain":
            plain.append(_b64(data))
        elif data and mime == "text/html":
            rich.append(_html_to_text(_b64(data)))
        for p in part.get("parts") or []:
            walk(p)

    walk(payload)
    return "\n".join(plain).strip() or "\n".join(rich).strip()


def parse_message(msg: dict) -> dict:
    headers = {h["name"].lower(): h["value"] for h in (msg.get("payload") or {}).get("headers", [])}
    body = _body(msg.get("payload") or {}) or html.unescape(msg.get("snippet", ""))
    limit = settings.gmail_body_chars
    return {"id": msg.get("id", ""), "from": headers.get("from", ""), "to": headers.get("to", ""),
            "subject": headers.get("subject", "(no subject)"), "date": headers.get("date", ""),
            "body": body[:limit] + (" …[truncated]" if len(body) > limit else "")}


def _get(token: str, path: str, **params) -> dict:
    try:
        r = requests.get(f"{API}{path}", params=params, timeout=TIMEOUT,
                         headers={"Authorization": f"Bearer {token}"})
    except requests.RequestException as exc:
        raise GmailError(f"Gmail unreachable: {exc}") from exc
    if r.status_code == 401:
        raise GmailError("Gmail session expired — connect Gmail again")
    if r.status_code != 200:
        raise GmailError(f"Gmail API error {r.status_code}: {r.text[:200]}")
    return r.json()


def list_messages(token: str, query: str = "", max_results: int = 5, limit: int | None = None) -> list[dict]:
    """The newest messages matching a Gmail search query (e.g. "from:acme newer_than:7d")."""
    n = max(1, min(int(max_results or 5), limit or settings.gmail_max_results))
    ids = _get(token, "/messages", q=query or "", maxResults=n).get("messages", [])
    return [parse_message(_get(token, f"/messages/{m['id']}", format="full")) for m in ids]


def as_text(email: dict) -> str:
    """One email as the plain text the input guard and the executor see."""
    return f"From: {email['from']}\nTo: {email['to']}\nDate: {email['date']}\nSubject: {email['subject']}\n\n{email['body']}"
