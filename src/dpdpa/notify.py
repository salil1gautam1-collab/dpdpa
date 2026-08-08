"""Notifications + email delivery.

Each client has notifications.json (portal notifications, with per-item email
delivery status). A global _outbox.json under local/ records every email for the
operator's delivery log.

Email is sent via SMTP only when configured through environment variables:
  TRACKVAULT_SMTP_HOST, TRACKVAULT_SMTP_PORT, TRACKVAULT_SMTP_USER,
  TRACKVAULT_SMTP_PASS, TRACKVAULT_SMTP_FROM, TRACKVAULT_BASE_URL
If SMTP is not configured, emails are recorded with status "simulated" (nothing
leaves the machine) — honest for demos and safe by default.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage

from .evidence import utc_now
from .workspace import LOCAL_ROOT, client_dir, load_json, save_json

_OUTBOX = LOCAL_ROOT / "_outbox.json"


def _next_id(items: list) -> int:
    return (max((n.get("id", 0) for n in items), default=0)) + 1


def smtp_configured() -> bool:
    # Require host AND password so pre-filled host/user stay in simulated mode
    # until the operator adds the secret.
    return bool(os.environ.get("TRACKVAULT_SMTP_HOST") and os.environ.get("TRACKVAULT_SMTP_PASS"))


def test_recipient() -> str:
    """If set, ALL email is redirected here (a safety guard for testing)."""
    return os.environ.get("TRACKVAULT_TEST_RECIPIENT", "").strip()


def _send_email(to: str, subject: str, body: str) -> tuple[str, str]:
    """Return (status, actual_recipient). status: 'sent'|'simulated'|'error: ...'."""
    if not to:
        return "no-recipient", ""
    actual_to = to
    guard = test_recipient()
    if guard:
        body = (f"*** TEST MODE — this email was redirected to the test address. ***\n"
                f"*** Intended recipient: {to} ***\n\n") + body
        subject = f"[TEST→{to}] {subject}"
        actual_to = guard
    if not smtp_configured():
        return "simulated", actual_to
    try:
        msg = EmailMessage()
        msg["From"] = os.environ.get("TRACKVAULT_SMTP_FROM", os.environ["TRACKVAULT_SMTP_USER"])
        msg["To"] = actual_to
        msg["Subject"] = subject
        msg.set_content(body)
        host = os.environ["TRACKVAULT_SMTP_HOST"]
        port = int(os.environ.get("TRACKVAULT_SMTP_PORT", "587"))
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls(context=ssl.create_default_context())
            if os.environ.get("TRACKVAULT_SMTP_USER"):
                s.login(os.environ["TRACKVAULT_SMTP_USER"], os.environ.get("TRACKVAULT_SMTP_PASS", ""))
            s.send_message(msg)
        return "sent", actual_to
    except Exception as ex:
        return f"error: {type(ex).__name__}: {ex}", actual_to


def notify(slug: str, ntype: str, title: str, body: str, email_to: str = "",
           email: bool = True) -> dict:
    """Create a portal notification and (optionally) an email. Returns the item."""
    path = client_dir(slug) / "notifications.json"
    data = load_json(path, {"items": []})
    if email and email_to:
        status, actual_to = _send_email(email_to, f"[{ntype}] {title}", body)
    else:
        status, actual_to = "not-sent", ""
    redirected = actual_to and actual_to != email_to
    item = {"id": _next_id(data["items"]), "type": ntype, "title": title, "body": body,
            "createdAt": utc_now(), "read": False,
            "email": {"to": email_to, "status": status,
                      **({"redirectedTo": actual_to} if redirected else {})}}
    data["items"].insert(0, item)
    save_json(path, data)

    if email and email_to:
        ob = load_json(_OUTBOX, {"items": []})
        ob["items"].insert(0, {"id": _next_id(ob["items"]), "slug": slug, "to": email_to,
                               "deliveredTo": actual_to, "subject": f"[{ntype}] {title}",
                               "status": status, "sentAt": utc_now()})
        save_json(_OUTBOX, ob)
    return item


def list_notifications(slug: str) -> list:
    return load_json(client_dir(slug) / "notifications.json", {"items": []})["items"]


def unread_count(slug: str) -> int:
    return sum(1 for n in list_notifications(slug) if not n.get("read"))


def mark_all_read(slug: str) -> None:
    path = client_dir(slug) / "notifications.json"
    data = load_json(path, {"items": []})
    for n in data["items"]:
        n["read"] = True
    save_json(path, data)


def outbox() -> list:
    return load_json(_OUTBOX, {"items": []})["items"]


def base_url() -> str:
    return os.environ.get("TRACKVAULT_BASE_URL", "http://127.0.0.1:8377")
