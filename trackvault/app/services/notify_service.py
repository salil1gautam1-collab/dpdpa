"""Notifications + email (SMTP-gated, test-recipient guarded)."""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Notification

_s = get_settings()


def smtp_configured() -> bool:
    return bool(_s.smtp_host and _s.smtp_pass)


def _send_email(to: str, subject: str, body: str) -> tuple[str, str]:
    if not to:
        return "no-recipient", ""
    actual = to
    if _s.test_recipient.strip():
        body = (f"*** TEST MODE — redirected. Intended recipient: {to} ***\n\n") + body
        subject = f"[TEST->{to}] {subject}"
        actual = _s.test_recipient.strip()
    if not smtp_configured():
        return "simulated", actual
    try:
        msg = EmailMessage()
        msg["From"] = _s.smtp_from or _s.smtp_user
        msg["To"] = actual
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(_s.smtp_host, _s.smtp_port, timeout=20) as srv:
            srv.starttls(context=ssl.create_default_context())
            if _s.smtp_user:
                srv.login(_s.smtp_user, _s.smtp_pass)
            srv.send_message(msg)
        return "sent", actual
    except Exception as ex:  # pragma: no cover
        return f"error: {type(ex).__name__}", actual


def notify(db: Session, company_id: str, ntype: str, title: str, body: str,
           email_to: str = "") -> Notification:
    status, actual = _send_email(email_to, f"[{ntype}] {title}", body) if email_to else ("not-sent", "")
    n = Notification(company_id=company_id, ntype=ntype, title=title, body=body,
                     email_to=email_to, email_status=status, email_delivered_to=actual)
    db.add(n)
    db.commit()
    db.refresh(n)
    return n


def unread_count(db: Session, company_id: str) -> int:
    return len(list(db.execute(select(Notification).where(
        Notification.company_id == company_id, Notification.read.is_(False))).scalars()))
