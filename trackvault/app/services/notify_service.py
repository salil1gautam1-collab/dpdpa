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


def _env_cfg() -> dict:
    return {"enabled": True, "from_addr": _s.smtp_from, "test_recipient": _s.test_recipient.strip(),
            "host": _s.smtp_host, "port": _s.smtp_port, "user": _s.smtp_user, "password": _s.smtp_pass}


def smtp_configured(cfg: dict | None = None) -> bool:
    cfg = cfg or _env_cfg()
    return bool(cfg.get("host") and cfg.get("password"))


def _send_email(to: str, subject: str, body: str, attachment: tuple | None = None,
                cfg: dict | None = None) -> tuple[str, str]:
    """attachment = (filename, bytes, mime_subtype). cfg from settings_service or env."""
    cfg = cfg or _env_cfg()
    if not cfg.get("enabled", True):
        return "disabled", ""
    if not to:
        return "no-recipient", ""
    actual = to
    guard = (cfg.get("test_recipient") or "").strip()
    if guard:
        body = (f"*** TEST MODE — redirected. Intended recipient: {to} ***\n\n") + body
        subject = f"[TEST->{to}] {subject}"
        actual = guard
    if not smtp_configured(cfg):
        return "simulated", actual
    try:
        msg = EmailMessage()
        msg["From"] = cfg.get("from_addr") or cfg.get("user")
        msg["To"] = actual
        msg["Subject"] = subject
        msg.set_content(body)
        if attachment:
            fname, data, subtype = attachment
            msg.add_attachment(data, maintype="text", subtype=subtype, filename=fname)
        with smtplib.SMTP(cfg["host"], int(cfg["port"]), timeout=30) as srv:
            srv.starttls(context=ssl.create_default_context())
            if cfg.get("user"):
                srv.login(cfg["user"], cfg["password"])
            srv.send_message(msg)
        return "sent", actual
    except Exception as ex:  # pragma: no cover
        return f"error: {type(ex).__name__}", actual


def send_report_email(db: Session, company, snapshot, to_email: str, note: str = "") -> Notification:
    """Email the branded report as an attachment, and log it as a notification."""
    from ..reporting import client_report
    from ..services.rulebook_service import get_rulebook
    from ..domain.engine import summarize
    rb = get_rulebook(db, snapshot.rulebook_version)
    html = client_report(snapshot.data, rb, list(company.sites or []))
    s = summarize(snapshot.data)
    d = snapshot.scan_id
    date_fmt = f"{d[:4]}-{d[4:6]}-{d[6:8]}"
    body = (f"Please find attached the DPDPA compliance report for {company.name}, dated {date_fmt}.\n\n"
            f"Overall compliance score: {s['complianceScore']}%  "
            f"(gaps {s['counts']['GAP']}, partial {s['counts']['PARTIAL']}).\n")
    if note:
        body += f"\n{note}\n"
    body += f"\nOpen the attached file in a browser and use Print → Save as PDF for a PDF copy.\n"
    fname = f"DPDPA-Report-{company.slug}-{date_fmt}.html"
    from .settings_service import effective_email_config
    status, actual = _send_email(to_email, f"DPDPA Compliance Report — {company.name} ({date_fmt})",
                                 body, attachment=(fname, html.encode("utf-8"), "html"),
                                 cfg=effective_email_config(db))
    n = Notification(company_id=company.id, ntype="REPORT SENT",
                     title=f"Report emailed to {to_email} ({date_fmt})", body=body,
                     email_to=to_email, email_status=status, email_delivered_to=actual)
    db.add(n)
    db.commit()
    db.refresh(n)
    return n


def notify(db: Session, company_id: str, ntype: str, title: str, body: str,
           email_to: str = "") -> Notification:
    from .settings_service import effective_email_config
    cfg = effective_email_config(db)
    status, actual = _send_email(email_to, f"[{ntype}] {title}", body, cfg=cfg) if email_to else ("not-sent", "")
    n = Notification(company_id=company_id, ntype=ntype, title=title, body=body,
                     email_to=email_to, email_status=status, email_delivered_to=actual)
    db.add(n)
    db.commit()
    db.refresh(n)
    return n


def unread_count(db: Session, company_id: str) -> int:
    return len(list(db.execute(select(Notification).where(
        Notification.company_id == company_id, Notification.read.is_(False))).scalars()))
