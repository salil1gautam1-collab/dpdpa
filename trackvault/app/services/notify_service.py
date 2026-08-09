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
                cfg: dict | None = None, attachments: list | None = None) -> tuple[str, str]:
    """attachment = (filename, bytes, mime_subtype); attachments = a list of the
    same tuples for multi-document sends. cfg from settings_service or env."""
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
        for fname, data, subtype in ([attachment] if attachment else []) + (attachments or []):
            msg.add_attachment(data, maintype="text", subtype=subtype, filename=fname)
        with smtplib.SMTP(cfg["host"], int(cfg["port"]), timeout=30) as srv:
            srv.starttls(context=ssl.create_default_context())
            if cfg.get("user"):
                srv.login(cfg["user"], cfg["password"])
            srv.send_message(msg)
        return "sent", actual
    except Exception as ex:  # pragma: no cover
        return f"error: {type(ex).__name__}", actual


def send_report_email(db: Session, company, snapshot, to_email: str, note: str = "",
                      docs: tuple = ("report",)) -> Notification:
    """Email the chosen document(s) — executive report and/or gap assessment —
    as attachments, and log it as a notification."""
    from ..reporting import client_report, gap_assessment
    from ..services.rulebook_service import get_rulebook
    from ..domain.engine import summarize
    rb = get_rulebook(db, snapshot.rulebook_version)
    sites = list(company.sites or [])
    s = summarize(snapshot.data)
    d = snapshot.scan_id
    date_fmt = f"{d[:4]}-{d[4:6]}-{d[6:8]}"
    attachments, names = [], []
    if "report" in docs:
        attachments.append((f"DPDPA-Report-{company.slug}-{date_fmt}.html",
                            client_report(snapshot.data, rb, sites).encode("utf-8"), "html"))
        names.append("the compliance report")
    if "gaps" in docs:
        attachments.append((f"DPDPA-Gap-Assessment-{company.slug}-{date_fmt}.html",
                            gap_assessment(snapshot.data, rb, sites).encode("utf-8"), "html"))
        names.append("the gap assessment (working document)")
    what = " and ".join(names) or "the compliance report"
    body = (f"Please find attached {what} for {company.name}, dated {date_fmt}.\n\n"
            f"Overall compliance score: {s['complianceScore']}%  "
            f"(gaps {s['counts']['GAP']}, partial {s['counts']['PARTIAL']}).\n")
    if note:
        body += f"\n{note}\n"
    body += f"\nOpen an attached file in a browser and use Print → Save as PDF for a PDF copy.\n"
    from .settings_service import effective_email_config
    status, actual = _send_email(to_email, f"DPDPA Compliance Documents — {company.name} ({date_fmt})",
                                 body, attachments=attachments,
                                 cfg=effective_email_config(db))
    doc_label = " + ".join(n_.replace("the ", "") for n_ in names) or "report"
    n = Notification(company_id=company.id, ntype="REPORT SENT",
                     title=f"Emailed {doc_label} to {to_email} ({date_fmt})", body=body,
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
