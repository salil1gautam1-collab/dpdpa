"""Assessment orchestration — DB-backed, secret-decrypting, snapshot-persisting.

Replaces the prototype's file-based run_scan + infra dispatch. Credentials are
decrypted in memory only for the duration of the scan.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..crypto import decrypt_secret
from ..domain import engine
from ..domain.evidence import make_evidence, mask_pii, utc_now
from ..domain.scanners import web
from ..models import Company, Connector, QuestionnaireAnswer, Snapshot
from .rulebook_service import latest_rulebook

# provider -> scanner module import path
_SCANNERS = {
    "aws": "app.domain.scanners.aws",
    "azure": "app.domain.scanners.azure",
    "intune": "app.domain.scanners.intune",
    "gcp": "app.domain.scanners.gcp",
    "adgpo": "app.domain.scanners.adgpo",
    "firewall": "app.domain.scanners.firewall",
}


def run_and_notify(db: Session, company: Company, *, skip_web: bool = False,
                   actor_email: str = "") -> tuple[Snapshot, list]:
    """Run an assessment, detect changes vs the previous snapshot, and notify the
    client (report-ready, or an alert if something regressed/appeared). Shared by
    the manual run route and the scheduled monitor."""
    from .alerts import compute_alerts, summarize_alerts
    from . import notify_service
    from ..config import get_settings
    from ..domain.engine import summarize
    from ..models import Snapshot, User, Role

    prev = db.execute(select(Snapshot).where(Snapshot.company_id == company.id)
                      .order_by(Snapshot.scan_id.desc())).scalars().first()
    prev_data = prev.data if prev else None
    snap = run_assessment(db, company, skip_web=skip_web, actor_email=actor_email)
    alerts = compute_alerts(prev_data, snap.data)

    # Deterministic: the single active client for THIS company only — never another's.
    client = db.execute(select(User).where(User.company_id == company.id, User.role == Role.client,
                                           User.is_active.is_(True))
                        .order_by(User.created_at.desc())).scalars().first()
    s = summarize(snap.data)
    d = snap.scan_id
    date_fmt = f"{d[:4]}-{d[4:6]}-{d[6:8]}"
    base = get_settings().base_url
    email_to = client.email if client else ""
    if alerts:
        body = (f"Your latest DPDPA assessment ({date_fmt}) flagged {len(alerts)} change(s) that need "
                f"attention:\n\n{summarize_alerts(alerts)}\n\nCompliance score: {s['complianceScore']}%.\n"
                f"\nSign in: {base}/login\n")
        notify_service.notify(db, company.id, "ALERT",
                              f"⚠ {len(alerts)} change(s) need attention ({date_fmt})", body, email_to=email_to)
    else:
        body = (f"Your DPDPA compliance report dated {date_fmt} is available in your portal.\n\n"
                f"Compliance score: {s['complianceScore']}% (gaps {s['counts']['GAP']}, "
                f"partial {s['counts']['PARTIAL']}).\n\nSign in: {base}/login\n")
        notify_service.notify(db, company.id, "REPORT READY", f"New report dated {date_fmt}",
                              body, email_to=email_to)
    return snap, alerts


def unconfirmed_control_ids(db: Session, company_id: str):
    """Control ids the latest assessment could NOT confirm automatically (status TBC).
    Returns None if no assessment has run yet."""
    from ..models import Snapshot as _Snap
    latest = db.execute(select(_Snap).where(_Snap.company_id == company_id)
                        .order_by(_Snap.scan_id.desc())).scalars().first()
    if not latest:
        return None
    return {r["controlId"] for r in (latest.data or {}).get("resolutions", [])
            if r.get("status") == "TBC"}


def _assertions(db: Session, company_id: str) -> dict:
    out = {}
    rows = db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == company_id)).scalars()
    for r in rows:
        if r.status not in ("COMPLIANT", "PARTIAL", "GAP", "NA", "TBC"):
            continue
        out[r.control_id] = {
            "status": r.status,
            "evidence": [make_evidence("declaration", excerpt=mask_pii(r.evidence or ""),
                                       note=f"declared by {r.department or '?'}")],
        }
    return out


def run_assessment(db: Session, company: Company, *, skip_web: bool = False,
                   actor_email: str = "") -> Snapshot:
    rb = latest_rulebook(db)
    started = utc_now()
    findings: list = []
    meta: dict = {}

    # 1. Website scan (consent-gated)
    consent = company.scan_consent or {}
    if not skip_web and company.sites and consent.get("granted"):
        f, m = web.run(list(company.sites))
        findings += f
        meta.update(m)
    elif not skip_web and company.sites and not consent.get("granted"):
        meta["webScanner"] = "skipped — no scan consent"
    else:
        meta["webScanner"] = "skipped"

    # 2. Infra/cloud connectors (decrypt in memory)
    for conn in company.connectors:
        prov = conn.provider
        if prov not in _SCANNERS or not (conn.consent or {}).get("granted"):
            meta[f"{prov}Connector"] = "configured but not consented" if conn.consent is not None else "skipped"
            continue
        creds = {**(conn.public_config or {}), **decrypt_secret(conn.secret_enc), "consent": conn.consent}
        mod = __import__(_SCANNERS[prov], fromlist=["run_checks"])
        try:
            f, m = mod.run_checks(creds)
            findings += f
            meta.update(m)
            meta[f"{prov}Connector"] = "ran"
        except Exception as ex:  # pragma: no cover - defensive
            meta[f"{prov}Connector"] = f"error: {type(ex).__name__}"

    # 3. Resolve controls
    assertions = _assertions(db, company.id)
    overrides = company.applicability_overrides or {}
    web_by_check: dict = {}
    for fnd in findings:
        web_by_check.setdefault(fnd.get("webCheckId"), []).append(fnd)

    resolutions = []
    for c in rb["controls"]:
        r = engine.resolve(c, web_by_check, assertions, overrides)
        r.update(title=c["title"], category=c["category"], severity=c["severity"],
                 legalRef=c["legalRef"], remediation=c["remediation"],
                 appAssist=c.get("appAssist", {}), checkMethod=c["checkMethod"],
                 controlHash=engine.control_hash(c))
        resolutions.append(r)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot_data = {
        "scanId": ts, "client": company.name, "slug": company.slug,
        "rulebookVersion": rb["rulebookVersion"], "startedAt": started,
        "finishedAt": utc_now(), "meta": meta, "resolutions": resolutions,
    }
    s = engine.summarize(snapshot_data)
    row = Snapshot(company_id=company.id, scan_id=ts, rulebook_version=rb["rulebookVersion"],
                   score=s["complianceScore"], counts=s["counts"], data=snapshot_data,
                   created_by=actor_email)
    db.add(row)
    company.pending_assessment = False
    db.commit()
    db.refresh(row)
    return row
