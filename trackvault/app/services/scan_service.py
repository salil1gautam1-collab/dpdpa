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
                   actor_email: str = "", progress=None) -> tuple[Snapshot, list]:
    """Run an assessment, detect changes vs the previous snapshot, and notify the
    client (report-ready, or an alert if something regressed/appeared). Shared by
    the manual run route and the scheduled monitor."""
    from .alerts import compute_alerts, summarize_alerts
    from . import notify_service
    from ..config import get_settings
    from ..domain.engine import summarize
    from ..models import Snapshot, User, Role

    tell = progress or (lambda stage: None)
    prev = db.execute(select(Snapshot).where(Snapshot.company_id == company.id)
                      .order_by(Snapshot.scan_id.desc())).scalars().first()
    prev_data = prev.data if prev else None
    snap = run_assessment(db, company, skip_web=skip_web, actor_email=actor_email,
                          progress=progress)
    tell("Comparing with the previous assessment — looking for regressions and new third parties…")
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
    tell("Preparing the client notification…")
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
                   actor_email: str = "", progress=None) -> Snapshot:
    """progress: optional callable(str) — narrates each step for a live UI.
    Defaults to a no-op so the scheduler/CLI paths are unchanged."""
    tell = progress or (lambda stage: None)
    rb = latest_rulebook(db)
    started = utc_now()
    findings: list = []
    meta: dict = {}

    # 1. Website scan (consent-gated)
    consent = company.scan_consent or {}
    if not skip_web and company.sites and consent.get("granted"):
        tell(f"Scanning website{'s' if len(company.sites) > 1 else ''}: "
             f"{', '.join(company.sites)} — consent banners, trackers, cookies, security headers…")
        f, m = web.run(list(company.sites))
        findings += f
        meta.update(m)
    elif not skip_web and company.sites and not consent.get("granted"):
        meta["webScanner"] = "skipped — no scan consent"
    else:
        meta["webScanner"] = "skipped"

    # 2. Infra/cloud connectors (decrypt in memory)
    _names = {"aws": "AWS", "azure": "Azure", "intune": "Intune/Defender", "gcp": "Google Cloud",
              "adgpo": "AD/GPO", "firewall": "Firewall"}
    for conn in company.connectors:
        prov = conn.provider
        if prov not in _SCANNERS or not (conn.consent or {}).get("granted"):
            meta[f"{prov}Connector"] = "configured but not consented" if conn.consent is not None else "skipped"
            continue
        tell(f"Checking {_names.get(prov, prov)} (read-only, consented)…")
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
    tell("Merging questionnaire declarations…")
    assertions = _assertions(db, company.id)
    overrides = company.applicability_overrides or {}
    web_by_check: dict = {}
    for fnd in findings:
        web_by_check.setdefault(fnd.get("webCheckId"), []).append(fnd)

    tell(f"Resolving all {len(rb['controls'])} checkpoints (scanner findings beat declarations)…")
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


# ---- Narrated background assessment (the "something is happening" window) ----

def start_assessment_job(db: Session, company: Company, *, skip_web: bool,
                         actor_email: str):
    """Kick off an assessment in a background thread and return its job row.
    The operator watches a live progress page instead of a frozen browser."""
    import threading
    from ..models import AssessJob

    job = AssessJob(company_id=company.id, status="queued", stage="Queued",
                    created_by=actor_email)
    db.add(job)
    db.commit()
    db.refresh(job)
    t = threading.Thread(target=_run_assessment_job,
                         args=(job.id, company.id, skip_web, actor_email), daemon=True)
    t.start()
    return job


def _job_set(job_id: str, **fields) -> None:
    from ..db import SessionLocal
    from ..models import AssessJob
    with SessionLocal() as s:
        j = s.get(AssessJob, job_id)
        if j:
            for k, v in fields.items():
                setattr(j, k, v)
            s.commit()


def _run_assessment_job(job_id: str, company_id: str, skip_web: bool,
                        actor_email: str) -> None:
    from datetime import datetime, timezone
    from ..db import SessionLocal
    try:
        _job_set(job_id, status="running", stage="Starting the assessment engine…")
        with SessionLocal() as s:
            company = s.get(Company, company_id)
            snap, alerts = run_and_notify(
                s, company, skip_web=skip_web, actor_email=actor_email,
                progress=lambda stage: _job_set(job_id, stage=stage))
            score, scan_id, n_alerts = snap.score, snap.scan_id, len(alerts)
        _job_set(job_id, status="done", stage="Finished", scan_id=scan_id, score=score,
                 alerts=n_alerts, finished_at=datetime.now(timezone.utc),
                 note=(f"⚠ {n_alerts} change(s) flagged — the client was alerted."
                       if n_alerts else "Client notified that the report is ready."))
    except Exception as ex:  # never leave a job stuck in 'running'
        _job_set(job_id, status="error", stage="Assessment failed",
                 note=f"{type(ex).__name__}: {ex}",
                 finished_at=datetime.now(timezone.utc))


def autorun_due() -> int:
    """The submit safety net: if a customer's inputs have sat pending for more
    than TRACKVAULT_AUTORUN_HOURS with no operator action, run the assessment
    automatically so the customer still gets their report on time.

    Called from the in-process ticker (main.py) and from `app.ops monitor`
    (cron). Race-safe across workers: rows are taken with SKIP LOCKED and the
    one-running-job-per-company check applies."""
    from datetime import datetime, timedelta, timezone
    from ..config import get_settings
    from ..db import SessionLocal
    from ..models import AssessJob

    hours = get_settings().autorun_hours
    if not hours:
        return 0
    started = 0
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        candidates = list(db.execute(
            select(Company).where(Company.pending_assessment.is_(True))
            .with_for_update(skip_locked=True)).scalars())
        for c in candidates:
            at_raw = (c.submission or {}).get("at", "")
            try:
                at = datetime.fromisoformat(at_raw)
                if at.tzinfo is None:  # legacy date-only submissions
                    at = at.replace(tzinfo=timezone.utc)
            except ValueError:
                at = now  # unparseable — treat as fresh, never loop-run
            if now - at < timedelta(hours=hours):
                continue
            running = db.execute(select(AssessJob).where(
                AssessJob.company_id == c.id,
                AssessJob.status.in_(["queued", "running"]))).scalars().first()
            if running:
                continue
            skip_web = not (c.sites and (c.scan_consent or {}).get("granted"))
            job = AssessJob(company_id=c.id, status="queued", stage="Queued (auto-run)",
                            created_by=f"auto-run ({hours}h after submission)")
            db.add(job)
            from ..models import AuditLog
            db.add(AuditLog(actor_email="system", action="assessment.autorun",
                            target_type="company", target_id=c.id,
                            detail={"hours": hours, "submittedAt": at_raw}))
            db.commit()
            job_id, cid = job.id, c.id
            started += 1
    # Run OUTSIDE the locking session, and SYNCHRONOUSLY: callers are already
    # background contexts (the ticker thread, or the ops CLI) — a spawned
    # daemon thread would be killed when a short-lived CLI process exits.
    if started:
        for job_id, cid, skip in _pending_autorun_jobs():
            _run_assessment_job(job_id, cid, skip, "auto-run")
    return started


def _pending_autorun_jobs():
    from ..db import SessionLocal
    from ..models import AssessJob
    with SessionLocal() as db:
        jobs = list(db.execute(select(AssessJob).where(
            AssessJob.status == "queued",
            AssessJob.created_by.like("auto-run%"))).scalars())
        out = []
        for j in jobs:
            c = db.get(Company, j.company_id)
            skip = not (c and c.sites and (c.scan_consent or {}).get("granted"))
            out.append((j.id, j.company_id, skip))
        return out
