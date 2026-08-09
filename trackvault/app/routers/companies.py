"""Operator-side company management + running assessments."""
from __future__ import annotations

import re
from datetime import date

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import record
from ..config import get_settings
from ..db import get_db
from ..domain.engine import summarize
from ..models import (Company, Notification, QuestionnaireAnswer, Role, Snapshot, User)
from ..services import notify_service
from ..services.rulebook_service import latest_rulebook
from ..services.scan_service import run_assessment
from ..security import hash_password
from ..templating import render
from .helpers import check_csrf, redirect, require

router = APIRouter()
_s = get_settings()


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _company_or_404(db: Session, org_id: str, cid: str) -> Company:
    c = db.get(Company, cid)
    if not c or c.organization_id != org_id:
        from fastapi import HTTPException
        raise HTTPException(404, "Company not found")
    return c


@router.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, operator=True)
    q = (request.query_params.get("q") or "").strip()
    stmt = select(Company).where(Company.organization_id == p.user.organization_id)
    if q:
        stmt = stmt.where(Company.name.ilike(f"%{q}%"))
    companies = list(db.execute(stmt.order_by(Company.name)).scalars())
    rows = []
    for c in companies:
        latest = db.execute(select(Snapshot).where(Snapshot.company_id == c.id)
                            .order_by(Snapshot.scan_id.desc())).scalars().first()
        rows.append({"c": c, "latest": latest})
    return render(request, "dashboard.html", rows=rows, q=q)


@router.post("/companies")
def create_company(request: Request, name: str = Form(...), sites: str = Form(""),
                   csrf: str = Form(""), db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin, Role.analyst, Role.cs})
    check_csrf(p, csrf)
    site_list = [s.strip() for s in sites.split(",") if s.strip()]
    c = Company(organization_id=p.user.organization_id, name=name.strip(),
                slug=_slug(name), sites=site_list, scan_consent={"granted": False})
    db.add(c)
    db.commit()
    record(db, action="company.create", actor=p.user, target_type="company", target_id=c.id,
           ip=getattr(request.state, "client_ip", ""), name=name)
    return redirect(f"/companies/{c.id}", "Company created.")


@router.get("/companies/{cid}")
def company_detail(cid: str, request: Request, db: Session = Depends(get_db)):
    p = require(request, db, operator=True)
    c = _company_or_404(db, p.user.organization_id, cid)
    snaps = list(db.execute(select(Snapshot).where(Snapshot.company_id == cid)
                            .order_by(Snapshot.scan_id.desc())).scalars())
    latest = snaps[0] if snaps else None
    answered = len(list(db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == cid)).scalars()))
    rb = latest_rulebook(db)
    _labels = {"aws": "☁️ AWS", "azure": "🔷 Azure", "intune": "💻 Intune/Defender",
               "gcp": "🟡 Google Cloud", "adgpo": "🏢 AD/GPO", "firewall": "🧱 Firewall"}
    connected = [_labels.get(k.provider, k.provider) for k in c.connectors
                 if (k.consent or {}).get("granted") and k.secret_enc]
    last_run = []
    if latest:
        m = (latest.data or {}).get("meta", {})
        if m.get("pagesScanned"):
            last_run.append(f"🌐 website ({len(m['pagesScanned'])} pages)")
        for k, v in m.items():
            if k.endswith("Connector") and v == "ran":
                last_run.append(_labels.get(k[:-9], k[:-9]))
        last_run.append("📋 questionnaire")
    from ..models import Notification
    recent_alerts = list(db.execute(select(Notification).where(
        Notification.company_id == cid, Notification.ntype == "ALERT")
        .order_by(Notification.created_at.desc())).scalars())[:4]
    from ..config import get_settings
    # Anything running right now? Surface it so the operator can navigate freely
    # and always find the way back to the progress page.
    from ..models import AssessJob, ImportJob
    running_assess = db.execute(select(AssessJob).where(
        AssessJob.company_id == cid, AssessJob.status.in_(["queued", "running"]))
        .order_by(AssessJob.created_at.desc())).scalars().first()
    running_convert = db.execute(select(ImportJob).where(
        ImportJob.company_id == cid, ImportJob.status.in_(["queued", "running"]))
        .order_by(ImportJob.created_at.desc())).scalars().first()
    from ..services.frameworks import FRAMEWORKS
    return render(request, "company_operator.html", c=c, snaps=snaps, latest=latest,
                  answered=answered, total=len(rb["controls"]), connected=connected,
                  last_run=last_run, recent_alerts=recent_alerts,
                  ai_import_enabled=get_settings().ai_import_enabled,
                  running_assess=running_assess, running_convert=running_convert,
                  frameworks=FRAMEWORKS, selected_fw=list(c.frameworks or ["dpdpa"]))


@router.post("/companies/{cid}/consent")
def set_consent(cid: str, request: Request, granted_by: str = Form(...), csrf: str = Form(""),
                db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin, Role.analyst})
    c = _company_or_404(db, p.user.organization_id, cid)
    check_csrf(p, csrf)
    c.scan_consent = {"granted": True, "grantedBy": granted_by.strip(), "date": date.today().isoformat()}
    db.commit()
    record(db, action="company.consent", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""))
    return redirect(f"/companies/{cid}", "Scan authorisation recorded.")


@router.post("/companies/{cid}/scan")
def run_scan(cid: str, request: Request, skip_web: str = Form(""), csrf: str = Form(""),
             db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin, Role.analyst})
    c = _company_or_404(db, p.user.organization_id, cid)
    check_csrf(p, csrf)
    skip = bool(skip_web) or not c.sites
    if not skip and not (c.scan_consent or {}).get("granted"):
        return redirect(f"/companies/{cid}", "Record website scan authorisation first (or run questionnaire-only).", err=True)
    from ..models import AssessJob
    running = db.execute(select(AssessJob).where(AssessJob.company_id == cid,
                                                 AssessJob.status.in_(["queued", "running"]))
                         ).scalars().first()
    if running:
        return redirect(f"/companies/{cid}/assess/{running.id}",
                        "An assessment is already running for this company — here it is.")
    from ..services.scan_service import start_assessment_job
    job = start_assessment_job(db, c, skip_web=skip, actor_email=p.user.email)
    record(db, action="assessment.start", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""), job=job.id, skip_web=skip)
    return redirect(f"/companies/{cid}/assess/{job.id}",
                    "Assessment started — this page follows the progress. You can browse "
                    "anywhere; the company page shows it running too.")


@router.get("/companies/{cid}/assess/{jid}")
def assess_status(cid: str, jid: str, request: Request, db: Session = Depends(get_db)):
    from ..models import AssessJob
    p = require(request, db, operator=True)
    c = _company_or_404(db, p.user.organization_id, cid)
    j = db.get(AssessJob, jid)
    if not j or j.company_id != cid:
        from fastapi import HTTPException
        raise HTTPException(404, "Assessment run not found")
    return render(request, "assess_status.html", c=c, j=j,
                  refresh=(j.status in ("queued", "running")))


@router.post("/companies/{cid}/send-report")
def send_report(cid: str, request: Request, to_email: str = Form(...), scan_id: str = Form(""),
                note: str = Form(""), csrf: str = Form(""),
                doc_report: str = Form(""), doc_gaps: str = Form(""),
                db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin, Role.analyst, Role.cs, Role.legal})
    c = _company_or_404(db, p.user.organization_id, cid)
    check_csrf(p, csrf)
    docs = tuple(d for d, on in (("report", doc_report), ("gaps", doc_gaps)) if on)
    if not docs:
        return redirect(f"/companies/{cid}", "Pick at least one document to attach "
                        "(report and/or gap assessment).", err=True)
    q = select(Snapshot).where(Snapshot.company_id == cid)
    snap = (db.execute(q.where(Snapshot.scan_id == scan_id)).scalar_one_or_none() if scan_id
            else db.execute(q.order_by(Snapshot.scan_id.desc())).scalars().first())
    if not snap:
        return redirect(f"/companies/{cid}", "No report to send yet — run an assessment first.", err=True)
    to = to_email.strip()
    if "@" not in to:
        return redirect(f"/companies/{cid}", "Enter a valid recipient email.", err=True)
    from ..services.notify_service import send_report_email
    n = send_report_email(db, c, snap, to, note.strip(), docs=docs)
    record(db, action="report.email", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""), to=to, status=n.email_status)
    if n.email_status == "sent":
        where = f" (redirected to {n.email_delivered_to} — test mode)" if n.email_delivered_to != to else ""
        return redirect(f"/companies/{cid}", f"Report emailed to {to}{where}.")
    if n.email_status == "simulated":
        return redirect(f"/companies/{cid}", "Email is in simulated mode — set SMTP to send for real. (Logged, not sent.)")
    return redirect(f"/companies/{cid}", f"Could not send: {n.email_status}.", err=True)


@router.post("/companies/{cid}/monitoring")
def set_monitoring(cid: str, request: Request, frequency: str = Form("off"), csrf: str = Form(""),
                   db: Session = Depends(get_db)):
    from datetime import datetime, timedelta, timezone
    p = require(request, db, roles={Role.admin, Role.analyst})
    c = _company_or_404(db, p.user.organization_id, cid)
    check_csrf(p, csrf)
    freq = frequency if frequency in ("off", "weekly", "monthly") else "off"
    c.monitor_frequency = freq
    if freq == "off":
        c.next_monitor_at = None
    else:
        days = 7 if freq == "weekly" else 30
        c.next_monitor_at = datetime.now(timezone.utc) + timedelta(days=days)
    db.commit()
    record(db, action="monitoring.set", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""), frequency=freq)
    return redirect(f"/companies/{cid}",
                    f"Monitoring set to {freq}." + ("" if freq == "off" else " It will re-assess automatically and alert on changes."))


@router.get("/companies/{cid}/questionnaire")
def op_questionnaire(cid: str, request: Request, db: Session = Depends(get_db)):
    p = require(request, db, operator=True)
    c = _company_or_404(db, p.user.organization_id, cid)
    rb = latest_rulebook(db)
    existing = {a.control_id: a for a in db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == cid)).scalars()}
    cats = {x["id"]: x["name"] for x in rb["categories"]}
    from .client import VALID
    from ..services.scan_service import unconfirmed_control_ids
    controls = rb["controls"]
    unconfirmed = unconfirmed_control_ids(db, cid)
    filtered = request.query_params.get("only") == "unconfirmed" and unconfirmed is not None
    if filtered:
        controls = [x for x in controls if x["id"] in unconfirmed]
    return render(request, "questionnaire.html", c=c, controls=controls, cats=cats,
                  existing=existing, valid=sorted(VALID), back=f"/companies/{cid}",
                  action=f"/companies/{cid}/questionnaire", filtered=filtered,
                  full_link=f"/companies/{cid}/questionnaire",
                  unconfirmed_count=len(unconfirmed) if unconfirmed is not None else 0)


@router.post("/companies/{cid}/questionnaire")
async def op_save_questionnaire(cid: str, request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin, Role.analyst, Role.cs, Role.legal})
    c = _company_or_404(db, p.user.organization_id, cid)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    from .client import _apply_questionnaire
    n = _apply_questionnaire(db, cid, form)
    record(db, action="questionnaire.save", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""), answered=n)
    return redirect(f"/companies/{cid}", "Questionnaire saved.")


@router.get("/companies/{cid}/questionnaire-template.xlsx")
def download_template(cid: str, request: Request, db: Session = Depends(get_db)):
    from fastapi.responses import Response
    from ..config import get_settings
    from ..services.template_service import build_template
    p = require(request, db, operator=True)
    c = _company_or_404(db, p.user.organization_id, cid)
    data = build_template(latest_rulebook(db), get_settings().brand, company_name=c.name)
    fname = f"DPDPA-Questionnaire-{c.slug}.xlsx"
    return Response(content=data,
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@router.post("/companies/{cid}/import")
async def import_customer_data(cid: str, request: Request, db: Session = Depends(get_db)):
    """Import collated customer data from pasted text or an uploaded file
    (CSV / Excel / Word / PDF / JSON). Fuzzy-parses simple formats."""
    p = require(request, db, roles={Role.admin, Role.analyst, Role.cs})
    c = _company_or_404(db, p.user.organization_id, cid)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    from ..services import import_parser as ip

    lookup = ip.build_id_lookup([ctrl["id"] for ctrl in latest_rulebook(db)["controls"]])
    answers: list[dict] = []
    source_desc = []

    pasted = (form.get("payload", "") or "").strip()
    if pasted:
        answers += ip.parse_text(pasted, lookup)
        source_desc.append("pasted text")

    upload = form.get("file")
    fname = getattr(upload, "filename", "") or ""
    if upload is not None and fname:
        data = await upload.read()
        if len(data) > 15 * 1024 * 1024:
            return redirect(f"/companies/{cid}", "File too large (max 15 MB).", err=True)
        answers += ip.parse_upload(fname, data, lookup)
        source_desc.append(fname)

    # de-duplicate: last write wins per control id
    merged = {}
    for a in answers:
        merged[a["controlId"]] = a
    if not merged:
        return redirect(f"/companies/{cid}",
                        "Couldn't find any recognisable answers. Provide rows like 'SEC-01, gap, evidence' "
                        "or upload a CSV/Excel/Word/PDF with a control column and a status column.", err=True)

    existing = {a.control_id: a for a in db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == cid)).scalars()}
    for cidx, a in merged.items():
        if cidx in existing:
            existing[cidx].status = a["status"]
            existing[cidx].evidence = a.get("evidence", "")
            existing[cidx].department = a.get("department", "")
        else:
            db.add(QuestionnaireAnswer(company_id=cid, control_id=cidx, status=a["status"],
                                       evidence=a.get("evidence", ""), department=a.get("department", "")))
    db.commit()
    record(db, action="customer.data.import", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""), imported=len(merged), sources=source_desc)
    return redirect(f"/companies/{cid}",
                    f"Imported {len(merged)} answer(s) from {', '.join(source_desc)}. "
                    "Review in the questionnaire, then run the assessment.")


@router.post("/companies/{cid}/client-login")
def set_client_login(cid: str, request: Request, email: str = Form(...), csrf: str = Form(""),
                     db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin, Role.analyst, Role.cs})
    c = _company_or_404(db, p.user.organization_id, cid)
    check_csrf(p, csrf)
    email = email.strip().lower()
    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing and not (existing.company_id == cid and existing.role == Role.client):
        return redirect(f"/companies/{cid}", "That email already belongs to another account.", err=True)
    import secrets as _sec
    temp = "Tv-" + _sec.token_urlsafe(9)
    # Enforce exactly one active client per company — retire any prior client logins
    # so automated emails can never go to a stale/wrong address.
    for old in db.execute(select(User).where(User.company_id == cid, User.role == Role.client,
                                             User.email != email)).scalars():
        old.is_active = False
        old.company_id = None
    if existing:
        existing.password_hash = hash_password(temp)
        existing.must_change_password = True
        existing.is_active = True
        existing.company_id = cid
    else:
        u = User(organization_id=p.user.organization_id, email=email, name="Client",
                 role=Role.client, password_hash=hash_password(temp),
                 must_change_password=True, company_id=cid)
        db.add(u)
    db.commit()
    record(db, action="client.login.set", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""), email=email)
    return redirect(f"/companies/{cid}",
                    f"Client login set: {email}. One-time temporary password: {temp} — share it securely.")


# ---- Framework selection / interest ----
@router.post("/companies/{cid}/frameworks")
async def set_frameworks(cid: str, request: Request, db: Session = Depends(get_db)):
    from ..services.frameworks import FRAMEWORKS
    p = require(request, db, roles={Role.admin, Role.analyst, Role.cs})
    c = _company_or_404(db, p.user.organization_id, cid)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    chosen = ["dpdpa"]  # the active framework is always on
    for fid, fw in FRAMEWORKS.items():
        if fw["status"] == "coming-soon" and form.get(f"fw-{fid}") == "1":
            chosen.append(fid)
    c.frameworks = chosen
    db.commit()
    record(db, action="company.frameworks", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""), frameworks=chosen)
    extra = [FRAMEWORKS[f]["name"] for f in chosen if f != "dpdpa"]
    return redirect(f"/companies/{cid}",
                    ("Interest recorded for: " + ", ".join(extra) + " — they activate the moment "
                     "their rulebooks ship.") if extra else "Framework selection saved (DPDPA).")


# ---- Export & delete (DPDPA portability + erasure; admin only) ----
@router.get("/companies/{cid}/export")
def export_company_data(cid: str, request: Request, db: Session = Depends(get_db)):
    from fastapi.responses import Response
    from ..services.company_service import export_company
    p = require(request, db, roles={Role.admin})
    c = _company_or_404(db, p.user.organization_id, cid)
    data = export_company(db, c)
    record(db, action="company.export", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""))
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in c.name)[:40]
    stamp = date.today().isoformat()
    return Response(content=data, media_type="application/json",
                    headers={"Content-Disposition":
                             f'attachment; filename="TrackVault-Export-{safe}-{stamp}.json"'})


@router.post("/companies/{cid}/delete")
async def delete_company(cid: str, request: Request, db: Session = Depends(get_db)):
    from ..services.company_service import erase_company
    p = require(request, db, roles={Role.admin})
    c = _company_or_404(db, p.user.organization_id, cid)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    typed = (form.get("confirm_name", "") or "").strip()
    if typed != c.name:
        return redirect(f"/companies/{cid}",
                        "Deletion cancelled — the company name you typed didn't match exactly.",
                        err=True)
    reason = (form.get("reason", "") or "").strip() or "erasure requested by admin"
    name = erase_company(db, cid, reason=reason, actor_email=p.user.email)
    return redirect("/dashboard", f"{name} and all its data have been permanently erased.")
