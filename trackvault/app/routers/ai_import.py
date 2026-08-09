"""Document conversion: upload any customer document, convert it in the
background (visible progress), review the proposed checkpoint answers, apply
what you approve, and download the converted Excel. Operator-only.
The conversion only suggests — a human confirms every row."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import delete, select

from sqlalchemy.orm import Session

from ..audit import record
from ..db import get_db
from ..models import AiSuggestion, Company, ImportJob, QuestionnaireAnswer, Role
from ..services import conversion_service
from ..services.rulebook_service import latest_rulebook
from ..templating import render
from .helpers import check_csrf, redirect, require

router = APIRouter()


def _company(request, db, cid):
    p = require(request, db, roles={Role.admin, Role.analyst, Role.cs})
    c = db.get(Company, cid)
    if not c or c.organization_id != p.user.organization_id:
        raise HTTPException(404, "Company not found")
    return p, c


def _job(db, cid: str, jid: str) -> ImportJob:
    j = db.get(ImportJob, jid)
    if not j or j.company_id != cid:
        raise HTTPException(404, "Conversion not found")
    return j


# ---- start a conversion ----
@router.post("/companies/{cid}/convert")
async def convert_start(cid: str, request: Request, db: Session = Depends(get_db)):
    from ..config import get_settings
    if not get_settings().ai_import_enabled:
        return redirect(f"/companies/{cid}", "Document conversion is disabled on this server.", err=True)
    p, c = _company(request, db, cid)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    upload = form.get("file")
    fname = getattr(upload, "filename", "") or ""
    if not upload or not fname:
        return redirect(f"/companies/{cid}", "Choose a document to convert.", err=True)
    data = await upload.read()
    if len(data) > 15 * 1024 * 1024:
        return redirect(f"/companies/{cid}", "File too large (max 15 MB).", err=True)
    running = db.execute(select(ImportJob).where(ImportJob.company_id == cid,
                                                 ImportJob.status.in_(["queued", "running"]))
                         ).scalars().first()
    if running:
        return redirect(f"/companies/{cid}/convert/{running.id}",
                        "A conversion is already running for this company — here it is.")
    job = conversion_service.start_job(db, cid, fname, data, p.user.email)
    record(db, action="convert.start", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""), source=fname, job=job.id)
    return redirect(f"/companies/{cid}/convert/{job.id}",
                    "Conversion started — this page follows the progress.")


# ---- watch progress / see the outcome ----
@router.get("/companies/{cid}/convert/{jid}")
def convert_status(cid: str, jid: str, request: Request, db: Session = Depends(get_db)):
    p, c = _company(request, db, cid)
    j = _job(db, cid, jid)
    return render(request, "convert_status.html", c=c, j=j,
                  refresh=(j.status in ("queued", "running")))


# ---- the converted, re-usable Excel ----
@router.get("/companies/{cid}/convert/{jid}/download")
def convert_download(cid: str, jid: str, request: Request, db: Session = Depends(get_db)):
    from ..config import get_settings
    p, c = _company(request, db, cid)
    j = _job(db, cid, jid)
    sugs = list(db.execute(select(AiSuggestion).where(AiSuggestion.company_id == cid)
                           .order_by(AiSuggestion.control_id)).scalars())
    if not sugs:
        return redirect(f"/companies/{cid}/convert/{jid}",
                        "Nothing to download yet — the conversion found no answers, or they "
                        "were already applied/discarded.", err=True)
    data = conversion_service.build_converted_workbook(
        latest_rulebook(db), get_settings().brand, c.name, j.filename, sugs)
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in c.name)[:40]
    return Response(content=data,
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition":
                             f'attachment; filename="Converted-{safe}.xlsx"'})


# ---- review & apply (human decision, always) ----
@router.get("/companies/{cid}/ai-review")
def ai_review(cid: str, request: Request, db: Session = Depends(get_db)):
    p, c = _company(request, db, cid)
    sugs = list(db.execute(select(AiSuggestion).where(AiSuggestion.company_id == cid)
                           .order_by(AiSuggestion.control_id)).scalars())
    rb = latest_rulebook(db)
    titles = {x["id"]: x["title"] for x in rb["controls"]}
    existing = {a.control_id: a.status for a in db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == cid)).scalars()}
    last_job = db.execute(select(ImportJob).where(ImportJob.company_id == cid)
                          .order_by(ImportJob.created_at.desc())).scalars().first()
    return render(request, "ai_review.html", c=c, sugs=sugs, titles=titles,
                  existing=existing, statuses=["COMPLIANT", "PARTIAL", "GAP", "NA", "TBC"],
                  provider_note="", last_job=last_job)


@router.post("/companies/{cid}/ai-review/apply")
async def ai_apply(cid: str, request: Request, db: Session = Depends(get_db)):
    p, c = _company(request, db, cid)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    sugs = {s.id: s for s in db.execute(select(AiSuggestion).where(
        AiSuggestion.company_id == cid)).scalars()}
    existing = {a.control_id: a for a in db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == cid)).scalars()}
    applied = 0
    for sid, sug in sugs.items():
        if form.get(f"accept-{sid}") != "1":
            continue
        st = (form.get(f"status-{sid}", "") or sug.status).upper()
        if st not in {"COMPLIANT", "PARTIAL", "GAP", "NA", "TBC"}:
            continue
        ev = (form.get(f"ev-{sid}", "") or sug.evidence).strip()
        if sug.control_id in existing:
            existing[sug.control_id].status = st
            existing[sug.control_id].evidence = ev
            existing[sug.control_id].department = "Converted document (reviewed)"
        else:
            db.add(QuestionnaireAnswer(company_id=cid, control_id=sug.control_id, status=st,
                                       evidence=ev, department="Converted document (reviewed)"))
        applied += 1
    db.execute(delete(AiSuggestion).where(AiSuggestion.company_id == cid))
    db.commit()
    record(db, action="convert.apply", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""), applied=applied)
    return redirect(f"/companies/{cid}", f"Applied {applied} reviewed answer(s) to the questionnaire.")


@router.post("/companies/{cid}/ai-review/discard")
async def ai_discard(cid: str, request: Request, db: Session = Depends(get_db)):
    p, c = _company(request, db, cid)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    db.execute(delete(AiSuggestion).where(AiSuggestion.company_id == cid))
    db.commit()
    return redirect(f"/companies/{cid}", "Discarded the converted suggestions.")
