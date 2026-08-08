"""Client-side workspace: view report, questionnaire, submit inputs, notifications."""
from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.datastructures import FormData
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import record
from ..db import get_db
from ..models import (Company, Notification, QuestionnaireAnswer, Snapshot)
from ..services.rulebook_service import latest_rulebook
from ..templating import render
from .helpers import check_csrf, redirect, require

router = APIRouter()

VALID = {"COMPLIANT", "PARTIAL", "GAP", "NA", "TBC"}


def _client_company(request: Request, db: Session) -> tuple:
    p = require(request, db, client=True)
    if not p.user.company_id:
        raise HTTPException(400, "No company linked to this login")
    c = db.get(Company, p.user.company_id)
    if not c:
        raise HTTPException(404, "Company not found")
    return p, c


@router.get("/workspace")
def workspace(request: Request, db: Session = Depends(get_db)):
    p, c = _client_company(request, db)
    latest = db.execute(select(Snapshot).where(Snapshot.company_id == c.id)
                        .order_by(Snapshot.scan_id.desc())).scalars().first()
    answered = len(list(db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == c.id)).scalars()))
    notes = list(db.execute(select(Notification).where(Notification.company_id == c.id)
                            .order_by(Notification.created_at.desc())).scalars())[:6]
    unread = sum(1 for n in notes if not n.read)
    total = len(latest_rulebook(db)["controls"])
    return render(request, "client_workspace.html", c=c, latest=latest, answered=answered,
                  total=total, notes=notes, unread=unread)


@router.post("/workspace/notifications/read")
async def mark_read(request: Request, db: Session = Depends(get_db)):
    p, c = _client_company(request, db)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    for n in db.execute(select(Notification).where(Notification.company_id == c.id,
                                                   Notification.read.is_(False))).scalars():
        n.read = True
    db.commit()
    return redirect("/workspace")


@router.post("/workspace/submit-inputs")
async def submit_inputs(request: Request, db: Session = Depends(get_db)):
    p, c = _client_company(request, db)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    c.submission = {"submitted": True, "at": date.today().isoformat(), "by": p.user.email}
    c.pending_assessment = True
    db.commit()
    record(db, action="client.submit", actor=p.user, target_type="company", target_id=c.id,
           ip=getattr(request.state, "client_ip", ""))
    return redirect("/workspace", "Thank you — your inputs are submitted. Your assessment team will prepare your report.")


@router.get("/workspace/questionnaire")
def questionnaire(request: Request, db: Session = Depends(get_db)):
    p, c = _client_company(request, db)
    rb = latest_rulebook(db)
    existing = {a.control_id: a for a in db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == c.id)).scalars()}
    cats = {x["id"]: x["name"] for x in rb["categories"]}
    return render(request, "questionnaire.html", c=c, controls=rb["controls"], cats=cats,
                  existing=existing, valid=sorted(VALID), back="/workspace")


@router.post("/workspace/questionnaire")
async def save_questionnaire(request: Request, db: Session = Depends(get_db)):
    p, c = _client_company(request, db)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    _apply_questionnaire(db, c.id, form)
    record(db, action="questionnaire.save", actor=p.user, target_type="company", target_id=c.id,
           ip=getattr(request.state, "client_ip", ""))
    return redirect("/workspace", "Answers saved. Submit your inputs when ready.")


def _apply_questionnaire(db: Session, company_id: str, form: FormData) -> int:
    from ..services.rulebook_service import latest_rulebook as _lr
    rb = _lr(db)
    existing = {a.control_id: a for a in db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == company_id)).scalars()}
    n = 0
    for ctrl in rb["controls"]:
        cid = ctrl["id"]
        st = form.get(f"st-{cid}", "")
        if st not in VALID:
            continue
        ev = (form.get(f"ev-{cid}", "") or "").strip()
        dept = (form.get(f"dept-{cid}", "") or "").strip()
        if cid in existing:
            existing[cid].status = st
            existing[cid].evidence = ev
            existing[cid].department = dept
        else:
            db.add(QuestionnaireAnswer(company_id=company_id, control_id=cid, status=st,
                                       evidence=ev, department=dept))
        n += 1
    db.commit()
    return n
