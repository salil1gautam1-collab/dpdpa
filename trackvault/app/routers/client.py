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
    total = len(latest_rulebook(db)["controls"])
    return render(request, "client_workspace.html", c=c, latest=latest, answered=answered,
                  total=total)


@router.get("/workspace/notifications")
def notifications_page(request: Request, db: Session = Depends(get_db)):
    """All notifications, grouped by date (newest first) — its own page so the
    workspace never floods."""
    p, c = _client_company(request, db)
    notes = list(db.execute(select(Notification).where(Notification.company_id == c.id)
                            .order_by(Notification.created_at.desc())).scalars())
    groups: dict = {}  # insertion-ordered: newest date first
    for n in notes:
        groups.setdefault(n.created_at.strftime("%A, %d %B %Y"), []).append(n)
    unread = sum(1 for n in notes if not n.read)
    return render(request, "client_notifications.html", c=c, groups=groups,
                  unread=unread, total_count=len(notes))


@router.post("/workspace/notifications/read")
async def mark_read(request: Request, db: Session = Depends(get_db)):
    p, c = _client_company(request, db)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    for n in db.execute(select(Notification).where(Notification.company_id == c.id,
                                                   Notification.read.is_(False))).scalars():
        n.read = True
    db.commit()
    back = form.get("back", "")
    return redirect(back if back.startswith("/workspace") else "/workspace/notifications")


@router.post("/workspace/submit-inputs")
async def submit_inputs(request: Request, db: Session = Depends(get_db)):
    from datetime import datetime, timezone
    from ..config import get_settings
    from ..models import Role, User
    from ..services.notify_service import _send_email
    from ..services.settings_service import effective_email_config
    p, c = _client_company(request, db)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    c.submission = {"submitted": True, "at": datetime.now(timezone.utc).isoformat(),
                    "by": p.user.email}
    c.pending_assessment = True
    db.commit()
    record(db, action="client.submit", actor=p.user, target_type="company", target_id=c.id,
           ip=getattr(request.state, "client_ip", ""))

    # Tell the operator team immediately — the report clock starts now.
    s = get_settings()
    hours = s.autorun_hours
    admins = [u.email for u in db.execute(select(User).where(
        User.role == Role.admin, User.is_active.is_(True))).scalars()]
    if admins:
        auto_line = (f"If nobody runs it, it auto-runs and goes to the customer in about "
                     f"{hours} hour(s)." if hours else "Auto-run is disabled — it waits for you.")
        _send_email(", ".join(admins),
                    f"Inputs submitted — {c.name}",
                    (f"{p.user.email} just submitted inputs for {c.name}.\n\n"
                     f"Review and run the assessment: {s.base_url}/companies/{c.id}\n\n"
                     f"{auto_line}\n"),
                    cfg=effective_email_config(db))

    eta = (f" Your report is typically ready within {hours} hour(s) — we'll notify you here "
           f"and by email the moment it is." if hours else
           " Your assessment team will prepare your report and notify you when it's ready.")
    return redirect("/workspace", f"Thank you — your inputs are submitted.{eta}")


@router.get("/workspace/questionnaire")
def questionnaire(request: Request, db: Session = Depends(get_db)):
    p, c = _client_company(request, db)
    rb = latest_rulebook(db)
    existing = {a.control_id: a for a in db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == c.id)).scalars()}
    cats = {x["id"]: x["name"] for x in rb["categories"]}
    from ..services.scan_service import unconfirmed_control_ids
    controls = rb["controls"]
    unconfirmed = unconfirmed_control_ids(db, c.id)
    filtered = request.query_params.get("only") == "unconfirmed" and unconfirmed is not None
    if filtered:
        controls = [x for x in controls if x["id"] in unconfirmed]
    return render(request, "questionnaire.html", c=c, controls=controls, cats=cats,
                  existing=existing, valid=sorted(VALID), back="/workspace",
                  action="/workspace/questionnaire", filtered=filtered,
                  full_link="/workspace/questionnaire",
                  unconfirmed_count=len(unconfirmed) if unconfirmed is not None else 0)


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
