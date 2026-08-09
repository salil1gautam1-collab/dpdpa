"""Report rendering: client report, history, compare. Client or operator."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Company, Snapshot
from ..reporting import client_report
from ..services.rulebook_service import get_rulebook
from ..templating import render
from .helpers import require

router = APIRouter()


def _access(request: Request, db: Session, cid: str):
    p = require(request, db)
    c = db.get(Company, cid)
    if not c:
        raise HTTPException(404, "Company not found")
    if p.is_operator:
        if c.organization_id != p.user.organization_id:
            raise HTTPException(403, "Forbidden")
    elif p.user.company_id != cid:
        raise HTTPException(403, "Forbidden")
    return p, c


@router.get("/companies/{cid}/history")
def history(cid: str, request: Request, db: Session = Depends(get_db)):
    p, c = _access(request, db, cid)
    snaps = list(db.execute(select(Snapshot).where(Snapshot.company_id == cid)
                            .order_by(Snapshot.scan_id.desc())).scalars())
    back = f"/companies/{cid}" if p.is_operator else "/workspace"
    return render(request, "history.html", c=c, snaps=snaps, back=back)


@router.get("/companies/{cid}/report/{scan_id}")
def report(cid: str, scan_id: str, request: Request, db: Session = Depends(get_db)):
    p, c = _access(request, db, cid)
    snap = db.execute(select(Snapshot).where(Snapshot.company_id == cid,
                                             Snapshot.scan_id == scan_id)).scalar_one_or_none()
    if not snap:
        raise HTTPException(404, "Report not found")
    rb = get_rulebook(db, snap.rulebook_version)
    return HTMLResponse(client_report(snap.data, rb, list(c.sites or [])))


@router.get("/companies/{cid}/gap-assessment/{scan_id}")
def gap_assessment_view(cid: str, scan_id: str, request: Request, db: Session = Depends(get_db)):
    from ..reporting import gap_assessment
    p, c = _access(request, db, cid)
    snap = db.execute(select(Snapshot).where(Snapshot.company_id == cid,
                                             Snapshot.scan_id == scan_id)).scalar_one_or_none()
    if not snap:
        raise HTTPException(404, "Assessment not found")
    rb = get_rulebook(db, snap.rulebook_version)
    return HTMLResponse(gap_assessment(snap.data, rb, list(c.sites or [])))


@router.get("/companies/{cid}/compare")
def compare(cid: str, request: Request, a: str = "", b: str = "", db: Session = Depends(get_db)):
    p, c = _access(request, db, cid)
    sa = db.execute(select(Snapshot).where(Snapshot.company_id == cid, Snapshot.scan_id == a)).scalar_one_or_none()
    sb = db.execute(select(Snapshot).where(Snapshot.company_id == cid, Snapshot.scan_id == b)).scalar_one_or_none()
    if not sa or not sb:
        raise HTTPException(404, "Pick two valid reports")
    from ..domain.engine import summarize
    rank = {"COMPLIANT": 3, "PARTIAL": 2, "TBC": 1, "GAP": 0, "NA": 2}
    a_by = {r["controlId"]: r for r in sa.data["resolutions"]}
    b_by = {r["controlId"]: r for r in sb.data["resolutions"]}
    improved, regressed, newc = [], [], []
    for cid2, rb in b_by.items():
        ra = a_by.get(cid2)
        if ra is None:
            newc.append(rb); continue
        if ra["status"] != rb["status"]:
            row = (cid2, rb["title"], ra["status"], rb["status"])
            (improved if rank[rb["status"]] > rank[ra["status"]] else regressed).append(row)
    delta = round(summarize(sb.data)["complianceScore"] - summarize(sa.data)["complianceScore"], 1)
    return render(request, "compare.html", c=c, sa=sa, sb=sb, delta=delta,
                  improved=improved, regressed=regressed, newc=newc,
                  score_a=summarize(sa.data)["complianceScore"], score_b=summarize(sb.data)["complianceScore"],
                  back=(f"/companies/{cid}/history"))
