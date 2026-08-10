"""Public, tokenised connector self-setup for a customer's IT admin.

No login — the private link's token is the authorisation. The admin enters
read-only credentials directly (stored encrypted), and a live read-only check
confirms it worked. Rate-limited by the global middleware like every route.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Company, Connector
from ..templating import render
from .connectors import (FIELD_LABELS, FIELD_PLACEHOLDERS, PROVIDER_HELP, SPECS,
                         apply_connector_form)
from .helpers import redirect
from ..services.access_request import resolve, test_connection

router = APIRouter()


def _view(db: Session, company_id: str) -> dict:
    view = {}
    for conn in db.execute(select(Connector).where(Connector.company_id == company_id)).scalars():
        idf = SPECS.get(conn.provider, ("",))[0]
        idv = (conn.public_config or {}).get(idf, "") or ("provided" if conn.secret_enc else "")
        view[conn.provider] = {
            "connected": bool(conn.secret_enc),
            "id_hint": ("••••" + idv[-4:]) if len(idv) > 4 else "provided",
            "region": (conn.public_config or {}).get("region", ""),
            "tenantId": (conn.public_config or {}).get("tenantId", ""),
        }
    return view


@router.get("/setup/{token}")
def setup_page(token: str, request: Request, db: Session = Depends(get_db)):
    ar = resolve(db, token)
    if not ar:
        return render(request, "setup_invalid.html", status_code=404)
    c = db.get(Company, ar.company_id)
    providers = [p for p in ar.providers if p in SPECS]
    return render(request, "setup.html", token=token, c=c, providers=providers,
                  specs=SPECS, field_labels=FIELD_LABELS, field_placeholders=FIELD_PLACEHOLDERS,
                  provider_help=PROVIDER_HELP, view=_view(db, c.id))


@router.post("/setup/{token}/{provider}")
async def setup_save(token: str, provider: str, request: Request, db: Session = Depends(get_db)):
    ar = resolve(db, token)
    if not ar:
        raise HTTPException(404, "This setup link is invalid or has expired.")
    if provider not in ar.providers:
        raise HTTPException(404, "That connector was not part of this request.")
    c = db.get(Company, ar.company_id)
    form = await request.form()
    ok, msg = apply_connector_form(db, c, provider, form, granted_by=f"{c.name} IT (via setup link)")
    if not ok:
        return redirect(f"/setup/{token}", msg, err=True)
    # Immediately prove it with a live read-only check.
    tested_ok, test_msg = test_connection(db, c, provider)
    from ..audit import record
    record(db, action="connector.setup", actor=None, target_type="company", target_id=c.id,
           ip=getattr(request.state, "client_ip", ""), provider=provider, verified=tested_ok)
    return redirect(f"/setup/{token}", test_msg, err=not tested_ok)
