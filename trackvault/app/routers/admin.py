"""Admin: user management, rulebook import (CS/Legal), audit trail."""
from __future__ import annotations

import json
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import record
from ..db import get_db
from ..models import (AuditLog, Company, Organization, RULEBOOK_ROLES, Role, Rulebook, User)
from ..security import hash_password
from ..services.rulebook_service import all_rulebooks, latest_rulebook
from ..templating import render
from .helpers import check_csrf, redirect, require


router = APIRouter()


# ---- Users (admin only) ----
@router.get("/admin/users")
def users_page(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin})
    users = list(db.execute(select(User).where(User.organization_id == p.user.organization_id)
                            .order_by(User.role, User.email)).scalars())
    return render(request, "admin_users.html", users=users, roles=[r.value for r in Role])


@router.post("/admin/users/create")
async def create_user_post(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin})
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    email = (form.get("email", "") or "").strip().lower()
    role = form.get("role", "")
    if not email or "@" not in email or role not in {r.value for r in Role}:
        return redirect("/admin/users", "Valid email and role required.", err=True)
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        return redirect("/admin/users", "That email already exists.", err=True)
    import secrets
    temp = "Tv-" + secrets.token_urlsafe(9)
    u = User(organization_id=p.user.organization_id, email=email, name=form.get("name", ""),
             role=Role(role), password_hash=hash_password(temp), must_change_password=True)
    db.add(u)
    db.commit()
    record(db, action="user.create", actor=p.user, target_type="user", target_id=u.id,
           ip=getattr(request.state, "client_ip", ""), email=email, role=role)
    return redirect("/admin/users", f"User {email} ({role}) created. Temporary password: {temp}")


@router.post("/admin/users/{uid}/toggle")
async def toggle_user(uid: str, request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin})
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    u = db.get(User, uid)
    if u and u.organization_id == p.user.organization_id and u.id != p.user.id:
        u.is_active = not u.is_active
        db.commit()
        record(db, action="user.toggle", actor=p.user, target_type="user", target_id=uid,
               ip=getattr(request.state, "client_ip", ""), active=u.is_active)
    return redirect("/admin/users", "User updated.")


# ---- Rulebook (admin / CS / legal) ----
@router.get("/admin/rulebook")
def rulebook_page(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles=RULEBOOK_ROLES)
    books = all_rulebooks(db)
    current = books[-1] if books else None

    def bump(v):
        try:
            return f"{int(v.split('.')[0]) + 1}.0.0"
        except Exception:
            return "5.0.0"
    cats = current.data.get("categories", []) if current else []
    return render(request, "admin_rulebook.html", books=list(reversed(books)),
                  current=current, next_version=bump(current.version) if current else "1.0.0",
                  categories=cats, severities=["critical", "high", "medium", "low"],
                  methods=["questionnaire", "evidence", "hybrid", "web"])


@router.post("/admin/rulebook/add-checkpoint")
async def rulebook_add_checkpoint(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles=RULEBOOK_ROLES)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    version = (form.get("version", "") or "").strip()
    cid = (form.get("id", "") or "").strip().upper()
    control = {
        "id": cid,
        "category": (form.get("category", "") or "").strip(),
        "severity": (form.get("severity", "") or "medium").strip(),
        "title": (form.get("title", "") or "").strip(),
        "legalRef": (form.get("legalRef", "") or "").strip(),
        "description": (form.get("description", "") or "").strip(),
        "checkMethod": (form.get("checkMethod", "") or "questionnaire").strip(),
        "evidenceRequired": (form.get("evidenceRequired", "") or "").strip(),
        "remediation": (form.get("remediation", "") or "").strip(),
        "appAssist": {"possible": bool(form.get("appAssist")),
                      "how": (form.get("appAssistHow", "") or "").strip()},
    }
    try:
        if not cid or not control["title"] or not control["category"]:
            raise ValueError("id, title and category are required")
        rb = json.loads(json.dumps(latest_rulebook(db)))
        if cid in {c["id"] for c in rb["controls"]}:
            raise ValueError(f"control id {cid} already exists")
        if control["category"] not in {c["id"] for c in rb["categories"]}:
            raise ValueError(f"unknown category {control['category']}")
        if not version or db.execute(select(Rulebook).where(Rulebook.version == version)).scalar_one_or_none():
            raise ValueError("provide a new, unused version number")
        rb["rulebookVersion"] = version
        rb["lastUpdated"] = date.today().isoformat()
        rb["updateNote"] = (form.get("note", "") or f"Added checkpoint {cid}.").strip()
        rb["controls"].append(control)
        db.add(Rulebook(version=version, data=rb, source="imported", imported_by=p.user.email))
        db.commit()
        record(db, action="rulebook.add_checkpoint", actor=p.user, target_type="rulebook",
               target_id=version, ip=getattr(request.state, "client_ip", ""), control=cid)
        return redirect("/admin/rulebook", f"Published rulebook v{version} with new checkpoint {cid}.")
    except (json.JSONDecodeError, ValueError) as ex:
        return redirect("/admin/rulebook", f"Could not add checkpoint: {ex}", err=True)


@router.post("/admin/rulebook/append")
async def rulebook_append(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles=RULEBOOK_ROLES)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    version = (form.get("version", "") or "").strip()
    note = (form.get("note", "") or "").strip()
    try:
        new_controls = json.loads(form.get("controls", "") or "[]")
        if not isinstance(new_controls, list) or not new_controls:
            raise ValueError("controls must be a non-empty JSON array")
        for c in new_controls:
            for req in ("id", "category", "severity", "title", "checkMethod"):
                if req not in c:
                    raise ValueError(f"a control is missing '{req}'")
        if not version or db.execute(select(Rulebook).where(Rulebook.version == version)).scalar_one_or_none():
            raise ValueError("provide a new, unused version number")
        rb = json.loads(json.dumps(latest_rulebook(db)))
        ids = {c["id"] for c in rb["controls"]}
        dup = [c["id"] for c in new_controls if c["id"] in ids]
        if dup:
            raise ValueError(f"control id(s) already exist: {dup}")
        rb["rulebookVersion"] = version
        rb["lastUpdated"] = date.today().isoformat()
        rb["updateNote"] = note or f"Appended {len(new_controls)} control(s)."
        rb["controls"].extend(new_controls)
        db.add(Rulebook(version=version, data=rb, source="imported", imported_by=p.user.email))
        db.commit()
        record(db, action="rulebook.append", actor=p.user, target_type="rulebook", target_id=version,
               ip=getattr(request.state, "client_ip", ""), added=len(new_controls))
        return redirect("/admin/rulebook", f"Published rulebook v{version} (+{len(new_controls)}). "
                        "Re-run a company's assessment to apply it.")
    except (json.JSONDecodeError, ValueError) as ex:
        return redirect("/admin/rulebook", f"Import failed: {ex}", err=True)


@router.post("/admin/rulebook/import")
async def rulebook_import(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles=RULEBOOK_ROLES)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    try:
        rb = json.loads(form.get("rulebook", "") or "{}")
        if not rb.get("rulebookVersion") or not isinstance(rb.get("controls"), list) or not rb["controls"]:
            raise ValueError("rulebook needs rulebookVersion and a non-empty controls array")
        rb.setdefault("categories", [])
        v = rb["rulebookVersion"]
        if db.execute(select(Rulebook).where(Rulebook.version == v)).scalar_one_or_none():
            raise ValueError(f"version {v} already exists")
        db.add(Rulebook(version=v, data=rb, source="imported", imported_by=p.user.email))
        db.commit()
        record(db, action="rulebook.import", actor=p.user, target_type="rulebook", target_id=v,
               ip=getattr(request.state, "client_ip", ""))
        return redirect("/admin/rulebook", f"Imported rulebook v{v} ({len(rb['controls'])} controls).")
    except (json.JSONDecodeError, ValueError) as ex:
        return redirect("/admin/rulebook", f"Import failed: {ex}", err=True)


# ---- Blank questionnaire template ----
@router.get("/admin/questionnaire-template.xlsx")
def blank_template(request: Request, db: Session = Depends(get_db)):
    from fastapi.responses import Response
    from ..config import get_settings
    from ..services.template_service import build_template
    require(request, db, operator=True)
    data = build_template(latest_rulebook(db), get_settings().brand)
    return Response(content=data,
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": 'attachment; filename="DPDPA-Questionnaire-Template.xlsx"'})


# ---- Settings (admin) ----
@router.get("/admin/settings")
def settings_page(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin})
    from ..services.settings_service import effective_email_config, smtp_ready, get_ui_theme, VALID_THEMES
    cfg = effective_email_config(db)
    return render(request, "admin_settings.html", cfg=cfg, smtp_ready=smtp_ready(cfg),
                  ui_theme=get_ui_theme(db), themes=VALID_THEMES)


@router.post("/admin/settings/theme")
async def save_theme(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin})
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    from ..services.settings_service import set_ui_theme
    theme = set_ui_theme(db, (form.get("ui_theme", "") or "").strip())
    record(db, action="settings.theme", actor=p.user, target_type="settings", target_id="theme",
           ip=getattr(request.state, "client_ip", ""), theme=theme)
    return redirect("/admin/settings", f"Appearance set to {theme.title()}.")


@router.post("/admin/settings")
async def save_settings(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin})
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    from ..services.settings_service import set_raw
    set_raw(db, "email_enabled", "true" if form.get("email_enabled") else "false")
    set_raw(db, "email_from", (form.get("email_from", "") or "").strip())
    set_raw(db, "test_recipient", (form.get("test_recipient", "") or "").strip())
    record(db, action="settings.update", actor=p.user, target_type="settings", target_id="email",
           ip=getattr(request.state, "client_ip", ""),
           email_enabled=bool(form.get("email_enabled")),
           test_recipient=bool((form.get("test_recipient", "") or "").strip()))
    return redirect("/admin/settings", "Settings saved — effective immediately.")


# ---- Audit (admin) ----
@router.get("/admin/audit")
def audit_page(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin})
    entries = list(db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(200)).scalars())
    return render(request, "admin_audit.html", entries=entries)


# ---- Email delivery log (admin) ----
@router.get("/admin/outbox")
def outbox_page(request: Request, db: Session = Depends(get_db)):
    p = require(request, db, roles={Role.admin})
    from ..models import Notification, Company
    from ..services.settings_service import effective_email_config, smtp_ready
    rows = list(db.execute(select(Notification).where(Notification.email_to != "")
                           .order_by(Notification.created_at.desc()).limit(150)).scalars())
    names = {c.id: c.name for c in db.execute(select(Company)).scalars()}
    cfg = effective_email_config(db)
    mode = ("LIVE" if (smtp_ready(cfg) and cfg["enabled"]) else
            ("OFF" if not cfg["enabled"] else "SIMULATED"))
    if cfg["test_recipient"]:
        mode += f" · redirected to {cfg['test_recipient']}"
    return render(request, "admin_outbox.html", rows=rows, names=names, mode=mode)
