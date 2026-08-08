"""Authentication: login, logout, forced password change."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import record
from ..config import get_settings
from ..db import get_db
from ..models import Role, User
from ..security import (SESSION_COOKIE, create_session, hash_password, needs_rehash,
                        revoke_session, verify_password)
from ..templating import render
from .helpers import attach_principal, check_csrf, redirect

router = APIRouter()
_s = get_settings()


@router.get("/")
def home(request: Request, db: Session = Depends(get_db)):
    p = attach_principal(request, db)
    if p and p.is_operator:
        return RedirectResponse("/dashboard", status_code=307)
    if p and p.is_client:
        return RedirectResponse("/workspace", status_code=307)
    return render(request, "landing.html")


@router.get("/login")
def login_form(request: Request, db: Session = Depends(get_db)):
    attach_principal(request, db)
    return render(request, "login.html")


@router.post("/auth/login")
def login(request: Request, email: str = Form(...), password: str = Form(...),
          db: Session = Depends(get_db)):
    ip = getattr(request.state, "client_ip", "")
    user = db.execute(select(User).where(User.email == email.strip().lower())).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if user and user.locked_until and user.locked_until > now:
        record(db, action="login.locked", actor=user, ip=ip)
        return render(request, "login.html", error="Account temporarily locked. Try again later.")
    if not user or not user.is_active or not verify_password(user.password_hash, password):
        if user:
            user.failed_logins += 1
            if user.failed_logins >= _s.lockout_threshold:
                user.locked_until = now + timedelta(minutes=_s.lockout_minutes)
                user.failed_logins = 0
            db.commit()
            record(db, action="login.fail", actor=user, ip=ip)
        return render(request, "login.html", error="Email or password incorrect.")

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    db.commit()
    raw, _ = create_session(db, user, ip=ip)
    record(db, action="login.success", actor=user, ip=ip)
    dest = "/auth/change-password" if user.must_change_password else (
        "/dashboard" if user.role in {Role.admin, Role.cs, Role.legal, Role.analyst, Role.viewer} else "/workspace")
    resp = RedirectResponse(dest, status_code=303)
    resp.set_cookie(SESSION_COOKIE, raw, httponly=True, samesite="lax",
                    secure=_s.is_production, max_age=_s.session_ttl_hours * 3600, path="/")
    return resp


@router.post("/auth/logout")
def logout(request: Request, csrf: str = Form(""), db: Session = Depends(get_db)):
    p = attach_principal(request, db)
    if p:
        check_csrf(p, csrf)
        raw = request.cookies.get(SESSION_COOKIE, "")
        revoke_session(db, raw)
        record(db, action="logout", actor=p.user, ip=getattr(request.state, "client_ip", ""))
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/auth/change-password")
def change_form(request: Request, db: Session = Depends(get_db)):
    p = attach_principal(request, db)
    if not p:
        return RedirectResponse("/login", status_code=307)
    return render(request, "change_password.html")


@router.post("/auth/change-password")
def change_password(request: Request, csrf: str = Form(""), current: str = Form(...),
                    new_password: str = Form(...), db: Session = Depends(get_db)):
    p = attach_principal(request, db)
    if not p:
        return RedirectResponse("/login", status_code=307)
    check_csrf(p, csrf)
    if not verify_password(p.user.password_hash, current):
        return render(request, "change_password.html", error="Current password is incorrect.")
    if len(new_password) < 12:
        return render(request, "change_password.html", error="New password must be at least 12 characters.")
    p.user.password_hash = hash_password(new_password)
    p.user.must_change_password = False
    db.commit()
    record(db, action="password.change", actor=p.user, ip=getattr(request.state, "client_ip", ""))
    dest = "/dashboard" if p.is_operator else "/workspace"
    return redirect(dest, "Password changed.")
