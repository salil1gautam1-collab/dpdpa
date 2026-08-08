"""Shared router helpers: principal attachment, CSRF, redirects."""
from __future__ import annotations

import secrets
from urllib.parse import quote

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..security import Principal, _load_principal


def attach_principal(request: Request, db: Session) -> Principal | None:
    p = _load_principal(request, db)
    request.state.principal = p
    return p


def require(request: Request, db: Session, *, operator: bool = False, client: bool = False,
            roles: set | None = None) -> Principal:
    p = attach_principal(request, db)
    if not p:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    if operator and not p.is_operator:
        raise HTTPException(status_code=403, detail="Operator access required")
    if client and not p.is_client:
        raise HTTPException(status_code=403, detail="Client access only")
    if roles and p.user.role not in roles:
        raise HTTPException(status_code=403, detail="Insufficient role")
    return p


def check_csrf(p: Principal, token: str) -> None:
    if not token or not secrets.compare_digest(token, p.session.csrf_token):
        raise HTTPException(status_code=403, detail="CSRF token invalid")


def redirect(path: str, msg: str = "", err: bool = False) -> RedirectResponse:
    if msg:
        sep = "&" if "?" in path else "?"
        path = f"{path}{sep}msg={quote(msg)}" + ("&err=1" if err else "")
    return RedirectResponse(path, status_code=303)
