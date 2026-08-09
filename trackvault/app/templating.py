"""Jinja2 templating with security defaults and shared context."""
from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .config import get_settings

_env = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True, lstrip_blocks=True,
)
_settings = get_settings()


def _asset_stamp() -> str:
    """Content hash of the static assets (CSS + JS), used as a cache-buster
    (?v=...) so browsers fetch fresh copies whenever they actually change —
    including changes that ship without a version bump."""
    import hashlib
    h = hashlib.md5()
    found = False
    for name in ("app.css", "app.js"):
        try:
            h.update((Path(__file__).parent / "static" / name).read_bytes())
            found = True
        except OSError:
            pass
    return h.hexdigest()[:10] if found else __version__


_ASSET_STAMP = _asset_stamp()


def _client_unread(principal) -> int:
    """Unread-notification count for the nav badge (client logins only).
    One indexed COUNT per page render; fails safe to 0."""
    if not principal or not getattr(principal, "is_client", False):
        return 0
    company_id = getattr(principal.user, "company_id", None)
    if not company_id:
        return 0
    try:
        from sqlalchemy import func, select
        from .db import SessionLocal
        from .models import Notification
        with SessionLocal() as s:
            return s.execute(
                select(func.count()).select_from(Notification)
                .where(Notification.company_id == company_id,
                       Notification.read.is_(False))).scalar() or 0
    except Exception:
        return 0


def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    principal = getattr(request.state, "principal", None)
    from .services.settings_service import get_ui_theme
    base = {
        "request": request,
        "brand": _settings.brand,
        "version": __version__,
        "principal": principal,
        "user": principal.user if principal else None,
        "csrf": principal.session.csrf_token if principal else "",
        "flash": request.query_params.get("msg", ""),
        "flash_err": request.query_params.get("err") == "1",
        "ui_theme": get_ui_theme(),
        "asset_v": _ASSET_STAMP,
        "notif_unread": _client_unread(principal),
    }
    base.update(ctx)
    return HTMLResponse(_env.get_template(name).render(**base), status_code=status_code)
