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
    """Content hash of the stylesheet, used as a cache-buster (?v=...) so browsers
    fetch a fresh copy whenever the CSS actually changes — including changes that
    ship without a version bump."""
    import hashlib
    try:
        css = (Path(__file__).parent / "static" / "app.css").read_bytes()
        return hashlib.md5(css).hexdigest()[:10]
    except OSError:
        return __version__


_ASSET_STAMP = _asset_stamp()


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
    }
    base.update(ctx)
    return HTMLResponse(_env.get_template(name).render(**base), status_code=status_code)
