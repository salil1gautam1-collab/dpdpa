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


def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    principal = getattr(request.state, "principal", None)
    base = {
        "request": request,
        "brand": _settings.brand,
        "version": __version__,
        "principal": principal,
        "user": principal.user if principal else None,
        "csrf": principal.session.csrf_token if principal else "",
        "flash": request.query_params.get("msg", ""),
        "flash_err": request.query_params.get("err") == "1",
    }
    base.update(ctx)
    return HTMLResponse(_env.get_template(name).render(**base), status_code=status_code)
