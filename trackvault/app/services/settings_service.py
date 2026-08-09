"""Runtime-editable settings, layered over the environment.

Secrets (SMTP host/port/user/password) always come from the environment and are
never editable from the UI. Operational switches (email on/off, sender address,
the test-recipient redirect) live in the database so an admin can change them
from the Settings page — effective immediately, no restart.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import AppSetting


def get_raw(db: Session, key: str) -> str | None:
    row = db.get(AppSetting, key)
    return row.value if row else None


def set_raw(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key)
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))
    db.commit()


# ---- Appearance / theme (app-wide, admin-controlled) ----
VALID_THEMES = ("dark", "light", "midnight")
DEFAULT_THEME = "dark"
# Short-TTL cache. The app runs multiple uvicorn workers, each its own process —
# a forever-cache in one worker would never see a save made through another, so
# the theme would look "stuck" for ~half of all requests. A few seconds of TTL
# keeps renders cheap while every worker converges almost immediately.
_THEME_TTL_SECONDS = 3.0
_theme_cache: dict = {"v": None, "at": 0.0}


def get_ui_theme(db: Session | None = None) -> str:
    """The app-wide theme the admin has chosen (default: dark)."""
    import time
    if db is not None:
        val = get_raw(db, "ui_theme")
        _theme_cache.update(v=val if val in VALID_THEMES else DEFAULT_THEME, at=time.monotonic())
        return _theme_cache["v"]
    now = time.monotonic()
    if _theme_cache["v"] is None or (now - _theme_cache["at"]) > _THEME_TTL_SECONDS:
        try:
            from ..db import SessionLocal
            with SessionLocal() as s:
                val = get_raw(s, "ui_theme")
            _theme_cache.update(v=val if val in VALID_THEMES else DEFAULT_THEME, at=now)
        except Exception:
            return _theme_cache["v"] or DEFAULT_THEME  # DB not ready — don't cache
    return _theme_cache["v"]


def set_ui_theme(db: Session, value: str) -> str:
    import time
    theme = value if value in VALID_THEMES else DEFAULT_THEME
    set_raw(db, "ui_theme", theme)
    _theme_cache.update(v=theme, at=time.monotonic())
    return theme


def effective_email_config(db: Session) -> dict:
    s = get_settings()
    en = get_raw(db, "email_enabled")
    tr = get_raw(db, "test_recipient")
    return {
        "enabled": (en != "false") if en is not None else True,
        "from_addr": (get_raw(db, "email_from") or s.smtp_from),
        "test_recipient": ((tr if tr is not None else s.test_recipient) or "").strip(),
        # secrets — env only
        "host": s.smtp_host, "port": s.smtp_port, "user": s.smtp_user, "password": s.smtp_pass,
    }


def smtp_ready(cfg: dict) -> bool:
    return bool(cfg.get("host") and cfg.get("password"))
