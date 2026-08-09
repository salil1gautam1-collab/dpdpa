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
_theme_cache: dict = {"v": None}


def get_ui_theme(db: Session | None = None) -> str:
    """The app-wide theme the admin has chosen (default: dark). Cached in-process
    and refreshed on save, so it's cheap to read on every page render."""
    if db is not None:
        val = get_raw(db, "ui_theme")
        _theme_cache["v"] = val if val in VALID_THEMES else DEFAULT_THEME
        return _theme_cache["v"]
    if _theme_cache["v"] is None:
        try:
            from ..db import SessionLocal
            with SessionLocal() as s:
                val = get_raw(s, "ui_theme")
            _theme_cache["v"] = val if val in VALID_THEMES else DEFAULT_THEME
        except Exception:
            return DEFAULT_THEME  # DB not ready — render dark, don't cache
    return _theme_cache["v"]


def set_ui_theme(db: Session, value: str) -> str:
    theme = value if value in VALID_THEMES else DEFAULT_THEME
    set_raw(db, "ui_theme", theme)
    _theme_cache["v"] = theme
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
