"""Rulebook access — versioned, stored in the database."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Rulebook


def _version_key(v: str):
    return [int(p) if p.isdigit() else 0 for p in v.split(".")]


def all_rulebooks(db: Session) -> list[Rulebook]:
    rbs = list(db.execute(select(Rulebook)).scalars())
    return sorted(rbs, key=lambda r: _version_key(r.version))


def latest_rulebook(db: Session) -> dict:
    rbs = all_rulebooks(db)
    if not rbs:
        raise RuntimeError("No rulebook loaded")
    return rbs[-1].data


def get_rulebook(db: Session, version: str | None) -> dict:
    if not version:
        return latest_rulebook(db)
    row = db.execute(select(Rulebook).where(Rulebook.version == version)).scalar_one_or_none()
    if not row:
        raise ValueError(f"Rulebook version {version} not found")
    return row.data
