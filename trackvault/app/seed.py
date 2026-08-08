"""Idempotent startup seeding: rulebooks, provider org, bootstrap admin."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from sqlalchemy import select

from .config import get_settings
from .db import SessionLocal
from .models import Organization, Role, Rulebook, User
from .security import hash_password

log = logging.getLogger("trackvault.seed")
_RULEBOOK_DIR = Path(__file__).resolve().parent.parent / "rulebooks"


def seed_rulebooks(db) -> None:
    have = {r.version for r in db.execute(select(Rulebook)).scalars()}
    for f in sorted(_RULEBOOK_DIR.glob("dpdpa-rulebook.v*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        v = data["rulebookVersion"]
        if v not in have:
            db.add(Rulebook(version=v, data=data, source="shipped"))
            log.info("seeded rulebook v%s", v)
    db.commit()


def seed_provider_and_admin(db) -> None:
    s = get_settings()
    org = db.execute(select(Organization).where(Organization.is_provider.is_(True))).scalar_one_or_none()
    if not org:
        org = Organization(name=f"{s.brand} (provider)", is_provider=True)
        db.add(org)
        db.commit()
        db.refresh(org)
    if db.execute(select(User)).first() is None:
        admin = User(organization_id=org.id, email=s.bootstrap_admin_email.lower(),
                     name="Bootstrap Admin", role=Role.admin,
                     password_hash=hash_password(s.bootstrap_admin_password),
                     must_change_password=True)
        db.add(admin)
        db.commit()
        log.warning("Created bootstrap admin %s — change the password on first login.",
                    s.bootstrap_admin_email)


def seed_all() -> None:
    db = SessionLocal()
    try:
        seed_rulebooks(db)
        seed_provider_and_admin(db)
    except Exception as ex:  # pragma: no cover - concurrent seeding is tolerated
        db.rollback()
        log.info("seed skipped/rolled back (likely already seeded): %s", ex)
    finally:
        db.close()


if __name__ == "__main__":
    seed_all()
    log.info("seeding complete")

