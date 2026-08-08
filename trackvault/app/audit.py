"""Append-only audit logging helper."""
from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditLog


def record(db: Session, *, action: str, actor=None, target_type: str = "",
           target_id: str = "", ip: str = "", **detail) -> None:
    entry = AuditLog(
        action=action,
        actor_id=getattr(actor, "id", "") if actor else "",
        actor_email=getattr(actor, "email", "") if actor else "",
        actor_role=getattr(getattr(actor, "role", None), "value", "") if actor else "",
        target_type=target_type, target_id=target_id, ip=ip, detail=detail or {},
    )
    db.add(entry)
    db.commit()
