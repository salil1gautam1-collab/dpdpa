"""Company lifecycle: export (DPDPA data portability) and erasure.

One code path for erasure, used by both the admin UI and `python -m app.ops
erase` — so the CLI and the button can never drift apart.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import (AuditLog, Company, Connector, ImportJob, Notification,
                      QuestionnaireAnswer, Snapshot, User)


def export_company(db: Session, company: Company) -> bytes:
    """Everything the platform holds about a company, as one JSON document.
    Connector SECRETS are deliberately excluded — credentials are never exported."""
    answers = list(db.execute(select(QuestionnaireAnswer)
                              .where(QuestionnaireAnswer.company_id == company.id)
                              .order_by(QuestionnaireAnswer.control_id)).scalars())
    snaps = list(db.execute(select(Snapshot).where(Snapshot.company_id == company.id)
                            .order_by(Snapshot.scan_id)).scalars())
    notes = list(db.execute(select(Notification).where(Notification.company_id == company.id)
                            .order_by(Notification.created_at)).scalars())
    conns = list(db.execute(select(Connector).where(Connector.company_id == company.id)).scalars())
    clients = list(db.execute(select(User).where(User.company_id == company.id)).scalars())

    doc = {
        "exportedAt": datetime.now(timezone.utc).isoformat(),
        "format": "trackvault-company-export/1",
        "note": ("Complete export of this company's data held by the platform. "
                 "Connector credentials are never exported."),
        "company": {
            "name": company.name, "slug": company.slug, "sites": list(company.sites or []),
            "scanConsent": company.scan_consent, "monitorFrequency": company.monitor_frequency,
            "createdAt": company.created_at.isoformat() if company.created_at else None,
        },
        "clientLogins": [{"email": u.email, "active": u.is_active,
                          "lastLogin": u.last_login_at.isoformat() if u.last_login_at else None}
                         for u in clients],
        "questionnaireAnswers": [{"controlId": a.control_id, "status": a.status,
                                  "evidence": a.evidence, "department": a.department}
                                 for a in answers],
        "assessments": [{"scanId": s.scan_id, "rulebookVersion": s.rulebook_version,
                         "score": s.score, "counts": s.counts, "data": s.data}
                        for s in snaps],
        "notifications": [{"at": n.created_at.isoformat(), "type": n.ntype, "title": n.title,
                           "emailTo": n.email_to, "emailStatus": n.email_status}
                          for n in notes],
        "connectors": [{"provider": c.provider, "publicConfig": c.public_config,
                        "consent": c.consent} for c in conns],
    }
    return json.dumps(doc, indent=1, ensure_ascii=False).encode("utf-8")


def erase_company(db: Session, company_id: str, *, reason: str, actor_email: str = "") -> str:
    """DPDPA erasure: remove a company and every trace of its data.
    Returns the erased company's name. Raises ValueError if not found."""
    c = db.get(Company, company_id)
    if not c:
        raise ValueError("company not found")
    name = c.name
    from ..models import AssessJob, UserSession
    # FK-safe order: sessions -> users -> company-scoped rows -> the company.
    user_ids = select(User.id).where(User.company_id == company_id)
    db.execute(delete(UserSession).where(UserSession.user_id.in_(user_ids)))
    db.execute(delete(User).where(User.company_id == company_id))
    for model in (Snapshot, Connector, QuestionnaireAnswer, Notification, ImportJob, AssessJob):
        db.execute(delete(model).where(model.company_id == company_id))
    db.add(AuditLog(actor_email=actor_email, action="company.erase", target_type="company",
                    target_id=company_id, detail={"name": name, "reason": reason}))
    db.delete(c)
    db.commit()
    return name
