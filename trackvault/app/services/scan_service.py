"""Assessment orchestration — DB-backed, secret-decrypting, snapshot-persisting.

Replaces the prototype's file-based run_scan + infra dispatch. Credentials are
decrypted in memory only for the duration of the scan.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..crypto import decrypt_secret
from ..domain import engine
from ..domain.evidence import make_evidence, mask_pii, utc_now
from ..domain.scanners import web
from ..models import Company, Connector, QuestionnaireAnswer, Snapshot
from .rulebook_service import latest_rulebook

# provider -> scanner module import path
_SCANNERS = {
    "aws": "app.domain.scanners.aws",
    "azure": "app.domain.scanners.azure",
    "intune": "app.domain.scanners.intune",
    "gcp": "app.domain.scanners.gcp",
    "adgpo": "app.domain.scanners.adgpo",
    "firewall": "app.domain.scanners.firewall",
}


def _assertions(db: Session, company_id: str) -> dict:
    out = {}
    rows = db.execute(select(QuestionnaireAnswer).where(
        QuestionnaireAnswer.company_id == company_id)).scalars()
    for r in rows:
        if r.status not in ("COMPLIANT", "PARTIAL", "GAP", "NA", "TBC"):
            continue
        out[r.control_id] = {
            "status": r.status,
            "evidence": [make_evidence("declaration", excerpt=mask_pii(r.evidence or ""),
                                       note=f"declared by {r.department or '?'}")],
        }
    return out


def run_assessment(db: Session, company: Company, *, skip_web: bool = False,
                   actor_email: str = "") -> Snapshot:
    rb = latest_rulebook(db)
    started = utc_now()
    findings: list = []
    meta: dict = {}

    # 1. Website scan (consent-gated)
    consent = company.scan_consent or {}
    if not skip_web and company.sites and consent.get("granted"):
        f, m = web.run(list(company.sites))
        findings += f
        meta.update(m)
    elif not skip_web and company.sites and not consent.get("granted"):
        meta["webScanner"] = "skipped — no scan consent"
    else:
        meta["webScanner"] = "skipped"

    # 2. Infra/cloud connectors (decrypt in memory)
    for conn in company.connectors:
        prov = conn.provider
        if prov not in _SCANNERS or not (conn.consent or {}).get("granted"):
            meta[f"{prov}Connector"] = "configured but not consented" if conn.consent is not None else "skipped"
            continue
        creds = {**(conn.public_config or {}), **decrypt_secret(conn.secret_enc), "consent": conn.consent}
        mod = __import__(_SCANNERS[prov], fromlist=["run_checks"])
        try:
            f, m = mod.run_checks(creds)
            findings += f
            meta.update(m)
            meta[f"{prov}Connector"] = "ran"
        except Exception as ex:  # pragma: no cover - defensive
            meta[f"{prov}Connector"] = f"error: {type(ex).__name__}"

    # 3. Resolve controls
    assertions = _assertions(db, company.id)
    overrides = company.applicability_overrides or {}
    web_by_check: dict = {}
    for fnd in findings:
        web_by_check.setdefault(fnd.get("webCheckId"), []).append(fnd)

    resolutions = []
    for c in rb["controls"]:
        r = engine.resolve(c, web_by_check, assertions, overrides)
        r.update(title=c["title"], category=c["category"], severity=c["severity"],
                 legalRef=c["legalRef"], remediation=c["remediation"],
                 appAssist=c.get("appAssist", {}), checkMethod=c["checkMethod"],
                 controlHash=engine.control_hash(c))
        resolutions.append(r)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot_data = {
        "scanId": ts, "client": company.name, "slug": company.slug,
        "rulebookVersion": rb["rulebookVersion"], "startedAt": started,
        "finishedAt": utc_now(), "meta": meta, "resolutions": resolutions,
    }
    s = engine.summarize(snapshot_data)
    row = Snapshot(company_id=company.id, scan_id=ts, rulebook_version=rb["rulebookVersion"],
                   score=s["complianceScore"], counts=s["counts"], data=snapshot_data,
                   created_by=actor_email)
    db.add(row)
    company.pending_assessment = False
    db.commit()
    db.refresh(row)
    return row
