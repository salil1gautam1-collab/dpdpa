"""Connector management — credentials encrypted at rest. Client or operator."""
from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import record
from ..crypto import decrypt_secret, encrypt_secret
from ..db import get_db
from ..models import Company, Connector, Role
from ..templating import render
from .helpers import check_csrf, redirect, require

router = APIRouter()

# provider -> (id_field, [secret_fields], [plain_fields], label)
SPECS = {
    "aws": ("accessKeyId", ["secretAccessKey"], ["region"], "Amazon Web Services"),
    "azure": ("clientId", ["clientSecret"], ["tenantId"], "Microsoft Azure"),
    "intune": ("clientId", ["clientSecret"], ["tenantId"], "Microsoft Intune / Defender"),
    "gcp": ("projectId", ["accessToken"], [], "Google Cloud"),
    "adgpo": ("collectorJson", ["collectorJson"], [], "Active Directory / GPO"),
    "firewall": ("configText", ["configText"], [], "Firewall configuration"),
}

# Human-friendly labels so the form never shows raw field names like "clientId".
FIELD_LABELS = {
    "accessKeyId": "Access key ID",
    "secretAccessKey": "Secret access key",
    "region": "Default region",
    "clientId": "Application (client) ID",
    "clientSecret": "Client secret",
    "tenantId": "Directory (tenant) ID",
    "projectId": "Project ID",
    "accessToken": "OAuth access token",
}

FIELD_PLACEHOLDERS = {
    "accessKeyId": "AKIA…",
    "secretAccessKey": "the secret half of the key pair",
    "region": "ap-south-1 (Mumbai)",
    "clientId": "00000000-0000-0000-0000-000000000000",
    "clientSecret": "the secret Value from ‘Certificates & secrets’",
    "tenantId": "00000000-0000-0000-0000-000000000000",
    "projectId": "my-gcp-project-id",
    "accessToken": "ya29.…  (from: gcloud auth print-access-token)",
}

# One plain-English line per connector: what the credential IS and how to get it.
# The recurring theme — read-only, and never a personal sign-in.
PROVIDER_HELP = {
    "aws": ("A <b>read-only</b> IAM access key — not your console login. In AWS: IAM → Users → "
            "add a user → attach the AWS-managed <b>SecurityAudit</b> (read-only) policy → create "
            "an access key. Paste its Access key ID + Secret access key below."),
    "azure": ("A <b>read-only Entra ID app registration</b> (a “service principal”) — <b>not</b> your "
              "Azure sign-in. Ask your admin to register an app, add a client secret, and grant it "
              "<b>Reader</b> + <b>Security Reader</b> on the subscription. Then paste the three values "
              "below."),
    "intune": ("The <b>same</b> Entra ID app registration as Azure can be used — it just also needs the "
               "Microsoft Graph application permission <b>DeviceManagementManagedDevices.Read.All</b> "
               "with admin consent. Paste the three values below. (Not your Microsoft sign-in.)"),
    "gcp": ("A short-lived <b>read-only</b> OAuth access token for the project — e.g. run "
            "<code>gcloud auth print-access-token</code> as an account with <b>Viewer</b> / "
            "<b>Security Reviewer</b>. Paste the Project ID and the token."),
    "adgpo": ("<b>No credentials.</b> Run your read-only AD/GPO collector and paste its JSON output "
              "here — nothing connects to your directory."),
    "firewall": ("<b>No credentials.</b> Export your firewall’s configuration/ruleset and paste the "
                 "text here."),
}


def _access(request: Request, db: Session, cid: str) -> tuple:
    p = require(request, db)
    c = db.get(Company, cid)
    if not c:
        raise HTTPException(404, "Company not found")
    if p.is_operator:
        if c.organization_id != p.user.organization_id:
            raise HTTPException(403, "Forbidden")
    elif p.user.company_id != cid:
        raise HTTPException(403, "Forbidden")
    return p, c


@router.get("/companies/{cid}/connectors")
def connectors_page(cid: str, request: Request, db: Session = Depends(get_db)):
    p, c = _access(request, db, cid)
    existing = {k.provider: k for k in c.connectors}
    # Build display-safe view (never expose secrets)
    view = {}
    for prov, conn in existing.items():
        idf = SPECS[prov][0]
        idv = (conn.public_config or {}).get(idf, "") or ("provided" if conn.secret_enc else "")
        view[prov] = {"connected": bool(conn.secret_enc) and (conn.consent or {}).get("granted"),
                      "id_hint": ("••••" + idv[-4:]) if len(idv) > 4 else "provided",
                      "region": (conn.public_config or {}).get("region", ""),
                      "tenantId": (conn.public_config or {}).get("tenantId", "")}
    return render(request, "connectors.html", c=c, specs=SPECS, view=view,
                  field_labels=FIELD_LABELS, field_placeholders=FIELD_PLACEHOLDERS,
                  provider_help=PROVIDER_HELP,
                  back=("/companies/" + cid) if p.is_operator else "/workspace")


@router.post("/companies/{cid}/connectors/{provider}")
async def save_connector(cid: str, provider: str, request: Request, db: Session = Depends(get_db)):
    p, c = _access(request, db, cid)
    if provider not in SPECS:
        raise HTTPException(404, "Unknown provider")
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    id_field, secret_fields, plain_fields, label = SPECS[provider]
    if not form.get("consent"):
        return redirect(f"/companies/{cid}/connectors", f"Tick the authorisation box to connect {label}.", err=True)
    conn = db.execute(select(Connector).where(Connector.company_id == cid,
                                              Connector.provider == provider)).scalar_one_or_none()
    old_secret = decrypt_secret(conn.secret_enc) if conn else {}
    old_public = (conn.public_config or {}) if conn else {}
    # Collect secret fields (keep existing if blank)
    secret = {}
    for sf in set(secret_fields + ([id_field] if id_field in secret_fields else [])):
        val = (form.get(sf, "") or "").strip()
        secret[sf] = val or old_secret.get(sf, "")
    # id field may be public (aws/azure) or secret (adgpo/firewall)
    public = dict(old_public)
    if id_field not in secret_fields:
        public[id_field] = (form.get(id_field, "") or "").strip() or old_public.get(id_field, "")
    for pf in plain_fields:
        public[pf] = (form.get(pf, "") or "").strip() or old_public.get(pf, "")
    id_present = (public.get(id_field) if id_field not in secret_fields else secret.get(id_field))
    if not id_present:
        return redirect(f"/companies/{cid}/connectors", f"{id_field} is required for {label}.", err=True)

    consent = {"granted": True, "grantedBy": (c.contact or p.user.email), "date": date.today().isoformat()}
    if conn:
        conn.secret_enc = encrypt_secret(secret)
        conn.public_config = public
        conn.consent = consent
    else:
        conn = Connector(company_id=cid, provider=provider, secret_enc=encrypt_secret(secret),
                         public_config=public, consent=consent)
        db.add(conn)
    db.commit()
    record(db, action="connector.save", actor=p.user, target_type="company", target_id=cid,
           ip=getattr(request.state, "client_ip", ""), provider=provider)
    return redirect(f"/companies/{cid}/connectors", f"{label} connected (credentials encrypted).")


@router.post("/companies/{cid}/connectors/{provider}/disconnect")
async def disconnect(cid: str, provider: str, request: Request, db: Session = Depends(get_db)):
    p, c = _access(request, db, cid)
    form = await request.form()
    check_csrf(p, form.get("csrf", ""))
    conn = db.execute(select(Connector).where(Connector.company_id == cid,
                                              Connector.provider == provider)).scalar_one_or_none()
    if conn:
        db.delete(conn)
        db.commit()
        record(db, action="connector.delete", actor=p.user, target_type="company", target_id=cid,
               ip=getattr(request.state, "client_ip", ""), provider=provider)
    return redirect(f"/companies/{cid}/connectors", f"{SPECS[provider][3]} disconnected and credentials deleted.")
