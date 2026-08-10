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
    "gcp": ("A <b>read-only</b> OAuth access token for the project — run "
            "<code>gcloud auth print-access-token</code> as an account with <b>Viewer</b> / "
            "<b>Security Reviewer</b>, and paste it with the Project ID. Note: this token is valid "
            "for <b>about 1 hour</b>, so generate it right before running the assessment. "
            "(Durable service-account-key support is on the roadmap.)"),
    "adgpo": ("<b>No credentials — nothing connects to your directory.</b> Your domain admin reads "
              "these values from Active Directory / Group Policy and fills in whatever they can "
              "confirm. Leave anything unknown blank — it simply shows as ‘to confirm’."),
    "firewall": ("<b>No credentials.</b> Export your firewall’s configuration/ruleset and paste the "
                 "text. It’s a <b>heuristic</b> read of common formats (Cisco IOS/ASA, iptables, "
                 "pfSense, Fortinet) — it flags permissive ‘any’ rules, exposed management ports, and "
                 "missing logging. Findings are advisory; confirm against the live ruleset."),
}

def _adgpo_json(form) -> str:
    """Assemble the AD/GPO scanner's JSON from the friendly form fields, so admins
    fill in labeled boxes instead of writing JSON. Blank fields are omitted (the
    scanner resolves missing keys to TBC). Returns "" if nothing was entered."""
    import json as _json

    def num(field):
        v = (form.get(field, "") or "").strip()
        return int(v) if v.lstrip("-").isdigit() else None

    def tri(field):  # yes / no / (blank = unknown -> omit)
        v = (form.get(field, "") or "").strip().lower()
        return True if v == "yes" else (False if v == "no" else None)

    pw = {}
    if num("pw_minLength") is not None:
        pw["minLength"] = num("pw_minLength")
    if tri("pw_complexity") is not None:
        pw["complexity"] = tri("pw_complexity")
    if num("pw_lockout") is not None:
        pw["lockoutThreshold"] = num("pw_lockout")
    if num("pw_maxAge") is not None:
        pw["maxPasswordAgeDays"] = num("pw_maxAge")
    priv = {}
    if num("priv_da") is not None:
        priv["Domain Admins"] = num("priv_da")
    if num("priv_ea") is not None:
        priv["Enterprise Admins"] = num("priv_ea")
    gpo = {}
    for field, key in (("gpo_screen", "screenLockConfigured"),
                       ("gpo_audit", "auditPolicyConfigured"),
                       ("gpo_usb", "usbStorageBlocked")):
        if tri(field) is not None:
            gpo[key] = tri(field)

    data = {}
    if pw:
        data["passwordPolicy"] = pw
    if num("totalUsers") is not None:
        data["totalUsers"] = num("totalUsers")
    if priv:
        data["privilegedGroups"] = priv
    if num("staleAccounts") is not None:
        data["staleAccounts"] = num("staleAccounts")
    if gpo:
        data["gpo"] = gpo
    return _json.dumps(data) if data else ""


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
    # Collect secret fields (keep existing if blank). AD/GPO is a friendly form,
    # not a JSON paste — assemble its JSON from the individual fields here.
    adgpo_json = _adgpo_json(form) if provider == "adgpo" else None
    secret = {}
    for sf in set(secret_fields + ([id_field] if id_field in secret_fields else [])):
        if provider == "adgpo" and sf == "collectorJson":
            val = adgpo_json or ""
        else:
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
        msg = ("Enter at least one value to save AD/GPO." if provider == "adgpo"
               else f"{FIELD_LABELS.get(id_field, id_field)} is required for {label}.")
        return redirect(f"/companies/{cid}/connectors", msg, err=True)

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
