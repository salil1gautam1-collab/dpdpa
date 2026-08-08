"""Azure posture connector — read-only, consent-gated, stdlib only.

Access model: an Entra app registration (tenant id + client id + client secret)
granted the **Reader** and **Security Reader** roles on the subscription(s).
All calls are GETs against Azure Resource Manager / Microsoft Defender for Cloud.

Checks (docs/INFRA-SCANNER-SPEC.md):
  az_credentials_valid    token + list subscriptions
  az_storage_public       storage accounts: allowBlobPublicAccess = false
  az_storage_encryption   storage accounts: HTTPS-only + min TLS 1.2 + encryption
  az_nsg_exposure         NSG rules allowing * inbound on non-web ports
  az_defender_score       Defender for Cloud secure score
"""
from __future__ import annotations

from ..evidence import make_evidence
from .httpjson import get, error_summary
from .msauth import get_token

ARM = "https://management.azure.com"


def run_checks(conn: dict) -> tuple[list, dict]:
    findings: list = []
    meta: dict = {}

    def finding(cid, status, excerpt, note=""):
        findings.append({"webCheckId": cid, "site": "azure", "status": status,
                         "evidence": [make_evidence("azure-api", url=f"azure://{cid}",
                                                    excerpt=excerpt, note=note)]})

    token, err = get_token(conn.get("tenantId", ""), conn.get("clientId", ""),
                           conn.get("clientSecret", ""), ARM + "/.default")
    if not token:
        finding("az_credentials_valid", "gap", err,
                "app registration invalid or lacks Reader role — Azure checks skipped")
        return findings, meta
    hdr = {"Authorization": f"Bearer {token}"}

    code, data, raw = get(f"{ARM}/subscriptions?api-version=2020-01-01", hdr)
    subs = [s["subscriptionId"] for s in data.get("value", [])] if code == 200 and isinstance(data, dict) else []
    meta["azureSubscriptions"] = len(subs)
    if not subs:
        finding("az_credentials_valid", "partial",
                f"token acquired but no subscriptions visible (HTTP {code}): {error_summary(data, raw)}",
                "grant the app the Reader role on the target subscription(s)")
        return findings, meta
    finding("az_credentials_valid", "ok", f"connected; {len(subs)} subscription(s) visible")

    pub_bad, enc_bad, sa_total = [], [], 0
    nsg_exposed = []
    for sub in subs[:5]:
        code, data, raw = get(f"{ARM}/subscriptions/{sub}/providers/Microsoft.Storage/"
                              f"storageAccounts?api-version=2023-01-01", hdr)
        for sa in (data.get("value", []) if isinstance(data, dict) else []):
            sa_total += 1
            props = sa.get("properties", {})
            if props.get("allowBlobPublicAccess", True):
                pub_bad.append(sa.get("name", "?"))
            if not props.get("supportsHttpsTrafficOnly", False) or props.get("minimumTlsVersion", "") in ("", "TLS1_0", "TLS1_1"):
                enc_bad.append(sa.get("name", "?"))

        code, data, raw = get(f"{ARM}/subscriptions/{sub}/providers/Microsoft.Network/"
                              f"networkSecurityGroups?api-version=2023-05-01", hdr)
        for nsg in (data.get("value", []) if isinstance(data, dict) else []):
            for rule in nsg.get("properties", {}).get("securityRules", []):
                p = rule.get("properties", {})
                src = p.get("sourceAddressPrefix", "")
                ports = [p.get("destinationPortRange", "")] + p.get("destinationPortRanges", [])
                if (p.get("access") == "Allow" and p.get("direction") == "Inbound"
                        and src in ("*", "0.0.0.0/0", "Internet")
                        and not set(filter(None, ports)) <= {"80", "443"}):
                    nsg_exposed.append(f"{nsg.get('name','?')}:{rule.get('name','?')}")

    if sa_total == 0:
        finding("az_storage_public", "na", "no storage accounts found")
        finding("az_storage_encryption", "na", "no storage accounts found")
    else:
        finding("az_storage_public", "gap" if pub_bad else "ok",
                f"{sa_total} storage accounts; blob public access allowed on: {pub_bad or 'none'}")
        finding("az_storage_encryption", "gap" if enc_bad else "ok",
                f"storage accounts without HTTPS-only + TLS>=1.2: {enc_bad or 'none'}")
    finding("az_nsg_exposure", "gap" if nsg_exposed else "ok",
            f"NSG rules allowing internet inbound on non-web ports: {sorted(set(nsg_exposed))[:20] or 'none'}")

    # Defender for Cloud secure score (Security Reader)
    code, data, raw = get(f"{ARM}/subscriptions/{subs[0]}/providers/Microsoft.Security/"
                          f"secureScores/ascScore?api-version=2020-01-01", hdr)
    if code == 200 and isinstance(data, dict):
        props = data.get("properties", {})
        pct = round(100 * props.get("score", {}).get("current", 0) / (props.get("score", {}).get("max", 1) or 1))
        finding("az_defender_score", "ok" if pct >= 70 else ("partial" if pct >= 40 else "gap"),
                f"Defender for Cloud secure score: {pct}%")
    else:
        finding("az_defender_score", "unknown",
                f"secure score unavailable (HTTP {code}): {error_summary(data, raw)}",
                "enable Microsoft Defender for Cloud and grant Security Reader for this check")
    return findings, meta
