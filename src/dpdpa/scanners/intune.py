"""Endpoint & antivirus posture via Microsoft Intune / Defender (Graph API).

Access model: the same Entra app registration used for Azure, granted the
**application** permissions DeviceManagementManagedDevices.Read.All (and
optionally Device.Read.All), admin-consented. Read-only.

Answers the "how many laptops/servers, and are they protected" question:
  ep_credentials_valid    Graph token
  ep_device_inventory     device count + OS breakdown (Phase-1 estate inventory)
  ep_encryption           % of managed devices with disk encryption on
  ep_compliance           % of managed devices compliant with policy (AV, patching, etc.)
"""
from __future__ import annotations

from ..evidence import make_evidence
from .httpjson import get, error_summary
from .msauth import get_token

GRAPH = "https://graph.microsoft.com/v1.0"


def run_checks(conn: dict) -> tuple[list, dict]:
    findings: list = []
    meta: dict = {}

    def finding(cid, status, excerpt, note=""):
        findings.append({"webCheckId": cid, "site": "intune", "status": status,
                         "evidence": [make_evidence("graph-api", url=f"intune://{cid}",
                                                    excerpt=excerpt, note=note)]})

    token, err = get_token(conn.get("tenantId", ""), conn.get("clientId", ""),
                           conn.get("clientSecret", ""), "https://graph.microsoft.com/.default")
    if not token:
        finding("ep_credentials_valid", "gap", err,
                "app registration invalid or lacks Graph permissions — endpoint checks skipped")
        return findings, meta
    hdr = {"Authorization": f"Bearer {token}"}

    # Page through managed devices (politeness cap)
    devices, url = [], (f"{GRAPH}/deviceManagement/managedDevices?"
                        "$select=deviceName,operatingSystem,osVersion,complianceState,isEncrypted&$top=100")
    pages = 0
    while url and pages < 10:
        code, data, raw = get(url, hdr)
        if code != 200 or not isinstance(data, dict):
            if not devices:
                finding("ep_credentials_valid", "partial",
                        f"token acquired but managedDevices unavailable (HTTP {code}): {error_summary(data, raw)}",
                        "grant DeviceManagementManagedDevices.Read.All (application) with admin consent")
                return findings, meta
            break
        devices += data.get("value", [])
        url = data.get("@odata.nextLink")
        pages += 1

    finding("ep_credentials_valid", "ok", f"connected to Intune; {len(devices)} managed devices read")
    if not devices:
        for cid in ("ep_device_inventory", "ep_encryption", "ep_compliance"):
            finding(cid, "na", "no managed devices enrolled in Intune")
        return findings, meta

    os_counts: dict = {}
    for d in devices:
        os_counts[d.get("operatingSystem", "unknown")] = os_counts.get(d.get("operatingSystem", "unknown"), 0) + 1
    meta["endpointDeviceCount"] = len(devices)
    meta["endpointOsBreakdown"] = os_counts
    finding("ep_device_inventory", "ok",
            f"{len(devices)} managed devices — by OS: {os_counts}")

    enc = sum(1 for d in devices if d.get("isEncrypted"))
    epct = round(100 * enc / len(devices))
    finding("ep_encryption", "ok" if epct == 100 else ("partial" if epct >= 80 else "gap"),
            f"{enc}/{len(devices)} devices ({epct}%) have disk encryption enabled")

    comp = sum(1 for d in devices if d.get("complianceState") == "compliant")
    cpct = round(100 * comp / len(devices))
    finding("ep_compliance", "ok" if cpct >= 95 else ("partial" if cpct >= 80 else "gap"),
            f"{comp}/{len(devices)} devices ({cpct}%) compliant with policy (AV, patch, config)",
            "compliance policy should require real-time antivirus and current definitions")
    return findings, meta
