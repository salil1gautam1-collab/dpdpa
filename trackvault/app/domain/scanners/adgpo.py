"""Active Directory / Group Policy connector — upload/paste model.

The client's own domain administrator runs a signed, read-only collector script
(docs/collectors/ad-gpo-collector.ps1) and pastes its JSON output here. We never
hold domain credentials and never run anything in their environment.

Collector JSON shape (all optional; missing keys resolve to TBC):
{
  "passwordPolicy": {"minLength": 12, "complexity": true, "lockoutThreshold": 5, "maxPasswordAgeDays": 90},
  "totalUsers": 250,
  "privilegedGroups": {"Domain Admins": 3, "Enterprise Admins": 1},
  "staleAccounts": 4,
  "gpo": {"screenLockConfigured": true, "auditPolicyConfigured": true, "usbStorageBlocked": false}
}
"""
from __future__ import annotations

import json

from ..evidence import make_evidence


def run_checks(conn: dict) -> tuple[list, dict]:
    findings: list = []
    meta: dict = {}

    def finding(cid, status, excerpt, note=""):
        findings.append({"webCheckId": cid, "site": "ad", "status": status,
                         "evidence": [make_evidence("collector", url="ad://collector",
                                                    excerpt=excerpt, note=note)]})

    raw = conn.get("collectorJson", "").strip()
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError as ex:
        finding("ad_collector", "unknown", f"collector output could not be parsed as JSON: {ex}",
                "re-run the collector script and paste its complete output")
        return findings, meta
    if not data:
        finding("ad_collector", "unknown", "no collector output provided",
                "run docs/collectors/ad-gpo-collector.ps1 and paste the JSON")
        return findings, meta

    finding("ad_collector", "ok", "collector output received and parsed")
    meta["adTotalUsers"] = data.get("totalUsers")

    pw = data.get("passwordPolicy")
    if isinstance(pw, dict):
        issues = []
        if pw.get("minLength", 0) < 12:
            issues.append(f"min length {pw.get('minLength','?')} (recommend >=12)")
        if not pw.get("complexity"):
            issues.append("complexity disabled")
        if not pw.get("lockoutThreshold"):
            issues.append("no account lockout")
        finding("ad_password_policy", "ok" if not issues else ("partial" if len(issues) == 1 else "gap"),
                f"password policy: {pw}; concerns: {issues or 'none'}")
    else:
        finding("ad_password_policy", "unknown", "password policy not included in collector output")

    priv = data.get("privilegedGroups")
    if isinstance(priv, dict):
        da = priv.get("Domain Admins", 0) + priv.get("Enterprise Admins", 0)
        finding("ad_privileged_accounts", "gap" if da > 8 else ("partial" if da > 5 else "ok"),
                f"privileged group membership: {priv} (fewer is better; review if Domain/Enterprise Admins is large)")
    else:
        finding("ad_privileged_accounts", "unknown", "privileged group counts not provided")

    stale = data.get("staleAccounts")
    if stale is not None:
        finding("ad_stale_accounts", "ok" if stale == 0 else ("partial" if stale <= 5 else "gap"),
                f"{stale} enabled accounts inactive >90 days (should be disabled)")
    else:
        finding("ad_stale_accounts", "unknown", "stale-account count not provided")

    gpo = data.get("gpo")
    if isinstance(gpo, dict):
        missing = [k for k in ("screenLockConfigured", "auditPolicyConfigured") if not gpo.get(k)]
        finding("ad_gpo_hardening", "ok" if not missing else ("partial" if len(missing) == 1 else "gap"),
                f"GPO hardening: {gpo}; missing: {missing or 'none'}")
    else:
        finding("ad_gpo_hardening", "unknown", "GPO hardening settings not provided")

    return findings, meta
