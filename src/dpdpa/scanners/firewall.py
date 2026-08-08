"""Firewall configuration connector — upload/paste model.

The client exports their firewall configuration (or ruleset) and pastes it here.
We parse it heuristically across common formats (iptables, Cisco ASA/IOS,
pfSense/Fortinet exports) and flag permissive patterns. Findings are advisory
and marked for human confirmation — a config parse is not a substitute for a
firewall audit.

conn = {"configText": "...", "vendorHint": "iptables|cisco|fortinet|...", "consent": {...}}
"""
from __future__ import annotations

import re

from ..evidence import make_evidence

# permissive-source tokens across vendors
_ANY_SRC = re.compile(r"\b(0\.0\.0\.0/0|any|any4|::/0)\b", re.I)
_PERMIT = re.compile(r"\b(permit|allow|accept)\b", re.I)
_MGMT_PORT = re.compile(r"\b(22|23|3389|8443|8080|161)\b")
_LOG = re.compile(r"\blog(ging)?\b", re.I)


def run_checks(conn: dict) -> tuple[list, dict]:
    findings: list = []
    meta: dict = {}

    def finding(cid, status, excerpt, note=""):
        findings.append({"webCheckId": cid, "site": "firewall", "status": status,
                         "evidence": [make_evidence("config-parse", url="firewall://config",
                                                    excerpt=excerpt, note=note)]})

    text = conn.get("configText", "").strip()
    if not text:
        finding("fw_config", "unknown", "no firewall configuration provided",
                "paste the firewall config/ruleset export")
        return findings, meta

    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith(("#", "!"))]
    meta["firewallLines"] = len(lines)
    finding("fw_config", "ok", f"firewall configuration received ({len(lines)} rule/config lines parsed)")

    permit_lines = [ln for ln in lines if _PERMIT.search(ln)]
    any_any = [ln for ln in permit_lines if _ANY_SRC.search(ln)]
    # crude "any service" heuristic: permit + any-source + no explicit port/eq
    any_service = [ln for ln in any_any if not re.search(r"\b(eq|port|dport|--dport|:)\b", ln, re.I)]
    finding("fw_any_any", "gap" if any_service else ("partial" if any_any else "ok"),
            f"permissive rules with an 'any' source: {len(any_any)}; of which appear to allow any service: {len(any_service)}. "
            f"Example: {any_service[0][:120] if any_service else (any_any[0][:120] if any_any else 'none')}",
            "heuristic parse — confirm against the live ruleset")

    mgmt_exposed = [ln for ln in any_any if _MGMT_PORT.search(ln)]
    finding("fw_mgmt_exposure", "gap" if mgmt_exposed else "ok",
            f"management-port rules (SSH/RDP/Telnet/admin) reachable from an 'any' source: {len(mgmt_exposed)}. "
            f"Example: {mgmt_exposed[0][:120] if mgmt_exposed else 'none'}",
            "expose admin interfaces only via VPN/bastion")

    finding("fw_logging", "partial" if _LOG.search(text) else "gap",
            f"logging directives present in config: {bool(_LOG.search(text))}",
            "ensure deny/allow logging is enabled and retained >=1 year (Rule 6)")

    return findings, meta
