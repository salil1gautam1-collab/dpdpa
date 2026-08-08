"""Infrastructure scanner dispatch.

Reads local/<slug>/connectors.json and runs every configured, consent-granted
connector. Implemented: AWS, Azure, Microsoft Intune/Defender (endpoints), GCP.
Not yet built (config-upload model, see docs/INFRA-SCANNER-SPEC.md): Active
Directory / GPO collector, firewall config ingestion — these resolve via
questionnaire evidence until built.

connectors.json shape:
{
  "aws":   {"consent": {...}, "accessKeyId": "...", "secretAccessKey": "...", "region": "ap-south-1"},
  "azure": {"consent": {...}, "tenantId": "...", "clientId": "...", "clientSecret": "..."},
  "intune":{"consent": {...}, "tenantId": "...", "clientId": "...", "clientSecret": "..."},
  "gcp":   {"consent": {...}, "projectId": "...", "accessToken": "..."}
}

All credentials must be READ-ONLY principals. Prototype stores them in the
local workspace file (gitignored); production must use a secrets vault.
"""
from __future__ import annotations

from ..workspace import client_dir, load_json

# connector key -> (module name, required credential field, label)
_CONNECTORS = [
    ("aws", "aws", "accessKeyId", "AWS"),
    ("azure", "azure", "clientId", "Azure"),
    ("intune", "intune", "clientId", "Intune/Defender endpoints"),
    ("gcp", "gcp", "accessToken", "Google Cloud"),
    ("adgpo", "adgpo", "collectorJson", "Active Directory / GPO"),
    ("firewall", "firewall", "configText", "Firewall config"),
]


def run(cfg: dict) -> tuple[list, dict]:
    findings: list = []
    meta: dict = {}
    conns = load_json(client_dir(cfg["slug"]) / "connectors.json", {})

    for key, module, cred_field, label in _CONNECTORS:
        conn = conns.get(key, {})
        state_key = f"{key}Connector"
        if conn.get(cred_field) and conn.get("consent", {}).get("granted"):
            mod = __import__(f"dpdpa.scanners.{module}", fromlist=["run_checks"])
            f, m = mod.run_checks(conn)
            findings += f
            meta.update(m)
            meta[state_key] = "ran"
        elif conn:
            meta[state_key] = "configured but consent not granted — skipped"
        else:
            meta[state_key] = "not configured"

    return findings, meta
