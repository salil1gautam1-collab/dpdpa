"""Infrastructure scanner dispatch.

Reads local/<slug>/connectors.json and runs every configured, consent-granted
connector. Currently implemented: AWS (scanners/aws.py). Azure / GCP /
Intune / AD-GPO / firewall ingestion: specified in docs/INFRA-SCANNER-SPEC.md,
not yet built — they resolve via questionnaire evidence until then.

connectors.json shape:
{
  "aws": {
    "consent": {"granted": true, "grantedBy": "...", "date": "..."},
    "accessKeyId": "...", "secretAccessKey": "...", "region": "ap-south-1"
  }
}

Credentials must be a dedicated READ-ONLY principal (AWS: IAM user/role with
the SecurityAudit managed policy). Prototype stores them in the local
workspace file; production must use a secrets vault (see .NET guide).
"""
from __future__ import annotations

from ..workspace import client_dir, load_json


def run(cfg: dict) -> tuple[list, dict]:
    findings: list = []
    meta: dict = {}
    conns = load_json(client_dir(cfg["slug"]) / "connectors.json", {})

    aws_conn = conns.get("aws", {})
    if aws_conn.get("accessKeyId") and aws_conn.get("consent", {}).get("granted"):
        from . import aws
        f, m = aws.run_checks(aws_conn)
        findings += f
        meta.update(m)
        meta["awsConnector"] = "ran"
    elif aws_conn:
        meta["awsConnector"] = "configured but consent not granted — skipped"
    else:
        meta["awsConnector"] = "not configured"

    meta["infraScannerNote"] = ("Azure/GCP/endpoint/AD/firewall connectors are specified "
                                "(docs/INFRA-SCANNER-SPEC.md) but not yet implemented")
    return findings, meta
