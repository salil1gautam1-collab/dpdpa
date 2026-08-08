"""Infrastructure scanner — interface stub for the prototype.

The full specification lives in docs/INFRA-SCANNER-SPEC.md: cloud posture
(AWS/Azure/GCP read-only), endpoint estate via Intune/Defender/EDR APIs,
AD/GPO collector, firewall config ingestion, database posture — all
consent-gated with client-supplied least-privilege credentials.

The finding contract is identical to web.py: {webCheckId, status, evidence[]}.
Until implemented, infra-dependent controls resolve via questionnaire evidence.
"""
from __future__ import annotations


def run(config: dict) -> tuple[list, dict]:
    return [], {"infraScanner": "not implemented in prototype — controls resolve via questionnaire/evidence"}
