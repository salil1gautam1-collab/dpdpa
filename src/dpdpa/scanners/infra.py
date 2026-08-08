"""Infrastructure scanner — interface stub for the prototype.

Production implementation (see docs/DOTNET-IMPLEMENTATION-GUIDE.md) runs
read-only checks with client-supplied, least-privilege credentials, only after
written consent:

  - AWS: S3 public-access block, default encryption on buckets/EBS/RDS,
    CloudTrail enabled, IAM access-key age, security-group 0.0.0.0/0 exposure.
  - Databases: TLS enforcement, encryption-at-rest flags.
  - Endpoints: internal TLS posture.

The finding contract is identical to web.py: {webCheckId, status, evidence[]}.
Until implemented, infra-dependent controls resolve via questionnaire evidence.
"""
from __future__ import annotations


def run(config: dict) -> tuple[list, dict]:
    return [], {"infraScanner": "not implemented in prototype — controls resolve via questionnaire/evidence"}
