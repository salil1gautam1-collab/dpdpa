"""Google Cloud posture connector — read-only, consent-gated, stdlib only.

Access model: the client supplies a short-lived OAuth2 **access token** for a
principal with the `roles/viewer` + `roles/iam.securityReviewer` roles, plus the
target project id. They generate the token with:
    gcloud auth print-access-token   (or Workload Identity in automation)

Why a pasted token and not a service-account key file: signing a
service-account JWT requires RSA (RS256), which the Python standard library
cannot do. The production build adds SA-key support via a JWT/crypto library
(noted in docs/DOTNET-IMPLEMENTATION-GUIDE.md); the checks below are identical
either way.

Checks:
  gcp_credentials_valid   token introspection / list buckets
  gcp_storage_public      buckets: publicAccessPrevention = enforced
  gcp_firewall_exposure   firewall rules allowing 0.0.0.0/0 on non-web ports
  gcp_sql_ssl             Cloud SQL instances require SSL
"""
from __future__ import annotations

from ..evidence import make_evidence
from .httpjson import get, error_summary


def run_checks(conn: dict) -> tuple[list, dict]:
    findings: list = []
    meta: dict = {}
    project = conn.get("projectId", "")
    token = conn.get("accessToken", "")

    def finding(cid, status, excerpt, note=""):
        findings.append({"webCheckId": cid, "site": f"gcp:{project}", "status": status,
                         "evidence": [make_evidence("gcp-api", url=f"gcp://{cid}",
                                                    excerpt=excerpt, note=note)]})

    hdr = {"Authorization": f"Bearer {token}"}
    code, data, raw = get(f"https://storage.googleapis.com/storage/v1/b?project={project}", hdr)
    if code != 200:
        finding("gcp_credentials_valid", "gap" if code in (401, 403) else "unknown",
                f"bucket listing failed (HTTP {code}): {error_summary(data, raw)}",
                "token expired/invalid or project id wrong — GCP checks skipped. "
                "Generate a fresh token with: gcloud auth print-access-token")
        return findings, meta
    buckets = data.get("items", []) if isinstance(data, dict) else []
    meta["gcpBuckets"] = len(buckets)
    finding("gcp_credentials_valid", "ok", f"connected to project {project}; {len(buckets)} buckets")

    if not buckets:
        finding("gcp_storage_public", "na", "no buckets in project")
    else:
        exposed = [b.get("name", "?") for b in buckets
                   if b.get("iamConfiguration", {}).get("publicAccessPrevention") != "enforced"]
        finding("gcp_storage_public", "gap" if exposed else "ok",
                f"{len(buckets)} buckets; public-access-prevention NOT enforced on: {exposed or 'none'}")

    code, data, raw = get(f"https://compute.googleapis.com/compute/v1/projects/{project}/global/firewalls", hdr)
    if code != 200:
        finding("gcp_firewall_exposure", "unknown", f"firewall list HTTP {code}: {error_summary(data, raw)}")
    else:
        rules = data.get("items", []) if isinstance(data, dict) else []
        exposed = []
        for r in rules:
            if r.get("disabled") or r.get("direction", "INGRESS") != "INGRESS":
                continue
            if "0.0.0.0/0" not in r.get("sourceRanges", []):
                continue
            for a in r.get("allowed", []):
                ports = a.get("ports", [])
                if not ports or not set(ports) <= {"80", "443"}:
                    exposed.append(f"{r.get('name','?')}:{a.get('IPProtocol','')}{ports or '/all'}")
        finding("gcp_firewall_exposure", "gap" if exposed else "ok",
                f"firewall rules open to 0.0.0.0/0 on non-web ports: {sorted(set(exposed))[:20] or 'none'}")

    code, data, raw = get(f"https://sqladmin.googleapis.com/v1/projects/{project}/instances", hdr)
    if code != 200:
        finding("gcp_sql_ssl", "unknown", f"Cloud SQL list HTTP {code}: {error_summary(data, raw)}")
    else:
        insts = data.get("items", []) if isinstance(data, dict) else []
        if not insts:
            finding("gcp_sql_ssl", "na", "no Cloud SQL instances")
        else:
            no_ssl = [i.get("name", "?") for i in insts
                      if not i.get("settings", {}).get("ipConfiguration", {}).get("requireSsl", False)]
            finding("gcp_sql_ssl", "gap" if no_ssl else "ok",
                    f"{len(insts)} Cloud SQL instances; SSL not required on: {no_ssl or 'none'}")
    return findings, meta
