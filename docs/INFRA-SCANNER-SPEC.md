# Infrastructure & IT Estate Scanner — Specification

**Status: NOT built in the prototype.** `scanners/infra.py` is a stub that
defines the contract. This document specifies what the production infra scanner
does, so the dev team can build it and sales can represent it honestly:
today these checkpoints resolve from questionnaire declarations + uploaded
evidence; after this module ships they resolve from live, read-only checks.

## Consent & access model (non-negotiable)

Every connector runs only with the client's written consent and **client-supplied,
least-privilege, read-only credentials**, revocable by the client at any time.
The scanner never modifies anything, never reads business data content — it reads
*configuration and posture metadata* only. Each connector lists the exact
permissions it needs so the client's IT team can review before granting.

## Connectors

### 1. Cloud posture (AWS / Azure / GCP)

| Cloud | Access | Checks (mapped controls) |
|---|---|---|
| AWS | cross-account role with `SecurityAudit` managed policy | S3 public-access block + default encryption (SEC-02); EBS/RDS encryption flags (SEC-02); CloudTrail enabled + retention ≥ 1y (SEC-04); IAM: MFA, access-key age, wildcard policies (SEC-03); security groups open to 0.0.0.0/0 (SEC-01); region inventory → data-residency view (XB-01) |
| Azure | app registration with `Reader` + `Security Reader` roles | Storage account public access + encryption; SQL TDE; Activity Log retention; Entra ID MFA/conditional access posture; NSG exposure; Defender for Cloud secure score import |
| GCP | service account with `roles/viewer` + `roles/iam.securityReviewer` | Bucket public access + CMEK; Cloud SQL encryption; audit log config; IAM key age; firewall rules; asset inventory via Cloud Asset API |

Output per finding: resource id, region, observed setting, expected setting,
evidence JSON, severity — same finding contract as the web scanner.

### 2. Endpoint & device estate (laptops, servers, AV)

No custom agent in v1 — integrate with what the client already runs:

- **Microsoft Intune / Entra**: device inventory (count, OS, encryption/BitLocker
  status, compliance policy state) via Graph API (`DeviceManagementManagedDevices.Read.All`).
- **Microsoft Defender / EDR APIs** (Defender, CrowdStrike, SentinelOne):
  AV enabled, definitions current, unprotected device list → SEC-01.
- **No MDM/EDR present?** That itself is a finding (GAP on SEC-01 with evidence
  "no centralised endpoint management"), plus a CSV import path for a manual
  asset register so counts (servers, laptops) still enter the Phase-1 inventory.

### 3. Directory & policy (domain controller, GPO)

Read-only collector script (PowerShell, signed, run by the client's own admin —
we never hold DC credentials) exports and uploads:

- `Get-ADDefaultDomainPasswordPolicy` → password/lockout policy vs baseline (SEC-03)
- Privileged group membership counts (Domain/Enterprise Admins) + stale accounts
  (lastLogon > 90d) → SEC-03
- `Get-GPOReport -All` XML → screen-lock, USB storage, audit-policy settings (SEC-01, SEC-04)
- AD recycle bin / backup state → SEC-05

### 4. Network & perimeter (firewall)

- Config export ingestion (Fortinet/Palo Alto/Sophos/pfSense): any-any rules,
  unused rules, management interfaces exposed to WAN, logging enabled → SEC-01/SEC-04.
- External exposure check from our side (with consent): TLS posture and open
  well-known ports on the client's public IP ranges — **banner/handshake reads
  only, never exploitation**.

### 5. Databases & storage holding personal data

- TLS enforcement flag, encryption-at-rest flag, backup schedule metadata
  (SEC-02, SEC-05); access-log retention vs 1-year Rule 6 requirement (SEC-04).
- Optional column-name sampling (names only, never data values) to suggest
  personal-data classification for the RoPA (GOV-02).

## Engine integration

Each connector emits the standard finding: `{webCheckId, status, evidence[]}`
with new check ids (`aws_s3_encryption`, `intune_device_compliance`,
`ad_password_policy`, `fw_any_any`, ...). Rulebook v2 will bind these to the
SEC/RET/XB/GOV controls via `webCheckId` exactly as web checks bind today —
no engine changes needed; that is why the contract was frozen in the prototype.

## Phase-1 report additions

Estate inventory section: device counts by type/OS, cloud accounts and regions,
managed vs unmanaged endpoints, AV coverage %, firewall rule statistics —
the "how many servers, laptops" view, with per-item evidence.

## Build order (recommended)

1. AWS posture (TradeIndia runs on AWS — immediate pilot value)
2. Intune/Defender endpoint posture
3. AD/GPO collector script
4. Azure & GCP posture
5. Firewall config ingestion
