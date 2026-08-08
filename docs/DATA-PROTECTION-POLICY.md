# Data Protection Policy — for the tool itself

Requirement: the solution must itself be DPDPA-compliant and secure the data it
works with. This document states what the tool stores, why, for how long, and
the safeguards applied. Review annually or on rule changes.

## What the tool stores (data minimisation by design)

| Data | Contains personal data? | Why stored |
|---|---|---|
| Client config (`client.json`) | Business contact of the engaging org only | Engagement management |
| Rulebook | No | The checkpoint universe |
| Scan snapshots | No — evidence is PII-masked before write | Compliance evidence, audit trail |
| Questionnaire answers | Respondent name/department (works contact) | Attribution of declarations |
| Reports | No personal data beyond org contacts | Deliverable |

The tool deliberately does **not** ingest customer databases, call recordings,
KYC documents or any data-principal personal data. Discovery of such stores is
recorded as *metadata* (system name, category, owner), never as content.

## Safeguards (mapped to Rule 6)

- **Masking**: emails, Indian mobile numbers, GSTIN/PAN patterns are redacted
  from every stored excerpt (`evidence.py::mask_pii`). Integrity is kept via
  SHA-256 hashes of observed content.
- **Access control**: state lives under `local/` on the operator's machine;
  production/SaaS deployments must apply per-tenant encryption at rest and RBAC.
- **Logging**: every scan snapshot is immutable and timestamped — the audit log.
- **Transport**: all scanning over TLS; dashboard binds to 127.0.0.1 in the
  prototype.

## Retention

| Artefact | Retention | Rationale |
|---|---|---|
| Scan snapshots | 24 months rolling, then delete oldest | Enough to evidence a full audit cycle |
| Questionnaire answers | Life of engagement + 12 months | Re-assessment baseline |
| Reports | Client's choice; default 24 months | Deliverable archive |
| Client config | Until engagement ends, then 90 days | Wind-down window |

`python -m dpdpa retention --client <slug>` applies the schedule (prints what it
would delete; `--apply` executes and writes a deletion certificate).

## On engagement end
Client requests deletion → operator deletes `local/<client>/` after generating
a final deletion certificate. Nothing else exists, because nothing else is stored.
