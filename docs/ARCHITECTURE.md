# Architecture

## Overview

```
                        ┌─────────────────────────────┐
                        │   rulebook/*.json (versioned)│  ← the law, as data
                        └──────────────┬──────────────┘
                                       │
  ┌───────────────┐   findings   ┌─────▼──────┐   statuses   ┌─────────────┐
  │   SCANNERS    │─────────────▶│   ENGINE    │─────────────▶│   REPORTS   │
  │ web / quest./ │              │ (resolver)  │              │ Phase 1 & 2 │
  │ infra (stub)  │              └─────┬──────┘              │ HTML + JSON │
  └───────────────┘                    │                      └─────────────┘
          │                            │ scan snapshots               │
          ▼                            ▼                              ▼
  ┌───────────────┐            ┌─────────────┐               ┌─────────────┐
  │ EVIDENCE STORE│            │ DIFF/ALERTS │               │  DASHBOARD  │
  │ masked, hashed│            │ regressions │               │ dpdpa serve │
  └───────────────┘            └─────────────┘               └─────────────┘
```

All state lives under `local/<client-slug>/` as plain JSON — no database server.

## Components

### 1. Rulebook (`rulebook/dpdpa-rulebook.v1.json`)
The checkpoint universe. Each **control** has: id, category, severity, legal
reference, check method (`web` / `questionnaire` / `evidence` / `hybrid`),
optional `webCheckId` binding it to an automated check, evidence requirements,
remediation guidance, and an `appAssist` block stating whether and how this tool
can help close the gap.

**Updating for law changes:** publish `dpdpa-rulebook.v2.json`. Controls are
never deleted — superseded ones get `"deprecated": true` with a pointer. The
diff engine reports controls that are new/changed since the client's last scan
as `TBC`, so nothing silently changes status.

### 2. Scanners (`src/dpdpa/scanners/`)
Each scanner emits **findings**: `{webCheckId, status, evidence[], url, observedAt}`.

- **web.py** — polite crawl (default ≤ 10 pages, 1 req/s, honest User-Agent) of
  the client's public sites. Checks: HTTPS redirect, HSTS, security headers,
  cookie flags, pre-consent cookies, CMP/banner detection, Google Consent Mode
  signals, tracker enumeration (GA4, GTM, Meta, etc.), privacy-policy discovery
  and content analysis, grievance/DSR contact discovery, form enumeration with
  consent-control detection, terms discovery, notice language options.
- **questionnaire.py** — imports structured departmental answers (Parts A–M
  model, same shape as a typical DPDPA data-flow questionnaire) and
  direct control-status assertions (`controlId → status + evidence text`).
- **infra.py** — interface stub. Production: AWS Config/S3 policy checks, DB
  encryption flags, IAM review exports. Deliberately out of prototype scope;
  the finding contract is identical.

### 3. Evidence store (`evidence.py`)
Every finding carries evidence objects: `{kind, url, excerpt, headers, sha256,
observedAt}`. Excerpts are **PII-masked before storage** (emails, phone numbers,
GSTIN/PAN patterns) — the tool proves a form exists without storing what users
typed. Raw page bodies are never persisted, only hashes + masked excerpts.

### 4. Engine (`engine.py`)
Resolves each rulebook control to a status:
1. `web` controls ← scanner findings (mechanical mapping).
2. `questionnaire`/`evidence` controls ← imported answers/assertions.
3. `hybrid` controls ← automated signal caps the status: scanner GAP ⇒ GAP;
   scanner OK + no manual confirmation ⇒ PARTIAL (never auto-COMPLIANT).
4. Anything applicable with no signal ⇒ `TBC` (honest unknown, listed for
   manual entry). Applicability rules can mark controls `NA` with a reason.

Output: a **scan snapshot** `local/<client>/scans/<timestamp>.json` — statuses +
evidence + rulebook version. Snapshots are immutable; that is the audit trail.

### 5. Reports (`report.py`)
- **Phase 1 — Discovery & Inventory**: scan surface, observed cookies/trackers/
  third parties, forms found, questionnaire coverage by department.
- **Phase 2 — Gap Assessment**: per-category scorecards; every control with
  status, evidence, remediation, `appAssist`; NA list with reasons; TBC list as
  the manual-input worklist. Disclaimer embedded on every report.

### 6. Diff & alerts (`diffalert.py`)
Compares the two latest snapshots: regressions (COMPLIANT→GAP), improvements,
new/changed controls after a rulebook upgrade, new trackers/cookies observed.
Emits `alerts.json` + console output; production adds SMTP/webhook dispatch.

### 7. Dashboard (`server.py`)
`dpdpa serve` — stdlib HTTP server on localhost rendering the latest reports
and an index. No authentication in prototype ⇒ bind 127.0.0.1 only.

## Deployment models

| Model | How |
|---|---|
| Internal tool | Run CLI on a schedule (Task Scheduler / cron) per client |
| Subscription SaaS | Same engine behind a multi-tenant web app; `local/` becomes per-tenant encrypted storage; scans run from workers |
| Executable | PyInstaller one-file build (or .NET self-contained publish after port) |

## Security posture of the tool itself
- Local-first: client data never leaves the machine that runs the scan.
- `local/` is gitignored; the repo carries no client data.
- PII masking on all stored excerpts; SHA-256 for integrity, not content.
- Scanning is passive GET requests to public pages — no auth probing, no
  vulnerability scanning, no form submission. Run only with the client's
  written consent (see docs/DISCLAIMER.md).
