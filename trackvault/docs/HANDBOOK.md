# TrackVault — Operator's Handbook

*Everything the app does and how to use it. Read this, then go click around — nothing here requires coding.*

TrackVault measures an organisation against India's **Digital Personal Data Protection Act 2023 + DPDP Rules 2025**, encoded as **86 verifiable checkpoints**. Every checkpoint gets a verdict — with evidence — and the whole posture is watched continuously.

---

## Contents

1. [Getting started](#1-getting-started)
2. [Roles and who sees what](#2-roles-and-who-sees-what)
3. [The public site](#3-the-public-site)
4. [Onboard a customer](#4-onboard-a-customer)
5. [Getting customer data in](#5-getting-customer-data-in)
6. [Document conversion (any format in)](#6-document-conversion)
7. [Infrastructure connectors](#7-infrastructure-connectors)
8. [Running an assessment](#8-running-an-assessment)
9. [Reports, history and compare](#9-reports-history-and-compare)
10. [Monitoring, alerts and notifications](#10-monitoring-alerts-and-notifications)
11. [Regulatory watch — how the app tracks the law](#11-regulatory-watch)
12. [The rulebook](#12-the-rulebook)
13. [Settings, themes and email safety](#13-settings-themes-and-email-safety)
14. [What the customer sees](#14-what-the-customer-sees)
15. [Security and privacy](#15-security-and-privacy)
16. [Operations and scheduled jobs](#16-operations-and-scheduled-jobs)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. Getting started

**Run it locally**

```
cd trackvault
docker compose up -d --build
```

Open **http://localhost:8000**. The stack is: FastAPI app + PostgreSQL (+ optional self-hosted
AI reader, `ollama` service). First start runs migrations and seeds the provider organisation
and a bootstrap admin.

**Local sign-in (development defaults — change for production)**

| Who | Email | Password |
|---|---|---|
| Admin (operator) | `admin@trackvault.local` | set via `TRACKVAULT_BOOTSTRAP_ADMIN_PASSWORD` |
| Customer logins | created per company by the admin | whatever the admin sets |

Production deployment (HTTPS via Caddy, key generation, fail-fast config gate, backups) is in
[`DEPLOYMENT.md`](../DEPLOYMENT.md).

**The five verdicts** (used everywhere — reports, badges, questionnaires):

| Verdict | Meaning |
|---|---|
| `COMPLIANT` | Verified in place, evidence attached |
| `PARTIAL` | Some arrangement exists; incomplete |
| `GAP` | Required and missing — remediation recommended |
| `NA` | Doesn't apply to this organisation |
| `TBC` | Automation couldn't see it — awaiting a human answer |

**Golden rules** (say them in every customer conversation):
- We **identify** gaps; we act on customer systems **only with explicit consent, access and permission** — we are not the gap fillers.
- Reports inform legal counsel; they are **not legal advice**.
- Scanner findings beat declarations: if a customer says "compliant" but the scan finds a gap, **the gap wins**.

---

## 2. Roles and who sees what

**Operator side (your team)** — signs in and lands on the Companies dashboard:

| Role | Can do |
|---|---|
| `admin` | Everything: users, settings, audit, rulebook, all companies |
| `analyst` | Day-to-day assessment work on companies |
| `cs`, `legal` | Assessment work **plus** publishing rulebook updates |
| `viewer` | Read-only |

Users are managed at **Admin → Users** (create with a temporary password; the user must change
it on first sign-in; accounts can be deactivated).

**Customer side** — one **client** login per company, lands in their own workspace:
- Sees: their report, history, questionnaire, notifications. **Submit-only** — no run buttons.
  Running assessments is operator work (that's the billable service).
- **One active client login per company**, enforced structurally — a report can never reach
  another company's inbox.
- Forgotten customer password? Open the company page → set a new client login. The old one is
  retired automatically.

---

## 3. The public site

For logged-out visitors: **Home · How it works · About us · Contact · Sign in · Get started**.

- **Get started (self-serve signup):** a prospect creates their company workspace themselves —
  company name, websites, email, password — and lands signed-in in the submit-only client
  workspace. The new company appears on your operator dashboard immediately.
- The homepage also lists **coming-soon frameworks** (GDPR, HIPAA, SOC 2, ISO 27001) — demand
  routes to the contact page.

- The homepage opens on a **live assessment panel** — real checkpoint rows with verdict chips and
  a scanning sweep — plus the stat band (86 checkpoints · ₹250 cr max penalty · Nov 2026).
- **Contact** has a request-a-slot email button (prefilled subject/body) and a sign-in shortcut.
- The whole site follows the admin-chosen theme (see [Settings](#13-settings-themes-and-email-safety)).

---

## 4. Onboard a customer

Customers can also self-serve via **Get started** on the homepage — then you skip straight to
step 3's follow-up. The 🔎 box in the top bar searches companies by name. Manual path:

1. Sign in as an operator → **Companies** dashboard → **Add a company** (name + websites —
   the websites power the automated web scan).
2. Open the company page → **client login** → set the customer's email + temporary password.
3. Share the credentials. The customer signs in and starts providing inputs.

> Tip: while onboarding, keep **Settings → "Redirect all email to"** pointed at yourself.
> Every outgoing email then goes only to you — no accidental customer emails.

---

## 5. Getting customer data in

Three reliable paths, all on the company page:

**A. Excel template (preferred).** *⬇ Download Excel template* produces a branded workbook for
that company: a **Start Here** sheet with the consent statement, then the questionnaire grouped
by section (website, cloud, endpoints, security…), each row explained, with a status dropdown
including **N/A**. The customer fills it; you upload it back — parsed instantly.

**B. Direct import.** Any file that has a control column + status column — Excel, CSV, Word,
PDF — or simply paste rows like:

```
SEC-01, gap, security policy lapsed, IT
NT-1  partial  privacy notice being redrafted  Legal
```

Matching is forgiving: `SEC-1` = `sec01` = `SEC-01`; "not compliant", "no", "fail" → GAP;
"in progress" → PARTIAL; "n/a" → NA, etc.

**C. In-app questionnaire.** The customer answers in their portal — or you fill it during a
call. After an assessment, use **🎯 Confirm what automation couldn't** to show *only* the open
TBC items instead of all 86.

---

## 6. Document conversion

**The USP: any customer document in, an import-ready set of answers out.** The customer shares
their compliance information in whatever form they already have — a Word note, an auditor's
report, a gap register, a PDF — and the app converts it **in the background**.

On the company page → **🔄 Document conversion** → choose the file → *Convert this document*.
You land on a live progress page (*"Converting passage 9 of 13 · 6 answers found"*). Leave it —
the job keeps running on the server.

How it converts, in order:
1. **Deterministic pass** — if the document has structure (control + status columns), it parses
   **instantly and completely**. No AI involved.
2. **Chunked assisted pass** — free-form prose is split into small passages; for each passage a
   **private, self-hosted** reader is asked only about the ~8 checkpoints whose keywords appear
   there. Every passage is processed, in order, with retries — a fast machine finishes sooner, a
   slow machine takes longer, but **the whole document always gets converted**. Nothing ever
   leaves your environment.
3. **Human review** — when done: **Review & apply** (approve/edit/reject each proposed answer;
   nothing touches the questionnaire until you approve) and **⬇ Download converted Excel** —
   the converted document itself: Control ID, Section, Checkpoint, Status, Evidence, Confidence,
   Source quote. Check it, correct it, archive it, or re-import it later (its headers round-trip
   through Direct import).

Honesty notes: quality on prose scales with the model behind it (config: `TRACKVAULT_AI_MODEL`;
a GPU or larger model improves yield with zero code changes). Scanned image-only files can't be
read — ask for a text version. One conversion runs per company at a time.

---

## 7. Infrastructure connectors

Optional, and always **consent-gated + read-only**: AWS, Azure, Intune/Defender, GCP
(credential-based, encrypted at rest, decrypted in memory only during a scan), plus AD/GPO and
Firewall (paste/upload an export — no credentials at all).

Rules of engagement:
- Explicit consent recorded **per system**. No consent = the connector simply doesn't run
  (the report shows "configured but not consented").
- Read-only credentials only. Ask the customer's IT for a read-only role/service account.

Set up on the company page → **Connectors**.

---

## 8. Running an assessment

Company page → **Run assessment** — the button responds instantly and opens a **live progress
page** narrating each step (scanning which site, which connector, resolving checkpoints). You can
browse anywhere; the company page shows a running banner with a Watch-live link, and re-clicking
Run rejoins the run. The engine:
1. Scans consented websites (consent banners, trackers, cookies, security headers, TLS…) and
   consented cloud/endpoint systems.
2. Merges the questionnaire declarations.
3. Resolves all 86 checkpoints (scanner-beats-declaration) into a **snapshot**: score, verdict
   counts, evidence. Snapshots are permanent — nothing is overwritten, history is the audit trail.

**When a customer submits inputs:** every admin is emailed immediately; if nobody runs the
assessment within `TRACKVAULT_AUTORUN_HOURS` (default 2, 0 disables) it **auto-runs** and the
customer gets their report anyway. The customer is told to expect their report within 1–2 hours.

After every run, automatically:
- The score donut and **coverage panel** (% verified automatically vs declared, and what still
  needs human confirmation) update.
- Changes vs the previous run are detected; the customer gets a portal notification (and email
  if enabled) — a plain "report ready", or an **ALERT** if something regressed.

---

## 9. Reports, history and compare

- **Two documents per assessment:** the executive **client report** (for the board) and the
  **🔍 gap assessment** (for the team doing the work — full gap register with evidence,
  remediation, and Owner/Target-date columns). Both linked beside every report button, both
  print-ready, and the ✉ email form lets you attach either or both.
- **Client report** — branded, board-ready: cover, score donut, executive summary, findings
  (gaps first) with masked evidence excerpts, remediation recommendations, the provenance bar,
  TBC "awaiting input" list, and the disclaimer. Open → Print → **Save as PDF**.
- **Send it by email** from the company page (attachment included) — every send is recorded in
  the delivery log.
- **History** — every assessment ever run; open any past report on demand.
- **Compare** — pick any two reports: what improved, what regressed, what's new. Green arrow =
  progress. This is the renewal conversation: *"you were 22% in March, you're 61% now."*

---

## 10. Monitoring, alerts and notifications

- Per company, set a **monitoring cadence** (monthly / quarterly / off) on the company page.
  The scheduler re-assesses automatically when due.
- **Three alert types:** `REGRESSION` (a checkpoint got worse), `NEW_THIRD_PARTY` (a new tracker
  appeared on their site), `RULEBOOK_CHANGED` (the law moved since their last assessment).
- Customers see notifications on their own **Notifications page** (menu item with an unread
  badge; messages grouped by day, one line each, expandable). Operators see recent alerts on the
  company page. **Admin → Delivery log** shows every email with its status.

---

## 11. Regulatory watch

*How does the tool learn about new rules from the government?* — **Detection automated,
judgment human.**

- The app checks configured official pages (defaults: PIB press releases + PRS Legislative
  Research; MeitY's own site serves empty HTML to non-browsers, so add it only if that changes)
  for documents mentioning the DPDP framework.
- New findings appear on **Admin → Rulebook → 📡 Regulatory watch** with a red badge. Open the
  document, read it, **Mark reviewed** (recorded with your name).
- If the law actually moved: publish a new rulebook version right below (next section) — every
  company gets flagged and every customer notified automatically.
- **Check now** button for on-demand scans; `python -m app.ops watch` for the daily cron;
  sources editable in **Settings**.

---

## 12. The rulebook

The law lives as **versioned data** — never hardcoded.

- **Click any version number to read it**: every control grouped by section with severity,
  legal reference, check method, evidence required and remediation — plus **Export for study**
  (an Excel with a Review-notes column, made for counsel) and a JSON export. Exports are
  audit-logged.
- **Admin → Rulebook** (admin/cs/legal): the version table, plus two ways to update — a
  **form** to add a single checkpoint (id, category, severity, title, legal reference, check
  method, remediation…) or a bulk **import** for a whole revision.
- Publishing creates version *n+1*; old versions are never touched. Every existing report states
  the version it was assessed under.
- After publishing: companies' next assessments use the new version; anything newly required
  surfaces as a new gap; customers are notified. **Nothing changes silently.**

---

## 13. Settings, themes and email safety

**Admin → Settings** (effective immediately, no restart, audit-logged):

- **Send emails** — master on/off switch.
- **Sender address** — must be your authenticated mailbox (SMTP host/user/password themselves
  live in the server environment, `TRACKVAULT_SMTP_*` — secrets never editable from the UI).
- **Redirect all email to (test mode)** — the safety net: with an address set, *every* outgoing
  email goes only there, never to real customers. Use for onboarding and walkthroughs; clear it
  to go live. The delivery log records both intended and actual recipient.
- **Appearance** — one of six themes, applied app-wide instantly:
  🟢 Sentinel (default) · 🟣 Obsidian · 📜 Ledger · 🌙 Dark · ☀ Light · 🌌 Midnight.
- **Regulatory watch sources** — one URL per line.

**Email can't cross customers, structurally:** one active client login per company + every email
keyed to its company. Verified with dedicated tests.

---

## 14. What the customer sees

Their workspace is a three-step flow:
1. **Questionnaire** (with the 🎯 only-what's-left filter after a scan)
2. **Infrastructure & cloud access** (optional, consent per system)
3. **Submit my inputs** — which notifies your team that they're ready to assess

Plus: **Notifications** (own page, day-grouped, unread badge), their **report** (download as
PDF), and **history**. No run buttons anywhere — they provide inputs, your team assesses.

The pitch in one breath: *"You answer a questionnaire once and grant read-only access. We
measure you against all 86 checkpoints, prove every finding, and watch your posture
continuously."*

---

## 15. Security and privacy

The answers you'll be asked, and what's true:

| Concern | Answer |
|---|---|
| Connector credentials | Envelope-encrypted at rest; decrypted in memory only during a scan |
| Evidence | Personal data masked in excerpts; every excerpt hash-stamped (tamper-evident) |
| Passwords & sessions | argon2 hashing, expiring/revocable DB sessions, login lockout, CSRF tokens, per-IP rate limiting |
| Access | Role-based; customers strictly submit-only; one client login per company |
| Audit | Append-only log of every sensitive action — who, what, when, from where |
| App hardening | Strict Content-Security-Policy (no inline scripts), security headers, non-root container, HTTPS deploy, fail-fast production config gate |
| AI / conversion | Self-hosted only — documents never leave the environment; no per-token API costs; human review before anything applies |
| Data lifecycle | Backups (`scripts/backup.sh`), retention (`app.ops retention`), full DPDPA erasure of a company (`app.ops erase`) |

---

## 16. Operations and scheduled jobs

```
python -m app.ops monitor           # hourly/daily — re-assess due companies, fire alerts
python -m app.ops watch             # daily — regulatory watch
python -m app.ops purge-sessions    # daily — clear expired sessions
python -m app.ops retention --months 24 [--apply]   # snapshot retention
python -m app.ops erase --company <id>              # DPDPA erasure (company + all data)
./scripts/backup.sh                 # nightly DB backup, 14-day rotation
```

Run them inside the app container (`docker compose exec app …`) from cron. Details, HTTPS
deployment and key generation: [`DEPLOYMENT.md`](../DEPLOYMENT.md).

---

## 17. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Emails say **SIMULATED** | SMTP password not set in the server environment (`TRACKVAULT_SMTP_PASS`) → set it and `docker compose up -d --force-recreate app` |
| Email went to the wrong-looking address | Check Settings → test-mode redirect; the delivery log shows intended vs actual recipient |
| Customer can't sign in | Company page → set a new client login (old one retires automatically). Five failed tries = temporary lockout |
| Conversion stuck on "Converting…" | It isn't — big documents on slow machines take minutes by design; the progress page shows passage-by-passage movement. Errors always land the job in an explicit failed state with a reason |
| Conversion found little from a PDF | If it's a scanned image there's no text to read — ask for a text version, or use the template |
| Theme didn't change | It applies within ~3 seconds across all server workers; hard-refresh once (Ctrl+F5) if your browser cached the stylesheet |
| Regulatory watch found nothing | Normal on most days; "source unreachable" notes are government sites being government sites — try later |
| Changed `.env` but nothing happened | Plain restart doesn't re-read env: `docker compose up -d --force-recreate app` |

---

*TrackVault — measure, prove, watch. We identify gaps and record evidence; we are not the gap
fillers, and this is not legal advice. Remediation runs only with the client's consent, access
and permission.*
