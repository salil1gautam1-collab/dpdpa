# TrackVault — Architecture

*The technical companion to the [Operator's Handbook](HANDBOOK.md). Written for the engineering
team taking this over.*

---

## 1. System overview

```
                        ┌────────────────────────────────────────────────┐
                        │                 docker compose                 │
                        │                                                │
  Browser ── HTTPS ──►  │  Caddy (prod only)                             │
                        │    │  reverse proxy, TLS                       │
                        │    ▼                                           │
                        │  app  — FastAPI + Uvicorn (2 workers)          │
                        │    │      Jinja2 server-rendered UI            │
                        │    │      background threads (conversions)     │
                        │    ├──────────► db  — PostgreSQL 16            │
                        │    │              (the ONLY persistent state)  │
                        │    └──────────► ollama — self-hosted LLM       │
                        │                  (optional; document reader)   │
                        └────────────────────────────────────────────────┘
                             │ outbound only, all optional:
                             ├── customer websites (consented web scan)
                             ├── AWS / Azure / GCP / Graph APIs (consented, read-only)
                             ├── SMTP (Zoho) for email
                             └── PIB / PRS pages (regulatory watch)
```

Principles that shaped everything:

| Decision | Why |
|---|---|
| Server-rendered Jinja2, no SPA framework | Small team, auditable output, works under a strict CSP |
| The law is **versioned data**, never code | Rulebook updates are content operations by CS/Legal, not deployments |
| Scanner beats declaration | Evidence-first: a found gap outranks a claimed compliance |
| Snapshots are append-only | Assessment history is the audit trail; nothing is rewritten |
| Humans approve everything AI proposes | Compliance product: judgment must carry a person's name |
| All state in PostgreSQL | Containers are disposable; `pgdata` volume + backups are the truth |

---

## 2. Code layout

```
trackvault/
├─ app/
│  ├─ main.py             app factory, middleware chain, router mounting
│  ├─ config.py           pydantic-settings (env-driven) + production gate
│  ├─ db.py               engine + SessionLocal + Base
│  ├─ models.py           all ORM models (one file, ~15 tables)
│  ├─ security.py         argon2, sessions, CSRF, principals
│  ├─ audit.py            append-only audit recorder
│  ├─ templating.py       render() + shared context (theme, asset stamp, badges)
│  ├─ ops.py              CLI for cron: monitor | watch | retention | erase | purge-sessions
│  ├─ domain/             pure logic, no DB imports
│  │  ├─ engine.py        resolve() one control, summarize() a snapshot, control_hash()
│  │  ├─ evidence.py      make_evidence(), mask_pii(), hashing
│  │  └─ scanners/        web.py + aws / azure / intune / gcp / adgpo / firewall
│  ├─ services/           DB-aware orchestration
│  │  ├─ rulebook_service.py     versioned rulebooks (seeded from /rulebooks)
│  │  ├─ scan_service.py         run_assessment(), run_and_notify()
│  │  ├─ alerts.py               diff two snapshots → REGRESSION / NEW_THIRD_PARTY / …
│  │  ├─ import_parser.py        deterministic import (fuzzy ids, loose statuses)
│  │  ├─ conversion_service.py   background document conversion (threads)
│  │  ├─ ai_mapper.py            chunking, keyword shortlist, Ollama calls
│  │  ├─ reg_watch.py            regulatory watch (official sources)
│  │  ├─ notify_service.py       portal notifications + SMTP email (+attachments)
│  │  ├─ settings_service.py     DB-layered runtime settings, themes
│  │  ├─ template_service.py     branded Excel questionnaire template
│  │  └─ report/…                client report HTML (self-contained, print-ready)
│  ├─ routers/            auth, companies, client, reports, connectors,
│  │                      admin (users/rulebook/settings/audit/help), ai_import (conversion)
│  ├─ templates/          Jinja2 pages (base.html carries nav/theme/footer)
│  └─ static/             app.css (design system), app.js (progressive enhancement)
├─ alembic/               migrations (hand-reviewed; server_default on NOT NULL adds)
├─ rulebooks/             seed rulebook JSON (v1…v4 lineage, 86 controls)
├─ docs/                  HANDBOOK.md · ARCHITECTURE.md · HANDOFF.md · training deck
├─ tests/                 unit + integration (TestClient against real Postgres)
├─ Dockerfile             non-root image; entrypoint: wait-db → check-config →
│                         alembic upgrade → seed → uvicorn --workers 2
├─ docker-compose.yml     app + db (+ ollama profile); prod adds Caddy
└─ DEPLOYMENT.md          HTTPS deploy, key generation, cron, backups
```

---

## 3. The assessment engine (the core)

```
   rulebook vN (86 controls)          company inputs
   ┌───────────────────────┐   ┌──────────────────────────────┐
   │ id, category, severity│   │ web scan findings (consented)│
   │ checkMethod:          │   │ connector findings (consented│
   │  web|questionnaire|   │   │   read-only, creds decrypted │
   │  evidence|hybrid      │   │   in memory only)            │
   │ legalRef, remediation │   │ questionnaire declarations   │
   └──────────┬────────────┘   └──────────────┬───────────────┘
              ▼                               ▼
        engine.resolve(control, findings, assertions, overrides)
              │   • scanner gap beats declared COMPLIANT
              │   • no signal at all → TBC (awaiting input)
              ▼
        Snapshot (append-only): scanId, rulebookVersion, resolutions[],
        score, counts, meta — stored as JSONB, summarized for UI
              │
              ├─► client report (self-contained HTML → print/PDF)
              ├─► compare(A, B)  → improved / regressed / new
              └─► alerts.compute_alerts(prev, curr) → notify + email
```

Verdicts: `COMPLIANT · PARTIAL · GAP · NA · TBC`. Every resolution carries evidence objects
(masked excerpts + SHA-256 stamp) and the control's hash, so a report can prove which version
of which rule produced it.

---

## 4. Data model (PostgreSQL)

```
organizations ─┬─ users (role: admin|analyst|cs|legal|viewer|client,
               │         argon2 hash, lockout counters, company_id for clients)
               │     └── user_sessions (opaque token hash, expiry, revocation, CSRF)
               └─ companies ─┬─ questionnaire_answers   (controlId, status, evidence, dept)
                             ├─ connectors              (provider, public_config,
                             │                           secret_enc ← Fernet envelope)
                             ├─ snapshots               (append-only assessments, JSONB)
                             ├─ notifications           (portal + email delivery record)
                             ├─ import_jobs             (background conversions, progress)
                             └─ ai_suggestions          (pending conversion output,
                                                         human-reviewed before apply)
rulebooks        versioned law-as-data (JSONB), source: seeded|imported
reg_watch_items  regulatory-watch findings (unique URL, new|reviewed)
app_settings     runtime key-values (email switches, theme, watch sources)
audit_log        append-only: actor, action, target, ip, detail (never edited)
```

Invariants worth defending in review:
- **One active client user per company** (enforced in `set_client_login`; the email path
  selects deterministically by company_id) — this is what makes cross-customer email
  impossible.
- `snapshots` and `audit_log` are never updated or deleted (except by explicit
  retention/erasure ops).
- Connector secrets exist in plaintext **only inside `run_assessment()`'s memory**.

---

## 5. Request & security path

```
request ──► client-ip middleware ──► rate limiter (per-IP; stricter on /auth/login)
        ──► security headers + CSP (script-src 'self' — NO inline JS anywhere)
        ──► session lookup (opaque cookie → hashed token → principal)
        ──► router: require(role…) → CSRF check on every POST → handler
        ──► render() adds shared context: theme, asset hash, unread badge
        └─► access log (request id, latency); global error handler — no stack leaks
```

- Passwords: argon2id; login lockout after N failures; forced change on first sign-in.
- Sessions: DB-backed → revocable server-side; idle + absolute TTLs.
- CSP consequence for devs: **JS goes in `app.js`**, never inline `<script>` — inline is
  silently blocked (we hit this ourselves; see git history).
- Config gate: `python -m app.check_config` fails the container fast in production if any
  dev default (secret key, encryption key, admin password, HTTP base URL) survives.

---

## 6. Background work

Three mechanisms, deliberately simple (single-host deployment):

1. **In-process threads** — document conversions (`conversion_service.start_job`). The job
   writes progress to `import_jobs` via short-lived sessions, so any web worker can render the
   progress page. Every exit path sets a terminal status — a job can't stay "running" forever.
   *Constraint: a conversion dies with the process on restart/redeploy — acceptable (operator
   just re-uploads); revisit with a real queue (e.g. RQ/Celery) if multi-host ever happens.*
2. **In-process ticker** — a 10-minute loop started at boot auto-runs assessments whose
   customer submissions have waited past `TRACKVAULT_AUTORUN_HOURS` (race-safe: SKIP LOCKED +
   one-job-per-company; auto-runs execute synchronously in their caller so short-lived CLI
   processes can't orphan them).
3. **Cron via `app.ops`** — `monitor` (which also runs the same auto-run check) (scheduled re-assessments + alerts), `watch`
   (regulatory sources), `purge-sessions`, `retention`, `erase`. All idempotent.

The theme setting shows the multi-worker pattern used throughout: worker-local caches get a
short TTL (seconds) instead of invalidation messages — every worker converges quickly and
there's no cross-process machinery to break.

---

## 7. Document conversion pipeline (the USP)

```
upload ──► ImportJob(queued) ──► daemon thread
                                   │ extract text (docx/pdf/xlsx/csv/txt)
                                   │
                                   ├─ deterministic pass: import_parser
                                   │   (header detection, fuzzy control ids,
                                   │    loose status words)  ≥3 rows → DONE instantly
                                   │
                                   ├─ chunked assisted pass (prose):
                                   │   split into ~700-char passages, document order
                                   │   per passage: keyword-shortlist ~8 candidate
                                   │   controls → ask self-hosted model about ONLY
                                   │   those → lenient re-matching of its answers
                                   │   every passage processed; 1 retry; progress row
                                   │   updated per chunk  ("slow machine = slower,
                                   │   never less")
                                   ▼
                        ai_suggestions (best-per-control)
                                   │
                     ┌─────────────┴──────────────┐
                     ▼                            ▼
            review screen (human            converted .xlsx
            approves each row before        (headers round-trip through
            questionnaire is touched)       the deterministic importer)
```

Model quality scales with `TRACKVAULT_AI_MODEL` (GPU/bigger model = better prose yield,
zero code change). Privacy: Ollama runs in-compose; documents never leave the host.

---

## 8. Theming & front-end

- One CSS file, token-driven: every color is a CSS custom property; six themes are just
  token sets under `[data-theme=…]` (Sentinel default, Obsidian, Ledger, Dark, Light,
  Midnight). The admin's choice is stored in `app_settings`, stamped server-side on `<html>`.
- **Every text/surface pair is WCAG-verified** (body ≥7:1, secondary ≥4.5:1, graphics ≥3:1) —
  when adding colors, extend the checker script (see git history: `contrast_check.py`) rather
  than eyeballing.
- Status is never hue-only: tinted chips + the verdict word (color-blind safe).
- `app.js` is progressive enhancement only (scroll reveal, scanner sweep, all
  reduced-motion aware); the app is fully functional with JS disabled.
- Cache busting: the stylesheet/JS link carries an MD5 content stamp computed at boot.

---

## 9. External integrations

| Integration | Auth | Notes |
|---|---|---|
| Web scanner | none (public pages) | consent-gated per company; trackers/consent/cookies/headers/TLS |
| AWS | access key (read-only) | hand-rolled SigV4 — no boto3 dependency |
| Azure / Intune | OAuth client credentials | msauth.py; Defender & device posture |
| GCP | service-account bearer | buckets, audit logging |
| AD/GPO, Firewall | none — paste/upload exports | zero credentials by design |
| SMTP (Zoho) | env-only credentials | test-redirect guard; delivery log; attachments |
| Ollama | none (in-compose) | `/api/chat`, `format=json`, temperature 0.1 |
| Regulatory watch | none (public pages) | PIB + PRS defaults; MeitY is a JS shell → editable sources |

All integrations are **optional and fail soft**: an unreachable service degrades the feature,
never the app.

---

## 10. Testing & CI

- `tests/` runs the pure-unit suite anywhere; integration tests activate when
  `TRACKVAULT_DATABASE_URL` is set (compose provides it) and exercise auth, RBAC, CSRF,
  imports, assessments and email keying against real Postgres.
- Run: `docker compose run --rm -v "$PWD:/app" -e PYTHONPATH=/app app pytest -q`
- Keep the invariant tests sacred: cross-company email isolation, scanner-beats-declaration,
  one-active-client, session revocation.

---

## 11. Known limitations (deliberate, documented)

| Limitation | Why it's acceptable today | Upgrade path |
|---|---|---|
| Conversions run as in-process threads | single-host deploy; job re-upload is cheap | real queue when multi-host |
| 3B CPU model → modest prose yield | architecture proven; structured path is complete | `TRACKVAULT_AI_MODEL` + GPU |
| Scanned (image) PDFs unreadable | no OCR dependency yet | add OCR stage to conversion |
| MeitY site invisible to the watcher | their site is a JS shell | headless-browser fetch, or add sources |
| No per-user theme (app-wide only) | one brand experience; simpler | per-user override on `users` |

---

*If you change how any of this works, update this file in the same PR. The Handbook explains
what the app does; this file explains why it's built this way.*
