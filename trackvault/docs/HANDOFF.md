# TrackVault — Developer Handoff

*Read this first. It tells you what you're inheriting, how to get it running today, and where
every answer lives.*

---

## 1. What this is

TrackVault is a working, production-grade DPDPA compliance platform (India's DPDP Act 2023 +
Rules 2025). It has been run against a real pilot customer end to end. You are inheriting a
**functioning product**, not a prototype: 22/22 tests green, deployed via Docker Compose, with
an HTTPS production path already scripted.

| Document | What it answers |
|---|---|
| [`HANDBOOK.md`](HANDBOOK.md) | What the app does — every feature, operator's view |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How and why it's built this way — engineer's view |
| [`../DEPLOYMENT.md`](../DEPLOYMENT.md) | Production deploy, HTTPS, key generation, cron, backups |
| `TrackVault-Training.pptx` (this folder) | The 16-slide operator training deck |

All three markdown docs are also served inside the app: sign in as an operator → **Help**.

---

## 2. Day-one checklist

1. **Get repo access.** Private GitHub repo: `salil1gautam1-collab/dpdpa` (the enterprise app
   is the `trackvault/` directory; the repo root also contains the earlier prototype, kept for
   reference). Ask the owner to add your GitHub accounts as collaborators — or, if you prefer
   another host (GitLab, Bitbucket, self-hosted), `git clone` + push the full history there;
   nothing is GitHub-specific.
2. **Run it.**
   ```
   cd trackvault
   cp .env.example .env        # then fill in the values (see §3)
   docker compose up -d --build
   ```
   → http://localhost:8000, sign in with the bootstrap admin you configured.
3. **Run the tests.**
   ```
   docker compose run --rm -v "$PWD:/app" -e PYTHONPATH=/app app pytest -q
   ```
   Expect all green. If integration tests skip, `TRACKVAULT_DATABASE_URL` isn't set.
4. **Read the Handbook once, clicking along.** Half a day; you'll know the whole product.

---

## 3. Secrets & environment

**`.env` is never in git.** The owner hands it over separately (password manager / in person).
`.env.example` lists every variable. The production config gate refuses to boot with dev
defaults, so missing secrets fail loudly, not silently.

You need, minimum, for production:
- `TRACKVAULT_SECRET_KEY`, `TRACKVAULT_ENCRYPTION_KEY` — generate per `DEPLOYMENT.md`
- `TRACKVAULT_BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` — first admin
- `TRACKVAULT_SMTP_*` — mail credentials (currently Zoho)
- `TRACKVAULT_BASE_URL`, `TRACKVAULT_ENVIRONMENT=production`

**Rotate on handover** (the outgoing owner had these): SMTP password, admin password,
secret/encryption keys (re-encrypt connector secrets if you rotate the encryption key —
or simply re-enter connector credentials, there are few).

---

## 4. Data & privacy obligations you inherit

- **Customer data stays in the PostgreSQL volume (`pgdata`) — it is not in the repo.** Backups
  via `scripts/backup.sh`. Treat dumps as confidential.
- The pilot customer's source documents and any per-customer working files live **outside the
  repo** (owner's `local/` folder and private storage, both gitignored). Never commit customer
  data, and never show one customer's data to another — the app enforces the second part
  structurally (one client login per company; company-keyed email).
- The app itself must stay DPDPA-clean: masked evidence, consent-gated scanning, erasure via
  `python -m app.ops erase --company <id>`. Keep those properties when you extend it.

---

## 5. Engineering conventions (the short list that will save you pain)

1. **No inline `<script>` — ever.** The CSP (`script-src 'self'`) silently blocks it. JS goes
   in `app/static/app.js`.
2. **Rulebook changes are data, not code.** CS/Legal publish new versions through the UI. If
   you're editing rulebook JSON in a code PR, stop and ask why.
3. **Migrations:** hand-review Alembic output; any new NOT NULL column on an existing table
   needs a `server_default` or it fails on live rows.
4. **Snapshots and audit_log are append-only.** Don't add code that mutates them.
5. **New colors go through the contrast checker** (see `ARCHITECTURE.md` §8); every theme
   defines the same token set — the parity check in git history shows how to verify.
6. **Multi-worker awareness:** module-level caches need short TTLs (see `settings_service`);
   uvicorn runs 2 workers and they don't share memory.
7. **Fail soft on external services.** Every integration (scanners, SMTP, Ollama, watch
   sources) must degrade its feature, never crash the app.
8. **`docker compose restart` does not re-read `.env`** — use `up -d --force-recreate`.
9. Templates/CSS are baked into the image — UI changes need `up -d --build`.

---

## 6. Where the bodies are buried (honest notes)

- **Document conversion yield on prose** is limited by the bundled 3B CPU model. The pipeline
  is complete and correct; swap `TRACKVAULT_AI_MODEL` to a larger model on GPU hardware and
  quality scales with zero code change. Structured files already convert perfectly.
- **Conversions are in-process threads** — a redeploy kills a running job (operator re-uploads;
  progress row shows error/stale). Move to a real queue only if you go multi-host.
- **MeitY's website** serves empty HTML to non-browsers, so the regulatory watch defaults to
  PIB + PRS. A headless-browser fetcher would let you add MeitY back.
- **Scanned image PDFs** can't be read (no OCR dependency). The conversion job reports this
  cleanly and suggests the template path.
- The **prototype app** at the repo root predates `trackvault/` — reference only; don't extend
  it.

---

## 7. Suggested first-quarter roadmap (owner's priorities)

1. **Browser-mode scanning** — drive a headless browser for the web scanner (JS-rendered
   consent banners, MeitY watch source). *Top of the owner's list.*
2. **GPU / larger model for conversion** — biggest quality jump for the USP, config-only.
3. **A fictional walkthrough company** with synthetic data, so real customer data never
   appears in sales demonstrations.
4. OCR stage for scanned documents.
5. Per-user theme preference (tokens already support it).

---

## 8. Support handover

- Ops commands & cron: Handbook §16, `DEPLOYMENT.md`.
- The admin **Audit** page answers "who did what, when".
- The **Delivery log** answers "did the customer get the email".
- Every conversion, watch check and rulebook publish is audit-logged.

Welcome aboard. Read the Handbook, run the app, break nothing that's append-only.
