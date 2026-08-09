# TrackVault (enterprise)

Enterprise-grade rebuild of the DPDPA compliance platform, addressing the
maturity scorecard. The valuable domain logic (rulebook engine, six connectors,
evidence model, reports) is carried over; the entire platform layer is rebuilt
production-grade.

**Start here:** [docs/HANDBOOK.md](docs/HANDBOOK.md) — the operator's handbook
covering every feature (also available inside the app: sign in → **Help**).
Deployment & ops: [DEPLOYMENT.md](DEPLOYMENT.md).

## Stack

- **FastAPI** (ASGI) behind Uvicorn workers — replaces the stdlib server
- **PostgreSQL** + **SQLAlchemy 2.0** + **Alembic** migrations — replaces JSON files
- **Argon2** password hashing; **server-side sessions** (DB-backed, expiring, revocable)
- **Fernet envelope encryption** for connector credentials — nothing sensitive in cleartext
- **RBAC**: admin / cs / legal / analyst / viewer / client
- **CSRF** tokens, **rate limiting**, **security headers**, non-root container
- **Append-only audit log** of security-relevant actions
- **pytest** suite + **GitHub Actions CI** (tests + dependency & secret scanning)

## Run it

```bash
cd trackvault
docker compose up -d --build
# open http://localhost:8000/login
```

The entrypoint waits for Postgres, applies migrations (`alembic upgrade head`),
seeds rulebooks + a bootstrap admin, then starts the app.

**First login:** `admin@trackvault.local` / `ChangeMe!Admin2026` (set via
`TRACKVAULT_BOOTSTRAP_ADMIN_*`). You're forced to change it on first sign-in.

## Configuration (environment)

| Variable | Purpose |
|---|---|
| `TRACKVAULT_DATABASE_URL` | Postgres DSN |
| `TRACKVAULT_SECRET_KEY` | app secret (sessions, key derivation) |
| `TRACKVAULT_ENCRYPTION_KEY` | dedicated secrets key (urlsafe-base64 32 bytes). **Set in production** — `/healthz` reports `derived-key-insecure` if unset |
| `TRACKVAULT_ENVIRONMENT` | `development` / `production` (enables HSTS, secure cookies) |
| `TRACKVAULT_SMTP_*` | email (blank host → simulated) |
| `TRACKVAULT_TEST_RECIPIENT` | redirect all email here while testing |

## What the scorecard flagged, and where it's fixed

| Scorecard gap | Fix |
|---|---|
| Secrets in plaintext | `crypto.py` Fernet encryption; DB stores ciphertext only (proven by tests) |
| Shared admin password, in-memory sessions | `models.User` + `UserSession`; per-user accounts, argon2, DB sessions, lockout |
| No HTTPS/CSRF/rate-limit | security-headers + CSRF tokens + `ratelimit.py` |
| No RBAC | `Role` enum + `require_roles` dependencies |
| No database | Postgres + SQLAlchemy + Alembic |
| No audit trail | append-only `audit_log` + `audit.record()` |
| No tests/CI | `tests/` + `.github/workflows/ci.yml` |

## Tests

```bash
docker compose run --rm --no-deps -v "${PWD}:/app" -e PYTHONPATH=/app --entrypoint python app -m pytest
```

Pure security tests (encryption, hashing, rate limit, engine) run with no
database; integration tests run against Postgres when `TRACKVAULT_DATABASE_URL`
is set.

## Still on the roadmap (P1/P2 from the scorecard)

Background job queue + scheduler for recurring scans; SSO/SAML/OIDC; observability
(structured logs/metrics/tracing); headless-browser scanning; billing; SOC 2 / ISO
27001 readiness. See the maturity assessment for the sequenced plan.
