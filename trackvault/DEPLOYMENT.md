# TrackVault — Deployment Runbook

Standard containers (Postgres + FastAPI app + Caddy for HTTPS). Runs on any
cloud VM, on-prem server, or container platform. No cloud lock-in.

## Fastest path — a single VM with automatic HTTPS (≈30 minutes)

Prerequisites: a Linux server with Docker + Docker Compose, a domain name, and
ports 80/443 open.

```bash
# 1. Get the code onto the server (git clone, scp a zip, whatever you use)
cd trackvault

# 2. Generate secrets
python scripts/generate_keys.py        # copy the three lines it prints

# 3. Configure
cp .env.production.example .env
#    edit .env: paste the generated secrets, set POSTGRES_PASSWORD,
#    SITE_ADDRESS=your.domain, TRACKVAULT_BASE_URL=https://your.domain,
#    and the bootstrap admin email/password.

# 4. Point your domain's DNS A-record at the server's IP.

# 5. Launch (Caddy fetches a Let's Encrypt certificate automatically)
export $(grep -v '^#' .env | xargs)      # or use --env-file
docker compose -f docker-compose.prod.yml up -d --build
```

Visit `https://your.domain` — you have a live, HTTPS-secured site. Sign in with
the bootstrap admin and change the password.

The app **refuses to start** in production if the secret key, encryption key, or
admin password are still defaults — so you can't accidentally ship insecurely.

## What each piece is

| Container | Role |
|---|---|
| `caddy` | Public entrypoint on 80/443; automatic HTTPS; reverse-proxies to the app |
| `app` | FastAPI (Uvicorn workers). Not exposed to the host — only Caddy reaches it |
| `db` | PostgreSQL with a persistent volume |

On startup the app checks config, applies DB migrations (`alembic upgrade head`),
seeds the rulebooks + bootstrap admin, then serves.

## Using a managed database instead (recommended for scale)

Point `TRACKVAULT_DATABASE_URL` at your managed Postgres (AWS RDS, Azure Database
for PostgreSQL, Cloud SQL) and drop the `db` service. Managed Postgres gives you
automated backups, failover and patching.

## Container platforms

The image is a standard OCI container — deploy it on AWS ECS/Fargate, Azure
Container Apps, Google Cloud Run, or Kubernetes. Provide the same environment
variables; run `alembic upgrade head` as a release/pre-deploy step; add a
readiness probe on `GET /readyz` and a liveness probe on `GET /healthz`.

## CI/CD (any tool)

The GitHub Actions pipeline (`.github/workflows/ci.yml`) runs `pytest` +
dependency/secret scans. The same two commands port to any CI (Jenkins, GitLab
CI, Azure Pipelines):

```bash
pip install -r requirements.txt
pytest                    # needs a Postgres service + TRACKVAULT_DATABASE_URL
```

Then build and push the image, and roll it out.

## Backups & restore

```bash
./scripts/backup.sh                 # nightly via cron; keeps 14 days, gzip'd
./scripts/restore.sh backups/trackvault-YYYYMMDD-HHMMSS.sql.gz
```

With a managed database, use the provider's automated backups instead.

## Scheduled maintenance (cron)

```bash
docker compose exec app python -m app.ops monitor               # hourly/daily — re-assess due companies & fire alerts
docker compose exec app python -m app.ops watch                 # daily — regulatory watch: new DPDP documents on official sources
docker compose exec app python -m app.ops purge-sessions        # daily
docker compose exec app python -m app.ops retention --months 24 --apply   # monthly
docker compose exec app python -m app.ops erase --company <id>  # on engagement end / erasure request
```

**Monitoring:** set a company's monitoring to weekly/monthly in its workspace.
Schedule `app.ops monitor` (e.g. hourly via cron) — it re-assesses every company
whose schedule is due, and raises an alert (portal + email) if a checkpoint
regressed, a new third-party tracker appeared, or the rulebook changed.

## Operating notes

- **Secrets**: live only in `.env` (gitignored) or your platform's secret store.
  Rotating `TRACKVAULT_ENCRYPTION_KEY` invalidates stored connector credentials —
  re-enter connectors after a rotation.
- **Scaling out**: run more `app` replicas behind Caddy/your load balancer. Two
  things then need a shared store (both documented as roadmap): sessions/jobs and
  the rate limiter → back them with Redis. Single-node is fine for pilots.
- **Health**: `GET /healthz` (liveness) and `GET /readyz` (DB readiness).
- **Logs**: structured request logs with a request id (`rid=...`) go to stdout —
  ship them to your log stack (CloudWatch, Loki, ELK).

## What's production-ready today vs. what to add for large enterprise

Ready now: HTTPS, encrypted secrets, per-user RBAC, audit log, migrations,
backups, health probes, config safety gate, tests + CI.

Add for large-enterprise procurement (see the maturity assessment): SSO/SAML,
Redis-backed sessions/rate-limit for multi-node, a metrics/tracing stack,
headless-browser scanning, and a formal security review / pen test.
