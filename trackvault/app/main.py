"""TrackVault FastAPI application: middleware, startup seeding, routers."""
from __future__ import annotations

import logging
import secrets as _secrets
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from . import __version__
from .config import get_settings
from .crypto import using_derived_key
from .db import engine
from . import ratelimit
from .routers import admin, ai_import, auth, client, companies, connectors, reports
from .templating import render

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
log = logging.getLogger("trackvault")
access_log = logging.getLogger("trackvault.access")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Seeding runs once in the entrypoint (before workers start), not per-worker.
    if settings.is_production:
        issues = settings.production_issues()
        if issues:
            for i in issues:
                log.error("PRODUCTION CONFIG: %s", i)
            raise RuntimeError("Insecure production configuration — see logs. Refusing to start.")
    log.info("TrackVault %s started (env=%s)", __version__, settings.environment)
    # Conversion jobs run as in-process threads; a restart/redeploy kills them.
    # Mark orphans honestly instead of leaving them "running" forever.
    try:
        from datetime import datetime, timedelta, timezone
        from .db import SessionLocal
        from .models import ImportJob
        from sqlalchemy import select
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
        with SessionLocal() as s:
            orphans = list(s.execute(select(ImportJob).where(
                ImportJob.status.in_(["queued", "running"]),
                ImportJob.created_at < cutoff)).scalars())
            for j in orphans:
                j.status = "error"
                j.stage = "Interrupted by an app restart"
                j.note = "The server restarted while this conversion was running. Please re-upload the document."
                j.finished_at = datetime.now(timezone.utc)
            if orphans:
                s.commit()
                log.warning("marked %d orphaned conversion job(s) as interrupted", len(orphans))
    except Exception:  # never block startup over cleanup
        log.exception("orphaned-job sweep failed")
    yield


app = FastAPI(title="TrackVault", version=__version__, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)

_static = Path(__file__).parent / "static"
if _static.exists():
    app.mount("/static", StaticFiles(directory=str(_static)), name="static")


@app.middleware("http")
async def security_and_rate_limit(request: Request, call_next):
    ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
          or (request.client.host if request.client else "unknown"))
    rid = request.headers.get("x-request-id") or _secrets.token_hex(8)
    request.state.request_id = rid
    request.state.client_ip = ip
    path = request.url.path
    is_login = path in ("/login", "/auth/login")
    limit = settings.login_rate_limit_per_minute if is_login else settings.rate_limit_per_minute
    if not path.startswith("/static") and not ratelimit.allow(f"{ip}:{'login' if is_login else 'gen'}", limit):
        access_log.warning("rid=%s ip=%s 429 %s %s", rid, ip, request.method, path)
        return PlainTextResponse("Too many requests — slow down.", status_code=429)

    started = time.monotonic()
    try:
        response = await call_next(request)
    except Exception:
        dur = int((time.monotonic() - started) * 1000)
        log.exception("rid=%s ip=%s 500 %s %s (%dms)", rid, ip, request.method, path, dur)
        try:
            resp = render(request, "error.html", status_code=500, request_id=rid,
                          detail=("An unexpected error occurred. Please try again." if settings.is_production
                                  else "Internal error (see server logs)."))
        except Exception:
            resp = PlainTextResponse("Internal server error.", status_code=500)
        return _harden(resp)

    dur = int((time.monotonic() - started) * 1000)
    if not path.startswith("/static"):
        access_log.info("rid=%s ip=%s %s %s %s (%dms)", rid, ip, response.status_code,
                        request.method, path, dur)
    response.headers["X-Request-ID"] = rid
    return _harden(response)


def _harden(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/healthz")
def healthz():
    """Liveness + basic status (no DB dependency for liveness)."""
    return JSONResponse({
        "status": "ok",
        "version": __version__,
        "encryption": "derived-key-insecure" if using_derived_key() else "dedicated-key",
        "environment": settings.environment,
    })


@app.get("/readyz")
def readyz():
    """Readiness — checks the database is reachable."""
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
    except Exception as ex:  # pragma: no cover
        log.error("readyz db check failed: %s", ex)
        return JSONResponse({"status": "not-ready", "database": "error"}, status_code=503)
    return JSONResponse({"status": "ready", "database": "ok"})


app.include_router(auth.router)
app.include_router(companies.router)
app.include_router(client.router)
app.include_router(connectors.router)
app.include_router(reports.router)
app.include_router(ai_import.router)
app.include_router(admin.router)
