"""TrackVault FastAPI application: middleware, startup seeding, routers."""
from __future__ import annotations

import logging
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
from .routers import admin, auth, client, companies, connectors, reports

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
log = logging.getLogger("trackvault")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Seeding runs once in the entrypoint (before workers start), not per-worker.
    if using_derived_key() and settings.is_production:
        log.warning("SECURITY: TRACKVAULT_ENCRYPTION_KEY is not set in production — "
                    "secrets are encrypted with a key derived from SECRET_KEY. Set a dedicated key.")
    log.info("TrackVault %s started (env=%s)", __version__, settings.environment)
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
    path = request.url.path
    is_login = path in ("/login", "/auth/login")
    limit = settings.login_rate_limit_per_minute if is_login else settings.rate_limit_per_minute
    if not path.startswith("/static") and not ratelimit.allow(f"{ip}:{'login' if is_login else 'gen'}", limit):
        return PlainTextResponse("Too many requests — slow down.", status_code=429)

    request.state.client_ip = ip
    response = await call_next(request)
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
    db_ok = True
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
    except Exception as ex:  # pragma: no cover
        db_ok = False
        log.error("healthz db check failed: %s", ex)
    return JSONResponse({
        "status": "ok" if db_ok else "degraded",
        "version": __version__,
        "database": "ok" if db_ok else "error",
        "encryption": "derived-key-insecure" if using_derived_key() else "dedicated-key",
        "environment": settings.environment,
    }, status_code=200 if db_ok else 503)


app.include_router(auth.router)
app.include_router(companies.router)
app.include_router(client.router)
app.include_router(connectors.router)
app.include_router(reports.router)
app.include_router(admin.router)
