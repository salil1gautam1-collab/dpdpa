"""Integration tests against a real Postgres (set TRACKVAULT_DATABASE_URL).

Skipped automatically when no database is configured, so the pure unit suite
still runs anywhere.
"""
import os

import pytest

DB = os.environ.get("TRACKVAULT_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB, reason="no TRACKVAULT_DATABASE_URL configured")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from app.db import Base, engine
    from app import models  # noqa: F401
    Base.metadata.create_all(engine)
    from app.seed import seed_all
    seed_all()
    from app.main import app
    with TestClient(app) as c:
        yield c


def _login(client, email, password):
    return client.post("/auth/login", data={"email": email, "password": password},
                       follow_redirects=False)


def test_health(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["database"] == "ok"


def test_login_wrong_password_rejected(client):
    from app.config import get_settings
    s = get_settings()
    r = _login(client, s.bootstrap_admin_email, "definitely-wrong")
    assert r.status_code == 200            # re-renders login, no session cookie
    assert "tv_session" not in r.cookies


def test_admin_login_and_rbac(client):
    from app.config import get_settings
    s = get_settings()
    r = _login(client, s.bootstrap_admin_email, s.bootstrap_admin_password)
    assert r.status_code == 303
    assert "tv_session" in r.cookies
    # authenticated admin reaches the audit page
    r2 = client.get("/admin/audit", follow_redirects=False)
    assert r2.status_code == 200


def test_unauthenticated_dashboard_redirects(client):
    fresh = client.__class__(client.app)
    r = fresh.get("/dashboard", follow_redirects=False)
    assert r.status_code in (307, 401)     # redirected to login / unauthorized
