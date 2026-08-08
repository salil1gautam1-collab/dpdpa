"""The production config gate must catch insecure settings (no DB needed)."""
import os

os.environ.setdefault("TRACKVAULT_SECRET_KEY", "test-secret-key-at-least-32-chars-long")

from app.config import Settings  # noqa: E402


def test_production_rejects_default_secret_and_missing_key():
    s = Settings(environment="production", secret_key="dev-insecure-change-me-32chars-min",
                 encryption_key="", bootstrap_admin_password="ChangeMe!Admin2026")
    issues = s.production_issues()
    assert any("SECRET_KEY" in i for i in issues)
    assert any("ENCRYPTION_KEY" in i for i in issues)
    assert any("ADMIN_PASSWORD" in i for i in issues)


def test_production_accepts_strong_config():
    s = Settings(environment="production",
                 secret_key="x" * 48,
                 encryption_key="a-dedicated-key-value",
                 bootstrap_admin_password="a-strong-unique-password")
    assert s.production_issues() == []


def test_development_has_no_blocking_issues_by_default():
    s = Settings(environment="development")
    # development doesn't enforce, but the method still runs cleanly
    assert isinstance(s.production_issues(), list)
