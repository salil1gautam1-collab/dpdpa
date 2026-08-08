"""Application configuration, loaded from environment (12-factor)."""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRACKVAULT_", env_file=".env", extra="ignore")

    # Core
    brand: str = "TrackVault"
    environment: str = "development"          # development | staging | production
    base_url: str = "http://localhost:8000"
    secret_key: str = Field(default="dev-insecure-change-me-32chars-min")

    # Database
    database_url: str = "postgresql+psycopg://trackvault:trackvault@db:5432/trackvault"

    # Secrets encryption — master key for envelope-encrypting connector credentials.
    # MUST be set to a stable 32-byte urlsafe-base64 value in production. If unset,
    # a key is derived from secret_key (fine for dev, flagged in /healthz).
    encryption_key: str = ""

    # Auth / sessions
    session_ttl_hours: int = 12
    session_idle_minutes: int = 60
    argon2_time_cost: int = 3
    argon2_memory_kib: int = 65536
    lockout_threshold: int = 8               # failed logins before temporary lockout
    lockout_minutes: int = 15

    # Rate limiting (per-IP, sliding window, in-process token bucket)
    rate_limit_per_minute: int = 120
    login_rate_limit_per_minute: int = 10

    # First-run bootstrap admin (created only if no users exist)
    bootstrap_admin_email: str = "admin@trackvault.local"
    bootstrap_admin_password: str = "ChangeMe!Admin2026"

    # SMTP (email notifications). Blank host -> simulated (nothing sent).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = "info@dedicatusit.com"
    test_recipient: str = ""                  # redirect ALL mail here when set

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
