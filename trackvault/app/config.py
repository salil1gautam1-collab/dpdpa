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

    # AI-assisted import (self-hosted LLM by default — no data leaves your environment).
    # provider: "ollama" (self-hosted) | "none" (feature disabled)
    ai_provider: str = "ollama"
    ai_base_url: str = "http://ollama:11434"
    ai_model: str = "llama3.2:3b"
    ai_timeout: int = 120
    ai_max_doc_chars: int = 24000

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

    _DEFAULTS = {
        "secret_key": "dev-insecure-change-me-32chars-min",
        "bootstrap_admin_password": "ChangeMe!Admin2026",
    }

    def production_issues(self) -> list[str]:
        """Blocking misconfigurations that must be fixed before production."""
        issues = []
        if self.secret_key == self._DEFAULTS["secret_key"] or len(self.secret_key) < 32:
            issues.append("TRACKVAULT_SECRET_KEY is default or too short (set a random value >=32 chars).")
        if not self.encryption_key.strip():
            issues.append("TRACKVAULT_ENCRYPTION_KEY is not set — connector secrets would use a key "
                          "derived from SECRET_KEY. Set a dedicated key (scripts/generate_keys.py).")
        if self.bootstrap_admin_password == self._DEFAULTS["bootstrap_admin_password"]:
            issues.append("TRACKVAULT_BOOTSTRAP_ADMIN_PASSWORD is still the default — set a strong one.")
        return issues


@lru_cache
def get_settings() -> Settings:
    return Settings()

