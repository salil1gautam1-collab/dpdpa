"""ORM models. Tenant isolation via organization_id foreign keys throughout.

Design notes:
- Connector credentials are stored ENCRYPTED (see crypto.py); the ORM holds
  ciphertext only. Plaintext exists solely in memory during a scan.
- Scan snapshots are immutable once written (the audit trail of assessments).
- AuditLog is append-only; nothing updates or deletes it.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, Enum, Float, ForeignKey, Integer, String,
                        Text, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    """Operator roles (staff of the firm running TrackVault) + client."""
    admin = "admin"          # full control, user management, rulebook
    cs = "cs"                # company secretary — rulebook, governance
    legal = "legal"          # legal — rulebook, review
    analyst = "analyst"      # runs assessments, manages connectors
    viewer = "viewer"        # read-only operator
    client = "client"        # external customer — own workspace only


OPERATOR_ROLES = {Role.admin, Role.cs, Role.legal, Role.analyst, Role.viewer}
RULEBOOK_ROLES = {Role.admin, Role.cs, Role.legal}
RUN_ROLES = {Role.admin, Role.analyst}


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_provider: Mapped[bool] = mapped_column(Boolean, default=False)  # the firm running TrackVault
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    users: Mapped[list["User"]] = relationship(back_populates="organization")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", name="uq_users_email"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    role: Mapped[Role] = mapped_column(Enum(Role, name="role"), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    organization: Mapped[Organization] = relationship(back_populates="users")
    # A client user is linked to exactly one company workspace
    company_id: Mapped[str | None] = mapped_column(ForeignKey("companies.id"), nullable=True, index=True)


class UserSession(Base):
    """Server-side sessions — revocable, expiring, not in-memory."""
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)   # random token (hashed)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    ip: Mapped[str] = mapped_column(String(64), default="")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Company(Base):
    """A company being assessed (the client organisation)."""
    __tablename__ = "companies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    sites: Mapped[list] = mapped_column(JSONB, default=list)
    contact: Mapped[str] = mapped_column(String(255), default="")
    scan_consent: Mapped[dict] = mapped_column(JSONB, default=dict)
    applicability_overrides: Mapped[dict] = mapped_column(JSONB, default=dict)
    pending_assessment: Mapped[bool] = mapped_column(Boolean, default=False)
    submission: Mapped[dict] = mapped_column(JSONB, default=dict)
    monitor_frequency: Mapped[str] = mapped_column(String(12), default="off")  # off|weekly|monthly
    next_monitor_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Assessment frameworks: active today = dpdpa; the rest record customer
    # interest so activation is instant when their rulebooks ship.
    frameworks: Mapped[list] = mapped_column(JSONB, default=lambda: ["dpdpa"])
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    connectors: Mapped[list["Connector"]] = relationship(back_populates="company", cascade="all, delete-orphan")
    snapshots: Mapped[list["Snapshot"]] = relationship(back_populates="company", cascade="all, delete-orphan")


class QuestionnaireAnswer(Base):
    __tablename__ = "questionnaire_answers"
    __table_args__ = (UniqueConstraint("company_id", "control_id", name="uq_qa_company_control"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="")
    department: Mapped[str] = mapped_column(String(120), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class Connector(Base):
    """A cloud/infra connector. Credentials are stored ENCRYPTED in `secret_enc`."""
    __tablename__ = "connectors"
    __table_args__ = (UniqueConstraint("company_id", "provider", name="uq_connector_company_provider"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(20), nullable=False)   # aws|azure|intune|gcp|adgpo|firewall
    public_config: Mapped[dict] = mapped_column(JSONB, default=dict)    # non-secret (region, ids masked for display)
    secret_enc: Mapped[str] = mapped_column(Text, default="")          # encrypted JSON blob of secret fields
    consent: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    company: Mapped[Company] = relationship(back_populates="connectors")


class Snapshot(Base):
    """Immutable assessment result."""
    __tablename__ = "snapshots"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # timestamp id
    rulebook_version: Mapped[str] = mapped_column(String(20), nullable=False)
    score: Mapped[float] = mapped_column(default=0.0)
    counts: Mapped[dict] = mapped_column(JSONB, default=dict)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)   # full snapshot (resolutions, meta, evidence)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    created_by: Mapped[str] = mapped_column(String(255), default="")

    company: Mapped[Company] = relationship(back_populates="snapshots")


class Rulebook(Base):
    __tablename__ = "rulebooks"
    __table_args__ = (UniqueConstraint("version", name="uq_rulebook_version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    version: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    source: Mapped[str] = mapped_column(String(20), default="shipped")  # shipped|imported
    imported_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), nullable=False, index=True)
    ntype: Mapped[str] = mapped_column(String(40), default="")
    title: Mapped[str] = mapped_column(String(300), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    email_to: Mapped[str] = mapped_column(String(255), default="")
    email_status: Mapped[str] = mapped_column(String(80), default="")
    email_delivered_to: Mapped[str] = mapped_column(String(255), default="")
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class AiSuggestion(Base):
    """A pending AI-proposed questionnaire mapping, awaiting operator review.
    Never applied automatically — the operator accepts/edits/rejects."""
    __tablename__ = "ai_suggestions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), nullable=False, index=True)
    batch: Mapped[str] = mapped_column(String(36), default="", index=True)
    control_id: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="")
    source_quote: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(10), default="")
    source_name: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ImportJob(Base):
    """A background document-conversion job: any customer document in, an
    import-ready, human-reviewed set of checkpoint answers out. Large documents
    convert chunk by chunk with visible progress instead of blocking a request."""
    __tablename__ = "import_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(12), default="queued")  # queued|running|done|error
    stage: Mapped[str] = mapped_column(String(120), default="")        # human-readable progress line
    total_chunks: Mapped[int] = mapped_column(Integer, default=0)
    done_chunks: Mapped[int] = mapped_column(Integer, default=0)
    found: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AssessJob(Base):
    """A running assessment, narrated: the operator sees what the engine is doing
    (scanning which site, which connector, resolving controls) instead of a
    frozen browser. Same background-thread pattern as ImportJob."""
    __tablename__ = "assess_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(12), default="queued")  # queued|running|done|error
    stage: Mapped[str] = mapped_column(String(200), default="")
    scan_id: Mapped[str] = mapped_column(String(20), default="")       # set on success
    score: Mapped[float] = mapped_column(Float, default=0.0)
    alerts: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RegWatchItem(Base):
    """A document spotted on an official source (MeitY / eGazette / DPB) that may
    affect the rulebook. Detection is automated; judgment stays human: CS/Legal
    review the item and, if it changes the law, publish a new rulebook version."""
    __tablename__ = "reg_watch_items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    source: Mapped[str] = mapped_column(String(255), default="")
    url: Mapped[str] = mapped_column(String(1000), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(12), default="new", index=True)  # new|reviewed
    reviewed_by: Mapped[str] = mapped_column(String(255), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AppSetting(Base):
    """Runtime-editable settings (operational toggles). Secrets stay in env."""
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class AuditLog(Base):
    """Append-only audit trail. Never updated or deleted."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    actor_id: Mapped[str] = mapped_column(String(36), default="")
    actor_email: Mapped[str] = mapped_column(String(255), default="")
    actor_role: Mapped[str] = mapped_column(String(20), default="")
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(40), default="")
    target_id: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
