"""Authentication, sessions, RBAC, CSRF, password hashing."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import OPERATOR_ROLES, Role, User, UserSession

_settings = get_settings()
_ph = PasswordHasher(time_cost=_settings.argon2_time_cost,
                     memory_cost=_settings.argon2_memory_kib, parallelism=2)

SESSION_COOKIE = "tv_session"
CSRF_HEADER = "X-CSRF-Token"


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(hashed: str, password: str) -> bool:
    try:
        return _ph.verify(hashed, password)
    except (VerifyMismatchError, Exception):
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return _ph.check_needs_rehash(hashed)
    except Exception:
        return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_session(db: Session, user: User, ip: str = "") -> tuple[str, str]:
    """Create a server-side session. Returns (raw_cookie_token, csrf_token)."""
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    sess = UserSession(
        id=_hash_token(raw), user_id=user.id, csrf_token=csrf,
        expires_at=_now() + timedelta(hours=_settings.session_ttl_hours),
        last_seen_at=_now(), ip=ip,
    )
    db.add(sess)
    db.commit()
    return raw, csrf


def revoke_session(db: Session, raw_token: str) -> None:
    sess = db.get(UserSession, _hash_token(raw_token))
    if sess:
        sess.revoked = True
        db.commit()


class Principal:
    """The authenticated user + their live session, attached to the request."""
    def __init__(self, user: User, session: UserSession):
        self.user = user
        self.session = session

    @property
    def is_operator(self) -> bool:
        return self.user.role in OPERATOR_ROLES

    @property
    def is_client(self) -> bool:
        return self.user.role == Role.client


def _load_principal(request: Request, db: Session) -> Principal | None:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    sess = db.get(UserSession, _hash_token(raw))
    if not sess or sess.revoked:
        return None
    now = _now()
    if sess.expires_at <= now:
        return None
    if sess.last_seen_at + timedelta(minutes=_settings.session_idle_minutes) < now:
        return None
    user = db.get(User, sess.user_id)
    if not user or not user.is_active:
        return None
    sess.last_seen_at = now
    db.commit()
    return Principal(user, sess)


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal | None:
    return _load_principal(request, db)


def require_user(request: Request, db: Session = Depends(get_db)) -> Principal:
    p = _load_principal(request, db)
    if not p:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in required")
    return p


def require_roles(*roles: Role):
    allowed = set(roles)

    def dep(p: Principal = Depends(require_user)) -> Principal:
        if p.user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return p
    return dep


def require_operator(p: Principal = Depends(require_user)) -> Principal:
    if not p.is_operator:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator access required")
    return p


def verify_csrf(request: Request, p: Principal) -> None:
    """For state-changing requests: token from form or header must match session."""
    token = request.headers.get(CSRF_HEADER, "")
    if not token:
        # form-encoded fallback is checked by the route (it has the parsed form)
        token = getattr(request.state, "csrf_form_token", "")
    if not token or not secrets.compare_digest(token, p.session.csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
