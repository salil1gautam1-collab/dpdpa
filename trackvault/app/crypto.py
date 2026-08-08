"""Envelope encryption for secrets at rest (Fernet / AES-128-CBC + HMAC).

Connector credentials never touch the database in plaintext. The master key
comes from TRACKVAULT_ENCRYPTION_KEY (a urlsafe base64 32-byte key). In dev, if
unset, we derive a key from the app secret so the system still works — /healthz
reports this as insecure so it can't be missed in production.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings


def _fernet() -> Fernet:
    s = get_settings()
    key = s.encryption_key.strip()
    if not key:
        # Derive a stable key from secret_key for dev only.
        digest = hashlib.sha256(("derived::" + s.secret_key).encode()).digest()
        key = base64.urlsafe_b64encode(digest).decode()
    else:
        # Accept a raw base64 key or derive from an arbitrary passphrase.
        try:
            base64.urlsafe_b64decode(key)
            if len(base64.urlsafe_b64decode(key)) != 32:
                raise ValueError
        except Exception:
            digest = hashlib.sha256(key.encode()).digest()
            key = base64.urlsafe_b64encode(digest).decode()
    return Fernet(key.encode())


def using_derived_key() -> bool:
    return not get_settings().encryption_key.strip()


def encrypt_secret(data: dict) -> str:
    """Encrypt a dict of secret fields -> opaque token string."""
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return _fernet().encrypt(raw).decode("ascii")


def decrypt_secret(token: str) -> dict:
    if not token:
        return {}
    try:
        raw = _fernet().decrypt(token.encode("ascii"))
        return json.loads(raw.decode("utf-8"))
    except (InvalidToken, ValueError):
        return {}
