"""Evidence objects and PII masking.

Every stored excerpt passes through mask_pii() so the tool never persists
personal data observed on scanned pages. Integrity of the observed content is
preserved via SHA-256 of the raw bytes (hash first, mask after).
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Indian mobiles: optional +91/0 prefix then 10 digits starting 6-9
_MOBILE = re.compile(r"(?<!\d)(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
_GSTIN = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[A-Z]\d\b")
_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_AADHAAR = re.compile(r"(?<!\d)\d{4}\s\d{4}\s\d{4}(?!\d)")


def mask_pii(text: str) -> str:
    """Redact common Indian PII patterns from text before storage."""
    text = _EMAIL.sub("[email-redacted]", text)
    text = _GSTIN.sub("[gstin-redacted]", text)
    text = _PAN.sub("[pan-redacted]", text)
    text = _AADHAAR.sub("[id-redacted]", text)
    text = _MOBILE.sub("[mobile-redacted]", text)
    return text


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_evidence(kind: str, url: str = "", excerpt: str = "", headers: dict | None = None,
                  raw: bytes | None = None, note: str = "") -> dict:
    """Build an evidence record. `raw` is hashed, never stored."""
    ev = {
        "kind": kind,                     # e.g. "http-headers", "html-excerpt", "absence", "declaration"
        "url": url,
        "observedAt": utc_now(),
    }
    if excerpt:
        ev["excerpt"] = mask_pii(excerpt[:1500])
    if headers:
        keep = {k: v for k, v in headers.items() if k.lower() in (
            "strict-transport-security", "content-security-policy", "x-frame-options",
            "x-content-type-options", "referrer-policy", "server", "x-powered-by",
            "set-cookie", "location", "content-type")}
        ev["headers"] = {k: mask_pii(str(v))[:500] for k, v in keep.items()}
    if raw is not None:
        ev["sha256"] = sha256_hex(raw)
    if note:
        ev["note"] = note
    return ev
