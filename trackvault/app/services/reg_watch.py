"""Regulatory watch — how the app hears about new DPDP rules.

The government publishes law as documents, not APIs, so the pipeline is:
detection automated, judgment human. This service checks the configured
official pages for links whose text mentions the DPDP framework, records
anything unseen, and surfaces it to CS/Legal on the Rulebook page. A human
reads the document and, if the law moved, publishes a new rulebook version —
which then flags every company and notifies every customer automatically.

Runs on demand (Check now button) and on a schedule (python -m app.ops watch).
Failures on a source are recorded, never fatal — government sites go down.
"""
from __future__ import annotations

import html as _html
import re
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urljoin

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import RegWatchItem

# Server-rendered official/aggregator pages (MeitY's own site is a JS shell a
# plain fetch can't read — kept out of the defaults; sources are editable in
# Settings, so it can be added back if they ever serve real HTML).
DEFAULT_SOURCES = [
    "https://pib.gov.in/allRel.aspx",          # PIB — the day's govt press releases
    "https://www.pib.gov.in/indexd.aspx",      # PIB index
    "https://prsindia.org/theprsblog",         # PRS Legislative Research — law tracking
]

KEYWORDS = ("dpdp", "digital personal data protection", "data protection board",
            "personal data protection")

_LINK = re.compile(r'<a\s[^>]*href="([^"#]+)"[^>]*>(.*?)</a>', re.I | re.S)
_TAGS = re.compile(r"<[^>]+>")


def get_sources(db: Session) -> list[str]:
    from .settings_service import get_raw
    raw = get_raw(db, "reg_sources")
    if raw and raw.strip():
        return [ln.strip() for ln in raw.splitlines() if ln.strip().startswith("http")]
    return list(DEFAULT_SOURCES)


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (TrackVault regulatory watch; compliance monitoring)"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read(2_000_000).decode("utf-8", errors="replace")


def _extract(page: str, base_url: str) -> list[tuple[str, str]]:
    """(url, title) pairs for links whose visible text mentions the framework."""
    out = []
    for href, inner in _LINK.findall(page):
        title = _html.unescape(_TAGS.sub(" ", inner))
        title = re.sub(r"\s+", " ", title).strip()
        hay = (title + " " + href).lower()
        if title and any(k in hay for k in KEYWORDS):
            out.append((urljoin(base_url, href.strip()), title[:480]))
    return out


def check_now(db: Session) -> dict:
    """Scan all sources; store unseen items. Returns a small summary dict."""
    from .settings_service import set_raw
    seen = {i.url for i in db.execute(select(RegWatchItem)).scalars()}
    new_items, errors = [], []
    for src in get_sources(db):
        try:
            for url, title in _extract(_fetch(src), src):
                if url in seen:
                    continue
                seen.add(url)
                db.add(RegWatchItem(source=src, url=url[:990], title=title))
                new_items.append(title)
        except Exception as ex:
            errors.append(f"{src} — {type(ex).__name__}")
    db.commit()
    set_raw(db, "reg_last_check", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    return {"new": len(new_items), "titles": new_items[:10], "errors": errors}


def last_check(db: Session) -> str:
    from .settings_service import get_raw
    return get_raw(db, "reg_last_check") or "never"
