"""Rulebook loading. The law lives in versioned JSON files under rulebook/."""
from __future__ import annotations

import hashlib
import json

from .workspace import LOCAL_ROOT, RULEBOOK_DIR

# Rulebooks imported at runtime (by CS/Legal) live in the data volume so they
# persist across container rebuilds and never dirty the shipped repo.
IMPORT_DIR = LOCAL_ROOT / "_rulebooks"


def _version_key(v: str):
    parts = []
    for p in v.split("."):
        parts.append(int(p) if p.isdigit() else 0)
    return parts


def all_rulebooks() -> list[dict]:
    """All rulebooks (shipped + imported), de-duplicated by version, newest last."""
    seen, out = {}, []
    for d in (RULEBOOK_DIR, IMPORT_DIR):
        if not d.exists():
            continue
        for f in d.glob("dpdpa-rulebook.v*.json"):
            try:
                rb = json.loads(f.read_text(encoding="utf-8"))
                seen[rb["rulebookVersion"]] = rb  # imported overrides shipped for same version
            except (json.JSONDecodeError, KeyError):
                continue
    out = sorted(seen.values(), key=lambda rb: _version_key(rb["rulebookVersion"]))
    if not out:
        raise FileNotFoundError("No rulebook files found")
    return out


def load_rulebook(version: str | None = None) -> dict:
    """Load the latest (or a specific) rulebook version, shipped or imported."""
    books = all_rulebooks()
    if version:
        for rb in books:
            if rb["rulebookVersion"] == version:
                return rb
        raise ValueError(f"Rulebook version {version} not found")
    return books[-1]


def controls_by_id(rulebook: dict) -> dict:
    return {c["id"]: c for c in rulebook["controls"]}


def control_hash(control: dict) -> str:
    """Stable hash of a control definition — used by the diff engine to detect
    definition changes across rulebook versions."""
    canon = json.dumps(control, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]
