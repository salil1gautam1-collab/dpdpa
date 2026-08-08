"""Rulebook loading. The law lives in versioned JSON files under rulebook/."""
from __future__ import annotations

import hashlib
import json

from .workspace import RULEBOOK_DIR


def load_rulebook(version: str | None = None) -> dict:
    """Load the latest (or a specific) rulebook version."""
    files = sorted(RULEBOOK_DIR.glob("dpdpa-rulebook.v*.json"))
    if not files:
        raise FileNotFoundError("No rulebook files found under rulebook/")
    if version:
        for f in files:
            rb = json.loads(f.read_text(encoding="utf-8"))
            if rb["rulebookVersion"] == version:
                return rb
        raise ValueError(f"Rulebook version {version} not found")
    return json.loads(files[-1].read_text(encoding="utf-8"))


def controls_by_id(rulebook: dict) -> dict:
    return {c["id"]: c for c in rulebook["controls"]}


def control_hash(control: dict) -> str:
    """Stable hash of a control definition — used by the diff engine to detect
    definition changes across rulebook versions."""
    canon = json.dumps(control, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]
