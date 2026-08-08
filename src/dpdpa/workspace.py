"""Client workspace management. All state is plain JSON under local/<client-slug>/.

Layout:
  local/<slug>/client.json           engagement config
  local/<slug>/questionnaire.json    manual answers / control assertions
  local/<slug>/scans/<ts>.json       immutable scan snapshots
  local/<slug>/reports/              generated reports
  local/<slug>/alerts.json           latest diff alerts
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LOCAL_ROOT = REPO_ROOT / "local"
RULEBOOK_DIR = REPO_ROOT / "rulebook"


def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def client_dir(slug: str) -> Path:
    return LOCAL_ROOT / slug


def load_json(path: Path, default=None):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def init_client(name: str, sites: list[str]) -> str:
    slug = slugify(name)
    d = client_dir(slug)
    cfg_path = d / "client.json"
    if cfg_path.exists():
        return slug
    save_json(cfg_path, {
        "name": name,
        "slug": slug,
        "sites": sites,
        "scanConsent": {"granted": False, "grantedBy": "", "date": "",
                        "note": "Set granted=true only after written authorisation to scan."},
        "applicabilityOverrides": {},
        "schedule": {"frequency": "weekly"},
    })
    (d / "scans").mkdir(parents=True, exist_ok=True)
    (d / "reports").mkdir(parents=True, exist_ok=True)
    return slug


def load_client(slug: str) -> dict:
    cfg = load_json(client_dir(slug) / "client.json")
    if cfg is None:
        raise FileNotFoundError(f"No client workspace: local/{slug}/client.json (run: dpdpa init)")
    return cfg


def list_snapshots(slug: str) -> list[Path]:
    scans = client_dir(slug) / "scans"
    if not scans.exists():
        return []
    return sorted(scans.glob("*.json"))
