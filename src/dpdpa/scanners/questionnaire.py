"""Questionnaire importer — the manual-entry side of the scan.

local/<slug>/questionnaire.json shape:
{
  "assertions": [
    {"controlId": "SEC-01", "status": "GAP",
     "evidence": "Security measures marked Not Compliant in IT and Dial B2B responses",
     "source": {"department": "IT / Technology", "respondent": "questionnaire", "date": "2026-08"}}
  ],
  "departments": [ { "name": "...", "parts": { "A": {...}, ... } } ]   // optional Parts A-M blocks
}

Statuses accepted: COMPLIANT | PARTIAL | GAP | NA | TBC.
The engine treats these as declarations: they can settle `questionnaire`
controls outright, and they can *confirm* (but never override a scanner GAP on)
`hybrid` controls.
"""
from __future__ import annotations

from ..evidence import make_evidence, mask_pii
from ..workspace import client_dir, load_json

VALID = {"COMPLIANT", "PARTIAL", "GAP", "NA", "TBC"}


def load_assertions(slug: str, valid_control_ids: set[str]) -> tuple[dict, list[str]]:
    """Return ({controlId: assertion}, warnings)."""
    data = load_json(client_dir(slug) / "questionnaire.json", {})
    warnings, out = [], {}
    for a in data.get("assertions", []):
        cid, st = a.get("controlId", ""), str(a.get("status", "")).upper()
        if cid not in valid_control_ids:
            warnings.append(f"questionnaire: unknown controlId '{cid}' ignored")
            continue
        if st not in VALID:
            warnings.append(f"questionnaire: invalid status '{st}' for {cid} ignored")
            continue
        src = a.get("source", {})
        out[cid] = {
            "status": st,
            "evidence": [make_evidence(
                "declaration",
                excerpt=mask_pii(str(a.get("evidence", ""))),
                note=f"declared by {src.get('department', '?')} / {src.get('respondent', '?')} on {src.get('date', '?')}")],
        }
    return out, warnings


def department_coverage(slug: str) -> list[dict]:
    """Summarise which departments have submitted questionnaire blocks."""
    data = load_json(client_dir(slug) / "questionnaire.json", {})
    out = []
    for d in data.get("departments", []):
        parts = d.get("parts", {})
        out.append({"department": d.get("name", "?"),
                    "partsAnswered": sorted(parts.keys()),
                    "partsPending": [p for p in "ABCDEFGHIJKLM" if p not in parts]})
    return out
