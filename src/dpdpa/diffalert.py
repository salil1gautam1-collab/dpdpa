"""Diff engine — compares the two latest scan snapshots and raises alerts.

Alert types:
  REGRESSION   a checkpoint moved away from COMPLIANT (or PARTIAL -> GAP)
  IMPROVEMENT  a checkpoint improved
  NEW_CONTROL  rulebook upgrade introduced a checkpoint not previously assessed
  DEFINITION_CHANGED  a control's definition hash changed across rulebook versions
  NEW_THIRD_PARTY     a tracker/cookie appeared that wasn't in the previous scan

Production adds SMTP/webhook dispatch; prototype writes alerts.json + stdout.
"""
from __future__ import annotations

from .evidence import utc_now
from .workspace import client_dir, load_json, list_snapshots, save_json

_RANK = {"COMPLIANT": 3, "PARTIAL": 2, "TBC": 1, "GAP": 0, "NA": 2}


def diff(slug: str) -> dict:
    snaps = list_snapshots(slug)
    if len(snaps) < 2:
        return {"generatedAt": utc_now(), "alerts": [],
                "note": "fewer than two snapshots — nothing to compare yet"}
    prev, curr = load_json(snaps[-2]), load_json(snaps[-1])
    p = {r["controlId"]: r for r in prev["resolutions"]}
    c = {r["controlId"]: r for r in curr["resolutions"]}
    alerts = []

    for cid, rc in c.items():
        rp = p.get(cid)
        if rp is None:
            alerts.append({"type": "NEW_CONTROL", "controlId": cid, "title": rc["title"],
                           "detail": f"introduced in rulebook v{curr['rulebookVersion']} — status {rc['status']}"})
            continue
        if rp.get("controlHash") != rc.get("controlHash"):
            alerts.append({"type": "DEFINITION_CHANGED", "controlId": cid, "title": rc["title"],
                           "detail": "control definition changed across rulebook versions — re-verify"})
        if rp["status"] != rc["status"]:
            kind = "REGRESSION" if _RANK[rc["status"]] < _RANK[rp["status"]] else "IMPROVEMENT"
            alerts.append({"type": kind, "controlId": cid, "title": rc["title"],
                           "severity": rc["severity"],
                           "detail": f"{rp['status']} -> {rc['status']} (basis: {rc['basis']})"})

    prev_trk = prev.get("meta", {}).get("trackersObserved", {})
    for site, trackers in curr.get("meta", {}).get("trackersObserved", {}).items():
        new = set(trackers) - set(prev_trk.get(site, []))
        for t in sorted(new):
            alerts.append({"type": "NEW_THIRD_PARTY", "controlId": "PR-03",
                           "title": "New third-party tracker observed", "severity": "high",
                           "detail": f"{t} appeared on {site} — reconcile against processor register"})

    result = {"generatedAt": utc_now(), "comparedScans": [prev["scanId"], curr["scanId"]],
              "alerts": alerts}
    save_json(client_dir(slug) / "alerts.json", result)
    return result
