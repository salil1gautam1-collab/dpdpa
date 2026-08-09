"""Change detection between two assessment snapshots — the monitoring engine.

Produces alerts when a re-assessment shows something got worse or new:
  REGRESSION       a checkpoint moved to a worse status (e.g. Compliant -> Gap)
  NEW_THIRD_PARTY  a tracker/third party appeared that wasn't seen before
  RULEBOOK_CHANGED the assessment used a newer rulebook (new law requirements)
"""
from __future__ import annotations

_RANK = {"COMPLIANT": 3, "PARTIAL": 2, "TBC": 1, "GAP": 0, "NA": 2}


def _trackers(meta: dict) -> set:
    out = set()
    for host, lst in (meta.get("trackersObserved") or {}).items():
        for t in lst or []:
            out.add(t)
    return out


def compute_alerts(prev: dict, curr: dict) -> list[dict]:
    if not prev:
        return []
    alerts: list[dict] = []
    a = {r["controlId"]: r for r in prev.get("resolutions", [])}
    b = {r["controlId"]: r for r in curr.get("resolutions", [])}

    for cid, rc in b.items():
        ra = a.get(cid)
        if ra is None:
            continue  # new control handled via RULEBOOK_CHANGED below
        if ra["status"] != rc["status"] and _RANK[rc["status"]] < _RANK[ra["status"]]:
            alerts.append({"type": "REGRESSION", "controlId": cid, "title": rc.get("title", ""),
                           "severity": rc.get("severity", ""),
                           "detail": f"{ra['status']} → {rc['status']}"})

    new_tp = _trackers(curr.get("meta", {})) - _trackers(prev.get("meta", {}))
    for t in sorted(new_tp):
        alerts.append({"type": "NEW_THIRD_PARTY", "controlId": "PR-03",
                       "title": "New third party observed", "severity": "high",
                       "detail": f"{t} appeared since the last assessment"})

    if prev.get("rulebookVersion") and prev["rulebookVersion"] != curr.get("rulebookVersion"):
        alerts.append({"type": "RULEBOOK_CHANGED", "controlId": "", "title": "Rulebook updated",
                       "severity": "medium",
                       "detail": f"v{prev['rulebookVersion']} → v{curr['rulebookVersion']} (new DPDPA requirements)"})

    # regressions first, then by severity
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
    alerts.sort(key=lambda x: (x["type"] != "REGRESSION", sev.get(x.get("severity", ""), 4)))
    return alerts


def summarize_alerts(alerts: list[dict]) -> str:
    if not alerts:
        return ""
    lines = []
    for a in alerts[:12]:
        cid = f"{a['controlId']} " if a.get("controlId") else ""
        lines.append(f"• [{a['type'].replace('_', ' ').title()}] {cid}{a.get('title','')} — {a.get('detail','')}")
    if len(alerts) > 12:
        lines.append(f"• …and {len(alerts) - 12} more")
    return "\n".join(lines)
