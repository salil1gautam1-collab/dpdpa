"""Pure status-resolution engine — no I/O.

Combines automated findings + questionnaire assertions + applicability overrides
into control resolutions. Ported from the prototype; the resolution rules are
unchanged (they are the assessed, sound core).
"""
from __future__ import annotations

import hashlib
import json

from .evidence import make_evidence

_WORST = {"gap": 0, "partial": 1, "unknown": 2, "ok": 3, "na": 4}
_MAP = {"ok": "COMPLIANT", "partial": "PARTIAL", "gap": "GAP", "na": "NA", "unknown": "TBC"}


def control_hash(control: dict) -> str:
    canon = json.dumps(control, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]


def _combine_web(findings: list[dict]):
    if not findings:
        return None, []
    worst = min(findings, key=lambda f: _WORST.get(f["status"], 2))["status"]
    ev = [e for f in findings for e in f.get("evidence", [])]
    return worst, ev


def resolve(control: dict, web_by_check: dict, assertions: dict, overrides: dict) -> dict:
    cid = control["id"]
    res = {"controlId": cid, "evidence": [], "basis": "unresolved", "status": "TBC"}

    if cid in overrides:
        ov = overrides[cid]
        res.update(status="NA", basis="override",
                   evidence=[make_evidence("applicability", note=ov.get("reason", "declared not applicable"))])
        return res

    sig, sig_ev = _combine_web(web_by_check.get(control.get("webCheckId"), []))
    a = assertions.get(cid)
    method = control.get("checkMethod")

    if method == "web":
        if sig is not None:
            res.update(status=_MAP[sig], basis="web-scan", evidence=sig_ev)
    elif method in ("questionnaire", "evidence"):
        if a:
            res.update(status=a["status"], basis=method, evidence=a["evidence"])
    elif method == "hybrid":
        if sig == "gap":
            res.update(status="GAP", basis="web-scan", evidence=sig_ev)
            if a and a["status"] == "COMPLIANT":
                res["evidence"] = res["evidence"] + a["evidence"]
                res["conflict"] = "declared COMPLIANT but scanner observed a gap — declaration set aside"
        elif sig == "ok":
            if a and a["status"] in ("COMPLIANT", "PARTIAL", "NA", "GAP"):
                res.update(status=a["status"], basis="hybrid", evidence=sig_ev + a["evidence"])
            else:
                res.update(status="PARTIAL", basis="web-scan",
                           evidence=sig_ev + [make_evidence("note", note="automated signal positive; awaiting manual confirmation to mark COMPLIANT")])
        elif sig == "partial":
            st = a["status"] if a and a["status"] in ("GAP", "NA") else "PARTIAL"
            res.update(status=st, basis="hybrid" if a else "web-scan",
                       evidence=sig_ev + (a["evidence"] if a else []))
        else:
            if a:
                res.update(status=a["status"], basis=method if not sig else "hybrid",
                           evidence=(sig_ev or []) + a["evidence"])
            elif sig:
                res.update(status="TBC" if sig == "unknown" else _MAP[sig],
                           basis="web-scan", evidence=sig_ev)

    if res["status"] == "TBC" and not res["evidence"]:
        res["evidence"] = [make_evidence("absence", note="no automated signal and no declaration — needs manual input")]
    return res


def provenance(snapshot: dict) -> dict:
    """How each checkpoint was assessed: automatically (scan/connectors),
    from the client's declarations (questionnaire), or unconfirmed (needs manual input)."""
    auto = manual = unconfirmed = 0
    for r in snapshot["resolutions"]:
        if r["status"] == "TBC":
            unconfirmed += 1
        elif r.get("basis") in ("web-scan", "hybrid"):
            auto += 1
        else:  # questionnaire / evidence / override
            manual += 1
    determined = auto + manual
    auto_pct = round(100 * auto / determined, 1) if determined else 0.0
    manual_pct = round(100 * manual / determined, 1) if determined else 0.0
    return {"automated": auto, "manual": manual, "unconfirmed": unconfirmed,
            "determined": determined, "automatedPct": auto_pct, "manualPct": manual_pct}


def summarize(snapshot: dict) -> dict:
    counts = {"COMPLIANT": 0, "PARTIAL": 0, "GAP": 0, "NA": 0, "TBC": 0}
    by_cat: dict = {}
    for r in snapshot["resolutions"]:
        counts[r["status"]] += 1
        c = by_cat.setdefault(r["category"], {"COMPLIANT": 0, "PARTIAL": 0, "GAP": 0, "NA": 0, "TBC": 0})
        c[r["status"]] += 1
    determined = counts["COMPLIANT"] + counts["PARTIAL"] + counts["GAP"]
    score = round(100 * (counts["COMPLIANT"] + 0.5 * counts["PARTIAL"]) / determined, 1) if determined else 0.0
    applicable = sum(v for k, v in counts.items() if k != "NA")
    return {"counts": counts, "byCategory": by_cat, "applicable": applicable,
            "determined": determined, "complianceScore": score}
