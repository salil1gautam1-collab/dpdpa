"""Status resolution engine.

Combines automated findings + questionnaire assertions + applicability
overrides into one immutable scan snapshot.

Resolution rules:
  web           scanner decides (ok/partial/gap/na/unknown -> COMPLIANT/PARTIAL/GAP/NA/TBC)
  questionnaire declaration decides; nothing declared -> TBC
  evidence      same as questionnaire (declaration = evidence attached)
  hybrid        scanner GAP always wins (a declaration cannot override observed absence);
                scanner ok + declaration COMPLIANT -> COMPLIANT;
                scanner ok + no declaration       -> PARTIAL (never auto-COMPLIANT);
                otherwise the weaker of the two signals; nothing -> TBC
"""
from __future__ import annotations

from datetime import datetime, timezone

from .evidence import make_evidence, utc_now
from .rulebook import control_hash, load_rulebook
from .scanners import infra, questionnaire as qn, web
from .workspace import client_dir, load_client, save_json

_WORST = {"gap": 0, "partial": 1, "unknown": 2, "ok": 3, "na": 4}
_MAP = {"ok": "COMPLIANT", "partial": "PARTIAL", "gap": "GAP", "na": "NA", "unknown": "TBC"}


def _combine_web(findings: list[dict]) -> tuple[str | None, list]:
    """Worst status across sites for one webCheckId, with merged evidence."""
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
        else:  # unknown / na / no automated signal
            if a:
                res.update(status=a["status"], basis=method if not sig else "hybrid",
                           evidence=(sig_ev or []) + a["evidence"])
            elif sig:
                res.update(status="TBC" if sig == "unknown" else _MAP[sig],
                           basis="web-scan", evidence=sig_ev)

    if res["status"] == "TBC" and not res["evidence"]:
        res["evidence"] = [make_evidence("absence", note="no automated signal and no declaration — needs manual input")]
    return res


def run_scan(slug: str, skip_web: bool = False) -> dict:
    cfg = load_client(slug)
    rb = load_rulebook()
    started = utc_now()
    warnings: list[str] = []

    consent = cfg.get("scanConsent", {})
    if not skip_web and not consent.get("granted"):
        raise PermissionError(
            "scanConsent.granted is false in client.json — record the client's written "
            "authorisation before scanning, or run with --skip-web for questionnaire-only.")

    findings, meta = ([], {"webScanner": "skipped"}) if skip_web else web.run(cfg.get("sites", []))
    infra_findings, infra_meta = infra.run(cfg)
    findings += infra_findings
    meta.update(infra_meta)

    assertions, warn2 = qn.load_assertions(slug, {c["id"] for c in rb["controls"]})
    warnings += warn2

    web_by_check: dict = {}
    for f in findings:
        web_by_check.setdefault(f["webCheckId"], []).append(f)

    overrides = cfg.get("applicabilityOverrides", {})
    resolutions = []
    for c in rb["controls"]:
        r = resolve(c, web_by_check, assertions, overrides)
        r.update(title=c["title"], category=c["category"], severity=c["severity"],
                 legalRef=c["legalRef"], remediation=c["remediation"],
                 appAssist=c.get("appAssist", {}), checkMethod=c["checkMethod"],
                 controlHash=control_hash(c))
        resolutions.append(r)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot = {
        "scanId": ts,
        "client": cfg["name"],
        "slug": slug,
        "rulebookVersion": rb["rulebookVersion"],
        "startedAt": started,
        "finishedAt": utc_now(),
        "warnings": warnings,
        "meta": meta,
        "departmentCoverage": qn.department_coverage(slug),
        "resolutions": resolutions,
    }
    save_json(client_dir(slug) / "scans" / f"{ts}.json", snapshot)
    return snapshot


def summarize(snapshot: dict) -> dict:
    counts = {"COMPLIANT": 0, "PARTIAL": 0, "GAP": 0, "NA": 0, "TBC": 0}
    by_cat: dict = {}
    for r in snapshot["resolutions"]:
        counts[r["status"]] += 1
        c = by_cat.setdefault(r["category"], {"COMPLIANT": 0, "PARTIAL": 0, "GAP": 0, "NA": 0, "TBC": 0})
        c[r["status"]] += 1
    applicable = sum(v for k, v in counts.items() if k != "NA")
    determined = counts["COMPLIANT"] + counts["PARTIAL"] + counts["GAP"]
    score = round(100 * (counts["COMPLIANT"] + 0.5 * counts["PARTIAL"]) / determined, 1) if determined else 0.0
    return {"counts": counts, "byCategory": by_cat, "applicable": applicable,
            "determined": determined, "complianceScore": score}
