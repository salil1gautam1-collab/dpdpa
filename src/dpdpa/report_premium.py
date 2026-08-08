"""Premium client-facing report — a branded, print-ready deliverable.

Generates a single self-contained HTML page designed to print/save cleanly as a
PDF (cover page, executive summary, findings by severity with evidence, appendix).
A "Save as PDF" button invokes the browser's print dialog. No dependencies.

The firm brand is configurable via env DPDPA_REPORT_BRAND / DPDPA_REPORT_TAGLINE
so the same engine serves any delivering firm.
"""
from __future__ import annotations

import html
import os

from .engine import summarize
from .report import STATUS_LABELS
from .rulebook import load_rulebook
from .workspace import REPO_ROOT, client_dir, list_snapshots, load_json

BRAND = os.environ.get("DPDPA_REPORT_BRAND", "DPDPA Sentinel")
TAGLINE = os.environ.get("DPDPA_REPORT_TAGLINE", "DPDPA Compliance Assessment")

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATUS_ORDER = {"GAP": 0, "PARTIAL": 1, "TBC": 2, "COMPLIANT": 3, "NA": 4}
SCOL = {"COMPLIANT": "#1a7f37", "PARTIAL": "#b58900", "GAP": "#c62828",
        "NA": "#607d8b", "TBC": "#5c6bc0"}
SEVCOL = {"critical": "#8b0000", "high": "#c62828", "medium": "#b58900", "low": "#607d8b"}


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


_CSS = """
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body { font-family: Georgia, 'Times New Roman', serif; color: #1c2733; margin: 0; line-height: 1.5; }
.sheet { max-width: 900px; margin: 0 auto; padding: 24px; }
.toolbar { position: sticky; top: 0; background: #0d2137; color: #fff; padding: 10px 16px;
  display: flex; justify-content: space-between; align-items: center; font-family: Arial, sans-serif; }
.toolbar button { background: #0d6efd; color: #fff; border: 0; border-radius: 6px; padding: 9px 18px;
  font-size: 14px; cursor: pointer; }
.cover { min-height: 86vh; display: flex; flex-direction: column; justify-content: center;
  border-top: 8px solid #0d2137; padding-top: 40px; }
.cover .kicker { font-family: Arial, sans-serif; letter-spacing: 3px; text-transform: uppercase;
  color: #607d8b; font-size: 13px; }
.cover h1 { font-size: 40px; margin: 10px 0 6px; color: #0d2137; }
.cover .client { font-size: 26px; color: #14324f; margin: 18px 0 4px; }
.cover .meta { color: #5b7186; font-size: 15px; }
.cover .scorebox { margin: 34px 0; display: flex; align-items: center; gap: 24px; }
.donut { width: 150px; height: 150px; border-radius: 50%; flex: none;
  background: conic-gradient(var(--c) calc(var(--p)*1%), #e6ebf0 0); display: flex;
  align-items: center; justify-content: center; }
.donut > div { width: 116px; height: 116px; background: #fff; border-radius: 50%; display: flex;
  flex-direction: column; align-items: center; justify-content: center; }
.donut .n { font-size: 34px; font-weight: bold; color: #0d2137; }
.donut .l { font-size: 11px; color: #5b7186; font-family: Arial, sans-serif; }
.brandline { font-family: Arial, sans-serif; color: #0d2137; font-weight: bold; }
h2.sec { font-size: 22px; color: #0d2137; border-bottom: 2px solid #0d2137; padding-bottom: 6px;
  margin: 34px 0 14px; page-break-after: avoid; }
.tiles { display: flex; gap: 14px; flex-wrap: wrap; margin: 14px 0; }
.tile { flex: 1; min-width: 120px; border: 1px solid #dde5ed; border-radius: 8px; padding: 12px 16px;
  font-family: Arial, sans-serif; }
.tile .n { font-size: 28px; font-weight: bold; }
.tile .l { font-size: 12px; color: #5b7186; }
table { border-collapse: collapse; width: 100%; font-size: 13px; font-family: Arial, sans-serif; }
th, td { border: 1px solid #dde5ed; padding: 7px 9px; text-align: left; vertical-align: top; }
th { background: #eef2f6; }
.finding { border: 1px solid #dde5ed; border-left: 5px solid var(--sc); border-radius: 6px;
  padding: 12px 16px; margin: 12px 0; page-break-inside: avoid; }
.finding h4 { margin: 0 0 4px; font-size: 15px; font-family: Arial, sans-serif; }
.pill { display: inline-block; padding: 1px 9px; border-radius: 10px; color: #fff; font-size: 11px;
  font-family: Arial, sans-serif; }
.ev { font-family: 'Courier New', monospace; font-size: 11px; background: #f5f7fa; border-radius: 4px;
  padding: 6px 8px; margin: 6px 0; color: #3a4a5a; white-space: pre-wrap; word-break: break-word; }
.rec { font-size: 13px; color: #14324f; }
.disc { font-size: 11px; color: #5b7186; border-top: 1px solid #dde5ed; padding-top: 12px; margin-top: 24px; }
.pagebreak { page-break-before: always; }
@media print { .toolbar { display: none; } .sheet { max-width: none; padding: 0; } body { font-size: 12px; } }
"""


def _cover(cfg, snap, s) -> str:
    score = s["complianceScore"]
    color = "#1a7f37" if score >= 80 else "#b58900" if score >= 50 else "#c62828"
    sites = ", ".join(cfg.get("sites", [])) or "Questionnaire &amp; infrastructure assessment"
    return f"""
<div class="cover">
<div class="kicker">{_e(TAGLINE)}</div>
<h1>DPDPA Compliance Assessment</h1>
<div class="client">{_e(cfg['name'])}</div>
<div class="meta">{_e(sites)}</div>
<div class="scorebox">
<div class="donut" style="--p:{score};--c:{color}"><div><div class="n">{score}%</div><div class="l">COMPLIANCE</div></div></div>
<div>
<div style="font-size:15px;color:#5b7186;font-family:Arial">Assessed against the Digital Personal Data<br>
Protection Act, 2023 &amp; DPDP Rules, 2025</div>
<div style="margin-top:12px;font-size:14px">
<b style="color:{SCOL['GAP']}">{s['counts']['GAP']}</b> gaps ·
<b style="color:{SCOL['PARTIAL']}">{s['counts']['PARTIAL']}</b> partial ·
<b style="color:{SCOL['COMPLIANT']}">{s['counts']['COMPLIANT']}</b> compliant ·
<b style="color:{SCOL['TBC']}">{s['counts']['TBC']}</b> to confirm</div>
</div></div>
<div style="margin-top:auto;padding-top:40px">
<div class="brandline">Prepared by {_e(BRAND)}</div>
<div class="meta">Assessment reference {_e(snap['scanId'])} · rulebook v{_e(snap['rulebookVersion'])}</div>
</div></div>"""


def _executive_summary(s, cats, by_cat) -> str:
    tiles = "".join(
        f'<div class="tile"><div class="n" style="color:{SCOL[k]}">{v}</div><div class="l">{STATUS_LABELS[k]}</div></div>'
        for k, v in s["counts"].items())
    # weakest categories by gap count
    ranked = sorted(by_cat.items(), key=lambda kv: -(kv[1]["GAP"] + kv[1]["PARTIAL"]))[:5]
    focus = "".join(
        f"<tr><td>{_e(cats.get(cid, cid))}</td><td>{c['GAP']}</td><td>{c['PARTIAL']}</td>"
        f"<td>{c['COMPLIANT']}</td></tr>" for cid, c in ranked if c["GAP"] + c["PARTIAL"])
    return f"""
<h2 class="sec">Executive summary</h2>
<p>This report assesses {_e('the organisation')}'s posture against {s['determined']} determined DPDPA
checkpoints. The overall compliance score is <b>{s['complianceScore']}%</b>, computed as compliant plus
half-credit for partially-met checkpoints, over all determined (non-N/A) checkpoints.</p>
<div class="tiles">{tiles}</div>
<h3 style="font-family:Arial;font-size:15px;color:#0d2137">Priority focus areas</h3>
<table><tr><th>Area</th><th>Gaps</th><th>Partial</th><th>Compliant</th></tr>{focus or '<tr><td colspan=4>No open items.</td></tr>'}</table>
<p class="rec" style="margin-top:12px">The detailed findings that follow are ordered gaps-first and by severity. Each
carries the evidence on which the status was determined and a recommended remediation. Items marked
"to be confirmed" require inputs not yet available and are listed for completion.</p>"""


def _findings(snap) -> str:
    ordered = sorted(snap["resolutions"],
                     key=lambda r: (STATUS_ORDER[r["status"]], SEV_ORDER[r["severity"]]))
    assessed = [r for r in ordered if r["status"] in ("GAP", "PARTIAL", "COMPLIANT")]
    tbc = [r for r in ordered if r["status"] == "TBC"]
    na = [r for r in ordered if r["status"] == "NA"]

    out = ["<div class='pagebreak'></div><h2 class='sec'>Detailed findings</h2>",
           "<p>Checkpoints assessed from available evidence, gaps and partial items first. "
           "Items awaiting further input are summarised afterwards.</p>"]
    for r in assessed:
        evs = "".join(f'<div class="ev">{_e(x.get("excerpt") or x.get("note") or "")}'
                      + (f'\n{_e(x.get("headers"))}' if x.get("headers") else "") + "</div>"
                      for x in r["evidence"][:3] if (x.get("excerpt") or x.get("note") or x.get("headers")))
        rec = (f'<div class="rec"><b>Recommendation:</b> {_e(r["remediation"])}</div>'
               if r["status"] in ("GAP", "PARTIAL") else "")
        assist = r.get("appAssist", {})
        assist_html = (f'<div class="rec" style="color:#1a7f37"><b>We can assist:</b> {_e(assist.get("how"))} '
                       f'(with your consent, access and permission).</div>'
                       if assist.get("possible") and r["status"] in ("GAP", "PARTIAL") else "")
        out.append(f"""<div class="finding" style="--sc:{SEVCOL[r['severity']]}">
<h4>{_e(r['controlId'])} · {_e(r['title'])}
<span class="pill" style="background:{SCOL[r['status']]}">{STATUS_LABELS[r['status']]}</span>
<span class="pill" style="background:{SEVCOL[r['severity']]}">{_e(r['severity'])}</span></h4>
<div style="font-size:11px;color:#5b7186;font-family:Arial">{_e(r['legalRef'])}</div>
{evs}{rec}{assist_html}</div>""")

    if tbc:
        rows = "".join(f"<tr><td>{_e(r['controlId'])}</td><td>{_e(r['title'])}</td>"
                       f"<td>{_e(r['severity'])}</td><td>{_e(r['legalRef'])}</td></tr>" for r in tbc)
        out.append(f"""<h2 class="sec">Items awaiting further input ({len(tbc)})</h2>
<p>These checkpoints could not be determined from the evidence available at assessment time — typically
they need a questionnaire declaration or a system connection (e.g. a cloud or directory connector).
They are neither compliant nor gaps until assessed.</p>
<table><tr><th>Ref</th><th>Checkpoint</th><th>Severity</th><th>Legal basis</th></tr>{rows}</table>""")

    if na:
        rows = "".join(f"<tr><td>{_e(r['controlId'])}</td><td>{_e(r['title'])}</td></tr>" for r in na)
        out.append(f"""<h2 class="sec">Not applicable ({len(na)})</h2>
<table><tr><th>Ref</th><th>Checkpoint</th></tr>{rows}</table>""")
    return "".join(out)


def _disclaimer() -> str:
    text = (REPO_ROOT / "docs" / "DISCLAIMER.md").read_text(encoding="utf-8")
    body = text.split("---", 1)[-1].strip().replace("\n\n", " ").replace("**", "")
    return f'<div class="disc pagebreak"><b>Disclaimer.</b> {_e(body[:1600])}</div>'


def build(snap: dict) -> str:
    cfg = {"name": snap["client"], "sites": snap.get("meta", {}).get("_sites", [])}
    # sites aren't in the snapshot meta by default; pull from client config
    client_cfg = load_json(client_dir(snap["slug"]) / "client.json", {})
    cfg["sites"] = client_cfg.get("sites", [])
    s = summarize(snap)
    rb = load_rulebook(snap["rulebookVersion"])
    cats = {c["id"]: c["name"] for c in rb["categories"]}
    by_cat = s["byCategory"]
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>DPDPA Compliance Assessment — {_e(cfg['name'])}</title><style>{_CSS}</style></head><body>
<div class="toolbar"><span>{_e(BRAND)} · Client report</span>
<button onclick="window.print()">⭳ Save as PDF</button></div>
<div class="sheet">
{_cover(cfg, snap, s)}
{_executive_summary(s, cats, by_cat)}
{_findings(snap)}
{_disclaimer()}
</div></body></html>"""


def generate(slug: str, snap: dict | None = None) -> str:
    if snap is None:
        snaps = list_snapshots(slug)
        if not snaps:
            raise FileNotFoundError("No scan snapshots — run an assessment first")
        snap = load_json(snaps[-1])
    outdir = client_dir(slug) / "reports"
    outdir.mkdir(parents=True, exist_ok=True)
    p = outdir / "client-report.html"
    p.write_text(build(snap), encoding="utf-8")
    return str(p)
