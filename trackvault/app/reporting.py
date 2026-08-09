"""Client-facing report rendering (branded, print/PDF-ready). Pure functions
over a snapshot dict + rulebook dict — no I/O."""
from __future__ import annotations

import html

from .config import get_settings
from .domain.engine import provenance, summarize

STATUS_LABELS = {"COMPLIANT": "Compliant", "PARTIAL": "Partial", "GAP": "Gap",
                 "NA": "Not applicable", "TBC": "To be confirmed"}
SCOL = {"COMPLIANT": "#1a7f37", "PARTIAL": "#b58900", "GAP": "#c62828", "NA": "#607d8b", "TBC": "#5c6bc0"}
SEVCOL = {"critical": "#8b0000", "high": "#c62828", "medium": "#b58900", "low": "#607d8b"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATUS_ORDER = {"GAP": 0, "PARTIAL": 1, "TBC": 2, "COMPLIANT": 3, "NA": 4}

DISCLAIMER = ("This report identifies potential compliance gaps against the Digital Personal Data "
    "Protection Act, 2023 and the DPDP Rules, 2025, and records evidence of what was observed. It "
    "produces recommendations; it is not legal advice, and it does not by itself make an organisation "
    "compliant. Remediation of identified gaps is the organisation's responsibility; where assistance is "
    "offered it runs only with the organisation's explicit consent, access and permission. Automated "
    "checks cover what is observable; internal controls are assessed from declarations and evidence. A "
    "checkpoint marked Compliant reflects the evidence available at assessment time, not a guarantee "
    "against regulatory findings.")

_CSS = """
@page{size:A4;margin:18mm 16mm}*{box-sizing:border-box}
body{font-family:Georgia,'Times New Roman',serif;color:#1c2733;margin:0;line-height:1.5}
.sheet{max-width:900px;margin:0 auto;padding:24px}
.toolbar{position:sticky;top:0;background:#0d2137;color:#fff;padding:10px 16px;display:flex;
justify-content:space-between;align-items:center;font-family:Arial,sans-serif}
.toolbar button{background:#0d6efd;color:#fff;border:0;border-radius:6px;padding:9px 18px;font-size:14px;cursor:pointer}
.cover{min-height:82vh;display:flex;flex-direction:column;justify-content:center;border-top:8px solid #0d2137;padding-top:40px}
.kicker{font-family:Arial,sans-serif;letter-spacing:3px;text-transform:uppercase;color:#607d8b;font-size:13px}
.cover h1{font-size:40px;margin:10px 0 6px;color:#0d2137}.client{font-size:26px;color:#14324f;margin:18px 0 4px}
.meta{color:#5b7186;font-size:15px}.scorebox{margin:34px 0;display:flex;align-items:center;gap:24px}
.donut{width:150px;height:150px;border-radius:50%;flex:none;background:conic-gradient(var(--c) calc(var(--p)*1%),#e6ebf0 0);display:flex;align-items:center;justify-content:center}
.donut>div{width:116px;height:116px;background:#fff;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center}
.donut .n{font-size:34px;font-weight:bold;color:#0d2137}.donut .l{font-size:11px;color:#5b7186;font-family:Arial}
h2.sec{font-size:22px;color:#0d2137;border-bottom:2px solid #0d2137;padding-bottom:6px;margin:34px 0 14px}
.tiles{display:flex;gap:14px;flex-wrap:wrap;margin:14px 0}
.tile{flex:1;min-width:120px;border:1px solid #dde5ed;border-radius:8px;padding:12px 16px;font-family:Arial}
.tile .n{font-size:28px;font-weight:bold}.tile .l{font-size:12px;color:#5b7186}
table{border-collapse:collapse;width:100%;font-size:13px;font-family:Arial}
th,td{border:1px solid #dde5ed;padding:7px 9px;text-align:left;vertical-align:top}th{background:#eef2f6}
.finding{border:1px solid #dde5ed;border-left:5px solid var(--sc);border-radius:6px;padding:12px 16px;margin:12px 0;page-break-inside:avoid}
.finding h4{margin:0 0 4px;font-size:15px;font-family:Arial}
.pill{display:inline-block;padding:1px 9px;border-radius:10px;color:#fff;font-size:11px;font-family:Arial}
.ev{font-family:'Courier New',monospace;font-size:11px;background:#f5f7fa;border-radius:4px;padding:6px 8px;margin:6px 0;color:#3a4a5a;white-space:pre-wrap;word-break:break-word}
.rec{font-size:13px;color:#14324f}.disc{font-size:11px;color:#5b7186;border-top:1px solid #dde5ed;padding-top:12px;margin-top:24px}
.pagebreak{page-break-before:always}
@media print{.toolbar{display:none}.sheet{max-width:none;padding:0}body{font-size:12px}}
"""


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def client_report(snap: dict, rulebook: dict, sites: list) -> str:
    brand = get_settings().brand
    s = summarize(snap)
    score = s["complianceScore"]
    color = "#1a7f37" if score >= 80 else "#b58900" if score >= 50 else "#c62828"
    cats = {c["id"]: c["name"] for c in rulebook["categories"]}

    pv = provenance(snap)
    tiles = "".join(f'<div class="tile"><div class="n" style="color:{SCOL[k]}">{v}</div>'
                    f'<div class="l">{STATUS_LABELS[k]}</div></div>' for k, v in s["counts"].items())
    apct, mpct = pv["automatedPct"], pv["manualPct"]
    provenance_panel = f"""
<h2 class="sec">How this assessment was gathered</h2>
<p>Of the <b>{pv['determined']}</b> checkpoints that could be assessed,
<b style="color:#1a7f37">{apct}%</b> were <b>independently verified by {_e(brand)} scans</b>
(website, cloud and infrastructure connectors), and <b>{mpct}%</b> came from the organisation's own
declarations. <b>{pv['unconfirmed']}</b> further checkpoint(s) could not be verified automatically and
require manual confirmation (listed at the end).</p>
<div style="display:flex;height:26px;border-radius:6px;overflow:hidden;font-family:Arial;font-size:12px;margin:12px 0;border:1px solid #dde5ed">
<div style="width:{apct}%;background:#1a7f37;color:#fff;display:flex;align-items:center;justify-content:center">{apct}% automated</div>
<div style="width:{mpct}%;background:#b58900;color:#fff;display:flex;align-items:center;justify-content:center">{mpct}% declared</div>
</div>
<p class="rec" style="font-size:12.5px">A higher automated share means stronger, evidence-backed assurance.
Connecting more systems (cloud accounts, endpoints, directory, firewall) moves checkpoints from declared to
independently verified — and reduces the manual effort required.</p>"""
    ranked = sorted(s["byCategory"].items(), key=lambda kv: -(kv[1]["GAP"] + kv[1]["PARTIAL"]))
    focus = "".join(f"<tr><td>{_e(cats.get(cid,cid))}</td><td>{c['GAP']}</td><td>{c['PARTIAL']}</td>"
                    f"<td>{c['COMPLIANT']}</td></tr>" for cid, c in ranked if c["GAP"] + c["PARTIAL"])

    ordered = sorted(snap["resolutions"], key=lambda r: (STATUS_ORDER[r["status"]], SEV_ORDER[r["severity"]]))
    assessed = [r for r in ordered if r["status"] in ("GAP", "PARTIAL", "COMPLIANT")]
    tbc = [r for r in ordered if r["status"] == "TBC"]
    na = [r for r in ordered if r["status"] == "NA"]

    cards = []
    for r in assessed:
        evs = "".join(f'<div class="ev">{_e(x.get("excerpt") or x.get("note") or "")}</div>'
                      for x in r["evidence"][:3] if (x.get("excerpt") or x.get("note")))
        rec = (f'<div class="rec"><b>Recommendation:</b> {_e(r["remediation"])}</div>'
               if r["status"] in ("GAP", "PARTIAL") else "")
        cards.append(f'<div class="finding" style="--sc:{SEVCOL[r["severity"]]}">'
                     f'<h4>{_e(r["controlId"])} · {_e(r["title"])} '
                     f'<span class="pill" style="background:{SCOL[r["status"]]}">{STATUS_LABELS[r["status"]]}</span> '
                     f'<span class="pill" style="background:{SEVCOL[r["severity"]]}">{_e(r["severity"])}</span></h4>'
                     f'<div style="font-size:11px;color:#5b7186;font-family:Arial">{_e(r["legalRef"])}</div>{evs}{rec}</div>')

    tbc_tbl = ""
    if tbc:
        rows = "".join(f"<tr><td>{_e(r['controlId'])}</td><td>{_e(r['title'])}</td><td>{_e(r['severity'])}</td></tr>" for r in tbc)
        tbc_tbl = (f'<h2 class="sec">Items awaiting further input ({len(tbc)})</h2>'
                   f'<p>These need a declaration or a system connection to assess.</p>'
                   f'<table><tr><th>Ref</th><th>Checkpoint</th><th>Severity</th></tr>{rows}</table>')
    na_tbl = ""
    if na:
        rows = "".join(f"<tr><td>{_e(r['controlId'])}</td><td>{_e(r['title'])}</td></tr>" for r in na)
        na_tbl = f'<h2 class="sec">Not applicable ({len(na)})</h2><table><tr><th>Ref</th><th>Checkpoint</th></tr>{rows}</table>'

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>DPDPA Compliance Assessment — {_e(snap['client'])}</title><style>{_CSS}</style></head><body>
<div class="toolbar"><span>{_e(brand)} · Client report</span><button id="printBtn">⭳ Save as PDF</button></div>
<div class="sheet">
<div class="cover"><div class="kicker">DPDPA Compliance Assessment</div>
<h1>DPDPA Compliance Assessment</h1><div class="client">{_e(snap['client'])}</div>
<div class="meta">{_e(', '.join(sites) or 'Questionnaire &amp; infrastructure assessment')}</div>
<div class="scorebox"><div class="donut" style="--p:{score};--c:{color}"><div><div class="n">{score}%</div><div class="l">COMPLIANCE</div></div></div>
<div><div style="font-size:15px;color:#5b7186;font-family:Arial">Assessed against the Digital Personal Data<br>Protection Act, 2023 &amp; DPDP Rules, 2025</div>
<div style="margin-top:12px;font-size:14px"><b style="color:{SCOL['GAP']}">{s['counts']['GAP']}</b> gaps ·
<b style="color:{SCOL['PARTIAL']}">{s['counts']['PARTIAL']}</b> partial ·
<b style="color:{SCOL['COMPLIANT']}">{s['counts']['COMPLIANT']}</b> compliant</div></div></div>
<div style="margin-top:auto;padding-top:40px"><div style="font-family:Arial;color:#0d2137;font-weight:bold">Prepared by {_e(brand)}</div>
<div class="meta">Assessment reference {_e(snap['scanId'])} · rulebook v{_e(snap['rulebookVersion'])}</div></div></div>
<h2 class="sec">Executive summary</h2>
<p>This report assesses {s['determined']} determined DPDPA checkpoints. Overall compliance score:
<b>{score}%</b> (compliant plus half-credit for partial, over all determined checkpoints).</p>
<div class="tiles">{tiles}</div>
<h3 style="font-family:Arial;font-size:15px;color:#0d2137">Priority focus areas</h3>
<table><tr><th>Area</th><th>Gaps</th><th>Partial</th><th>Compliant</th></tr>{focus or '<tr><td colspan=4>No open items.</td></tr>'}</table>
{provenance_panel}
<div class="pagebreak"></div><h2 class="sec">Detailed findings</h2>
<p>Gaps and partial items first, each with evidence and a recommendation.</p>{''.join(cards)}
{tbc_tbl}{na_tbl}
<div class="disc pagebreak"><b>Disclaimer.</b> {_e(DISCLAIMER)}</div>
</div><script src="/static/report.js"></script></body></html>"""


def gap_assessment(snap: dict, rulebook: dict, sites: list) -> str:
    """The detailed working document alongside the executive client report:
    discovery surface, the full gap register (with Owner / Target-date columns
    to fill in), partials, and the to-confirm worklist grouped by area."""
    brand = get_settings().brand
    s = summarize(snap)
    cats = {c["id"]: c["name"] for c in rulebook["categories"]}
    meta = snap.get("meta", {}) or {}
    d = snap["scanId"]
    date_fmt = f"{d[:4]}-{d[4:6]}-{d[6:8]}"

    # --- discovery surface -------------------------------------------------
    pages = meta.get("pagesScanned") or []
    connectors = [k[:-9] for k, v in meta.items() if k.endswith("Connector") and v == "ran"]
    conn_line = ", ".join(connectors) if connectors else "none connected"
    web_line = (f"{len(pages)} page(s) scanned" if pages
                else _e(meta.get("webScanner", "not run")))
    forms = meta.get("formsFound")
    surface_rows = "".join([
        f"<tr><th>Websites in scope</th><td>{_e(', '.join(sites) or '—')}</td></tr>",
        f"<tr><th>Website scan</th><td>{web_line}</td></tr>",
        (f"<tr><th>Data-collection forms found</th><td>{_e(forms)}</td></tr>" if forms is not None else ""),
        f"<tr><th>Infrastructure connectors</th><td>{_e(conn_line)}</td></tr>",
        f"<tr><th>Questionnaire declarations</th><td>merged into every applicable checkpoint</td></tr>",
    ])

    def _evcell(r, limit=2):
        out = []
        for x in (r.get("evidence") or [])[:limit]:
            t = x.get("excerpt") or x.get("note") or ""
            if t:
                out.append(f'<div class="ev">{_e(t[:220])}</div>')
        return "".join(out) or '<span style="color:#5b7186">—</span>'

    ordered = sorted(snap["resolutions"], key=lambda r: (SEV_ORDER[r["severity"]], r["controlId"]))
    gaps = [r for r in ordered if r["status"] == "GAP"]
    partials = [r for r in ordered if r["status"] == "PARTIAL"]
    tbc = [r for r in ordered if r["status"] == "TBC"]

    def register(rows, title, note):
        if not rows:
            return ""
        body = "".join(
            f'<tr><td class="tag">{_e(r["controlId"])}</td>'
            f'<td><b>{_e(r["title"])}</b><div style="font-size:11px;color:#5b7186">{_e(cats.get(r["category"], r["category"]))} · {_e(r["legalRef"])}</div></td>'
            f'<td><span class="pill" style="background:{SEVCOL[r["severity"]]}">{_e(r["severity"])}</span></td>'
            f'<td>{_evcell(r)}</td>'
            f'<td class="rec">{_e(r["remediation"])}</td>'
            f'<td></td><td></td></tr>' for r in rows)
        return (f'<h2 class="sec">{title} ({len(rows)})</h2><p>{note}</p>'
                f'<table><tr><th style="width:60px">Ref</th><th style="width:24%">Checkpoint</th>'
                f'<th>Severity</th><th style="width:24%">What we observed</th>'
                f'<th style="width:24%">Recommended remediation</th>'
                f'<th style="width:90px">Owner</th><th style="width:90px">Target date</th></tr>{body}</table>')

    tbc_html = ""
    if tbc:
        by_cat: dict = {}
        for r in tbc:
            by_cat.setdefault(r["category"], []).append(r)
        blocks = ""
        for cid_, rows in by_cat.items():
            items = "".join(f"<tr><td class='tag'>{_e(r['controlId'])}</td><td>{_e(r['title'])}</td>"
                            f"<td>{_e(r['severity'])}</td></tr>" for r in rows)
            blocks += (f"<h3 style='font-family:Arial;font-size:14px;color:#0d2137'>"
                       f"{_e(cats.get(cid_, cid_))} ({len(rows)})</h3>"
                       f"<table><tr><th style='width:60px'>Ref</th><th>Checkpoint</th><th>Severity</th></tr>{items}</table>")
        tbc_html = (f'<div class="pagebreak"></div><h2 class="sec">To confirm — the follow-up worklist ({len(tbc)})</h2>'
                    f'<p>These checkpoints could not be verified automatically and are not yet declared. '
                    f'Each needs either a questionnaire answer, a document, or a system connection.</p>{blocks}')

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>DPDPA Gap Assessment — {_e(snap['client'])}</title><style>{_CSS}</style></head><body>
<div class="toolbar"><span>{_e(brand)} · Gap assessment (working document)</span><button id="printBtn">⭳ Save as PDF</button></div>
<div class="sheet">
<div style="border-top:8px solid #0d2137;padding-top:26px;margin-bottom:8px">
<div class="kicker">DPDPA Gap Assessment &amp; Discovery</div>
<h1 style="font-size:32px;margin:8px 0 2px;color:#0d2137">Gap Assessment</h1>
<div class="client" style="font-size:22px;margin:6px 0 2px">{_e(snap['client'])}</div>
<div class="meta">Assessment {_e(snap['scanId'])} · {date_fmt} · rulebook v{_e(snap['rulebookVersion'])} ·
score {s['complianceScore']}% · {s['counts']['GAP']} gaps · {s['counts']['PARTIAL']} partial ·
{s['counts']['TBC']} to confirm</div>
<p class="rec" style="margin-top:10px">This is the working document behind the executive report: every open
item with its evidence and recommended remediation, plus Owner and Target-date columns to drive closure.
The executive report is the companion for the board.</p></div>
<h2 class="sec">1. What was assessed</h2>
<table>{surface_rows}</table>
{register(gaps, "2. Gap register", "Checkpoints required by the DPDP framework and found missing. Severity-ordered — start at the top.")}
{register(partials, "3. Partial implementations", "Arrangements that exist but are incomplete. Usually the fastest score gains.")}
{tbc_html}
<div class="disc pagebreak"><b>Disclaimer.</b> {_e(DISCLAIMER)}</div>
</div><script src="/static/report.js"></script></body></html>"""
