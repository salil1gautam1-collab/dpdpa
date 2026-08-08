"""DPDPA Sentinel web application (stdlib only — no framework).

Public flow:  / (landing) -> /start (onboarding + consent) -> /company/<slug>
              (workspace: scan button, questionnaire, reports, alerts)
Admin flow:   /admin (login) -> operations dashboard across all companies.

Prototype auth is a single admin password (env DPDPA_ADMIN_PASSWORD, default
"dpdpa-admin") with in-memory sessions — replace with real identity in the
production port. Bind 127.0.0.1 locally; in Docker the container binds 0.0.0.0
internally and compose publishes the port to localhost only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import traceback
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

from . import PRODUCT_NAME, __version__
from .engine import run_scan, summarize
from .rulebook import load_rulebook
from .scanners.questionnaire import VALID
from .webui import (badge, e, landing, layout, start_form, admin_login,
                    company_login, STATUS_COLORS)
from .workspace import (LOCAL_ROOT, client_dir, init_client, list_snapshots,
                        load_client, load_json, save_json)

_jobs: dict = {}
_jobs_lock = threading.Lock()
_sessions: set = set()          # admin session tokens
_co_sessions: dict = {}         # company session token -> slug

PBKDF2_ITERS = 200_000


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt), PBKDF2_ITERS).hex()


def set_company_auth(cfg: dict, email: str, password: str) -> None:
    salt = secrets.token_hex(16)
    cfg["auth"] = {"email": email.strip().lower(), "salt": salt,
                   "hash": hash_password(password, salt),
                   "algo": f"pbkdf2-sha256-{PBKDF2_ITERS}"}


def find_company_by_email(email: str) -> dict | None:
    email = email.strip().lower()
    for cfg in _clients():
        if cfg.get("auth", {}).get("email") == email:
            return cfg
    return None

SCORE_COLORS = [(80, "var(--ok)"), (50, "var(--warn)"), (0, "var(--bad)")]


def _clients() -> list[dict]:
    out = []
    if LOCAL_ROOT.exists():
        for d in sorted(LOCAL_ROOT.iterdir()):
            cfg = load_json(d / "client.json")
            if cfg:
                out.append(cfg)
    return out


def _latest_snapshot(slug: str) -> dict | None:
    snaps = list_snapshots(slug)
    return load_json(snaps[-1]) if snaps else None


def _job_state(slug: str) -> dict | None:
    with _jobs_lock:
        return dict(_jobs[slug]) if slug in _jobs else None


def _start_scan(slug: str, skip_web: bool) -> None:
    with _jobs_lock:
        if _jobs.get(slug, {}).get("state") == "running":
            return
        _jobs[slug] = {"state": "running", "detail": "scan started"}

    def work():
        try:
            prev = _latest_snapshot(slug)
            prev_rb = prev.get("rulebookVersion") if prev else None
            snap = run_scan(slug, skip_web=skip_web)
            from .report import generate
            generate(slug, snap)
            from .diffalert import diff
            alerts = diff(slug).get("alerts", [])
            s = summarize(snap)

            # Publish notification + email to the client
            from . import notify as _n
            cfg2 = load_client(slug)
            email_to = cfg2.get("auth", {}).get("email", "")
            date_str = snap["scanId"][:8]
            date_fmt = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}"
            rb_changed = prev_rb and prev_rb != snap["rulebookVersion"]
            body = (f"Your DPDPA compliance report dated {date_fmt} is now available in your "
                    f"{PRODUCT_NAME} portal.\n\nCompliance score: {s['complianceScore']}%  "
                    f"(gaps {s['counts']['GAP']}, partial {s['counts']['PARTIAL']}, "
                    f"to confirm {s['counts']['TBC']}).\n")
            if rb_changed:
                body += (f"\nThis assessment reflects an updated rulebook (v{snap['rulebookVersion']}) "
                         f"following changes to the DPDP framework.\n")
            regressions = [a for a in alerts if a["type"] == "REGRESSION"]
            if regressions:
                body += f"\n{len(regressions)} checkpoint(s) regressed since your last report — see the change alerts.\n"
            body += f"\nSign in: {_n.base_url()}/login\n"
            _n.notify(slug, "REPORT READY",
                      f"New report dated {date_fmt}" + (" (updated for new rules)" if rb_changed else ""),
                      body, email_to=email_to)
            cfg2["lastPublishedAt"] = snap["scanId"]
            save_json(client_dir(slug) / "client.json", cfg2)

            with _jobs_lock:
                _jobs[slug] = {"state": "done",
                               "detail": f"Assessment complete — score {s['complianceScore']}% · client notified"
                                         + (" (email sent)" if _n.smtp_configured() and email_to else " (email simulated)")}
        except Exception as ex:
            with _jobs_lock:
                _jobs[slug] = {"state": "error", "detail": f"{type(ex).__name__}: {ex}"}
            traceback.print_exc()

    threading.Thread(target=work, daemon=True).start()


def _score_color(score: float) -> str:
    for threshold, color in SCORE_COLORS:
        if score >= threshold:
            return color
    return "var(--bad)"


# ----------------------------------------------------------------- pages ---

def _report_tiles(slug: str, snap: dict) -> str:
    return f"""
<div class="grid c4" style="margin-top:6px">
<div class="tile" style="border-color:#0d6efd"><div class="ico">📕</div><h3>Client Report (PDF)</h3>
<p>Branded, print-ready deliverable — cover, executive summary, findings, evidence.</p>
<p style="margin-top:12px"><a class="btn sm" href="/company/{slug}/report/client-report.html" target="_blank">Open &amp; save as PDF</a></p></div>
<div class="tile"><div class="ico">📄</div><h3>Phase 1 — Discovery</h3>
<p>Data footprint: pages, cookies, trackers, forms, questionnaire coverage.</p>
<p style="margin-top:12px"><a class="btn sm gray" href="/company/{slug}/report/phase1-discovery.html">Open</a></p></div>
<div class="tile"><div class="ico">📊</div><h3>Phase 2 — Gap Assessment</h3>
<p>Every checkpoint graded with severity, evidence and recommendations.</p>
<p style="margin-top:12px"><a class="btn sm gray" href="/company/{slug}/report/phase2-gap-assessment.html">Open</a></p></div>
<div class="tile"><div class="ico">🧾</div><h3>Machine-readable</h3>
<p>Summary JSON for your GRC tooling or board pack.</p>
<p style="margin-top:12px"><a class="btn sm gray" href="/company/{slug}/report/summary.json">summary.json</a></p></div>
</div>"""


def _connector_summary_rows(slug: str, conns: dict, cmeta: dict, manage: bool) -> str:
    link = (f' · <a href="/company/{slug}/connectors">manage</a>' if manage else "")
    provide = (f' <a href="/company/{slug}/connectors">Provide access →</a>' if manage else
               " <span class='small'>your administrator can add this</span>")

    def row(key, id_field, icon, label, ready_desc, detail_fn):
        c = conns.get(key, {})
        if c.get("consent", {}).get("granted") and c.get(id_field):
            return (f'<tr><td>{icon} {label}</td><td><b style="color:var(--ok)">Provided</b></td>'
                    f'<td class="small">{detail_fn(cmeta)}{link}</td></tr>')
        return (f'<tr><td>{icon} {label}</td><td><span style="color:var(--na)">Not provided</span></td>'
                f'<td class="small">{ready_desc}{provide}</td></tr>')

    return (
        row("aws", "accessKeyId", "☁️", "Cloud posture — AWS",
            "Read-only checks: S3, CloudTrail, security groups, RDS, IAM.",
            lambda m: (f"Account {e(m.get('awsAccount'))} · {m.get('s3Buckets','?')} buckets read"
                       if m.get('awsAccount') else "Access provided — awaiting next assessment.")) +
        row("azure", "clientId", "🔷", "Cloud posture — Azure",
            "Read-only checks: storage, NSG exposure, Defender score.",
            lambda m: (f"{m.get('azureSubscriptions','?')} subscription(s) read"
                       if 'azureSubscriptions' in m else "Access provided — awaiting next assessment.")) +
        row("gcp", "projectId", "🟡", "Cloud posture — Google Cloud",
            "Read-only checks: buckets, firewall, Cloud SQL SSL.",
            lambda m: (f"{m.get('gcpBuckets','?')} buckets read"
                       if 'gcpBuckets' in m else "Access provided — awaiting next assessment.")) +
        row("intune", "clientId", "💻", "Endpoints &amp; antivirus (Intune/Defender)",
            "Device counts, encryption &amp; AV-compliance coverage.",
            lambda m: (f"{m.get('endpointDeviceCount','?')} managed devices read"
                       if 'endpointDeviceCount' in m else "Access provided — awaiting next assessment.")) +
        row("adgpo", "collectorJson", "🏢", "Directory &amp; identity (AD / GPO)",
            "Password policy, privileged accounts, stale accounts, GPO hardening.",
            lambda m: (f"{m.get('adTotalUsers','?')} users; collector parsed"
                       if 'adTotalUsers' in m else "Collector output provided — awaiting next assessment.")) +
        row("firewall", "configText", "🧱", "Firewall &amp; perimeter",
            "Any-any rules, management exposure, logging.",
            lambda m: (f"{m.get('firewallLines','?')} config lines parsed"
                       if 'firewallLines' in m else "Config provided — awaiting next assessment.")))


def page_company(slug: str, msg: str = "", is_err: bool = False, is_admin: bool = False) -> bytes:
    cfg = load_client(slug)
    snap = _latest_snapshot(slug)
    job = _job_state(slug)
    running = bool(job and job["state"] == "running")
    consent = cfg.get("scanConsent", {})
    has_sites = bool(cfg.get("sites"))
    q = load_json(client_dir(slug) / "questionnaire.json", {})
    n_answered = len(q.get("assertions", []))
    alerts = load_json(client_dir(slug) / "alerts.json", {})
    conns = load_json(client_dir(slug) / "connectors.json", {})
    cmeta = (snap or {}).get("meta", {})
    total_controls = len(load_rulebook()["controls"])

    if snap:
        s = summarize(snap)
        score = s["complianceScore"]
        chips = "".join(
            f'<span class="chip"><b style="color:{STATUS_COLORS[k]}">{v}</b>{k.title() if k != "NA" else "N/A"}</span>'
            for k, v in s["counts"].items())
        head_right = (f'<div class="donut" style="--p:{score};--dc:{_score_color(score)}">'
                      f'<div>{score}%<small>compliance</small></div></div>')
    else:
        head_right = '<div class="donut" style="--p:0;--dc:var(--na)"><div>—<small>no report yet</small></div></div>'
        chips = ""

    job_note = (f'<div class="msg {"err" if job["state"] == "error" else ""}">{e(job["detail"])}</div>'
                if job and not running else "")
    running_note = ('<div class="card"><span class="spin"></span> <b>Assessment in progress…</b> '
                    'evaluating every checkpoint. This page refreshes automatically.</div>' if running else "")

    header = f"""
<div class="ws-head"><div class="wrap flexh">
<div style="flex:1;min-width:260px"><h1>{e(cfg['name'])}</h1>
<div class="small">{e(', '.join(cfg.get('sites', [])) or 'Questionnaire-only assessment')}</div>
<div class="chips">{chips}</div></div>{head_right}</div></div>"""

    account_card = (f'''<h2>Account</h2>
<div class="card" style="max-width:520px"><b>Sign-in:</b> {e(cfg["auth"]["email"])}
<form method="post" action="/company/{slug}/password">
<label>Current password</label><input type="password" name="current" required>
<label>New password (min 10 characters)</label><input type="password" name="new" required minlength="10">
<p><button class="btn sm" type="submit">Change password</button></p></form></div>''' if cfg.get("auth") else '')
    footer = (f'<p style="margin:26px 0"><a href="/" class="small">← home</a> &nbsp;·&nbsp;'
              f'<form method="post" action="/logout" style="display:inline">'
              f'<button class="btn sm gray" type="submit">Sign out</button></form></p>')

    # ============ COMPANY (client) VIEW — guided intake + read-only report ====
    if not is_admin:
        website_consent = "" if consent.get("granted") or not has_sites else f"""
<div class="card" style="border-color:#e6d9a8;background:#fff8e6">
<b>One thing to authorise:</b> we may run a passive, read-only scan of your public website(s)
({e(', '.join(cfg.get('sites', [])))}). No logins, no form submissions, no intrusion.
<form method="post" action="/company/{slug}/consent" style="margin-top:8px">
<input type="text" name="grantedBy" required placeholder="Your name, designation and basis of authorisation" style="max-width:520px">
<button class="btn sm" type="submit">Authorise website scan</button></form></div>"""

        submission = cfg.get("submission", {})
        submitted = submission.get("submitted")
        pending = cfg.get("pendingAssessment")
        submit_btn = (f'<form method="post" action="/company/{slug}/submit">'
                      f'<button class="btn big green" type="submit">'
                      f'{"Re-submit updated inputs" if submitted else "Submit my inputs →"}</button></form>')
        if pending:
            submit_zone = (f'<div class="card">🔔 <b>Your inputs were submitted on {e(submission.get("at",""))}.</b> '
                           f'Our DPDPA assessment team is preparing your report — it will appear below when ready. '
                           f'You don\'t need to do anything else.'
                           f'<div style="margin-top:10px">Changed something since submitting? {submit_btn}</div></div>')
        elif snap:
            submit_zone = (f'<div class="card">✅ Your report is ready below (assessment completed '
                           f'{e(snap["scanId"])}). Updated your questionnaire or access details since? '
                           f'Re-submit and your team will refresh it.<div style="margin-top:10px">{submit_btn}</div></div>')
        else:
            submit_zone = (f'<div class="card"><p>When your inputs are in, submit them. '
                           f'Our assessment team then prepares your DPDPA report — you don\'t run anything yourself.</p>'
                           f'{submit_btn}<p class="small" style="margin-top:8px">Submitting shares your questionnaire '
                           f'and any access you granted with your engagement team, who run the assessment for you.</p></div>')

        reports_zone = (f"<h2>Your report</h2>{_report_tiles(slug, snap)}"
                        f'<p class="small">Latest {e(_fmt_date(snap["scanId"]))} · rulebook v{e(snap["rulebookVersion"])} · '
                        f'<a href="/company/{slug}/history">all reports &amp; history →</a></p>'
                        if snap else
                        "<h2>Your report</h2><p class='small'>Your report appears here once your assessment team has prepared it.</p>")

        from . import notify as _n
        notes = _n.list_notifications(slug)
        unread = sum(1 for x in notes if not x.get("read"))
        if notes:
            note_rows = "".join(
                f'<div style="padding:8px 0;border-bottom:1px solid var(--line)">'
                f'<b>{"🔵 " if not x.get("read") else ""}{e(x["title"])}</b> '
                f'<span class="small">{e(x["createdAt"][:10])}</span><br>'
                f'<span class="small" style="white-space:pre-wrap">{e(x["body"][:280])}</span></div>'
                for x in notes[:6])
            notif_panel = f"""<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center">
<h3 style="margin:0">🔔 Notifications {f'<span class="badge" style="background:var(--bad)">{unread} new</span>' if unread else ''}</h3>
{f'<form method="post" action="/company/{slug}/notifications/read"><button class="btn sm gray" type="submit">Mark all read</button></form>' if unread else ''}
</div>{note_rows}</div>"""
        else:
            notif_panel = ""

        body = f"""{header}<div class="wrap">
{f'<div class="msg {"err" if is_err else ""}">{e(unquote(msg))}</div>' if msg else ''}
{job_note}
{notif_panel}
<h2>Complete your assessment inputs</h2>
<p class="small" style="max-width:760px">Three inputs drive your DPDPA assessment. Fill what applies, then submit —
everything is consent-based and you can update or withdraw anytime.</p>
<div class="grid c3">
<div class="tile"><div class="ico">📋</div><h3>1. Questionnaire</h3>
<p>Declare the internal controls we can't see from outside — policies, registers, workflows.
<b>{n_answered}/{total_controls}</b> answered.</p>
<p style="margin-top:10px"><a class="btn sm" href="/company/{slug}/questionnaire">Fill questionnaire</a></p></div>
<div class="tile"><div class="ico">🔑</div><h3>2. Infrastructure &amp; cloud access</h3>
<p>Optionally provide <b>read-only</b> access to your cloud/endpoints so we can verify posture directly.
You grant consent per system and can revoke it anytime.</p>
<p style="margin-top:10px"><a class="btn sm" href="/company/{slug}/connectors">Provide access &amp; consent</a></p></div>
<div class="tile"><div class="ico">✅</div><h3>3. Consent</h3>
<p>Website scan {'authorised' if consent.get('granted') or not has_sites else 'pending below'};
each access grant carries its own consent. We identify gaps — we never change your systems without permission.</p></div>
</div>
{website_consent}
<h2>Submit</h2>{submit_zone}
<h2>What your assessment covers</h2>
<table><tr><th style="width:230px">Surface</th><th style="width:120px">Status</th><th>Detail</th></tr>
<tr><td>🌐 Public websites &amp; catalogs</td><td>{'<b style="color:var(--ok)">Included</b>' if has_sites else '—'}</td>
<td class="small">{e(', '.join(cfg.get('sites', [])) or 'no sites listed')}</td></tr>
<tr><td>📋 Departmental questionnaire</td><td>{'<b style="color:var(--ok)">In use</b>' if n_answered else 'Pending'}</td>
<td class="small">{n_answered}/{total_controls} checkpoints declared</td></tr>
{_connector_summary_rows(slug, conns, cmeta, manage=True)}
</table>
{reports_zone}
{account_card}{footer}</div>"""
        return layout(cfg["name"], body, refresh=4 if running else None)

    # ================= ADMIN (operator) VIEW — full controls =================
    results = (_report_tiles(slug, snap) +
               f'<p class="small">Scans on file: {len(list_snapshots(slug))} · latest {e(_fmt_date(snap["scanId"]))} '
               f'· rulebook v{e(snap["rulebookVersion"])} · <a href="/company/{slug}/history">history &amp; compare →</a></p>' if snap else
               "<p class='small'>No assessment has run yet.</p>")
    if running:
        scan_zone = running_note
    else:
        buttons = []
        if has_sites:
            buttons.append(f'<form method="post" action="/company/{slug}/scan" style="display:inline">'
                           f'<button class="btn green" type="submit" '
                           + ("" if consent.get("granted") else 'disabled title="record scan consent first"')
                           + ">▶ Run full assessment</button></form>")
        buttons.append(f'<form method="post" action="/company/{slug}/scan?skipweb=1" style="display:inline">'
                       f'<button class="btn gray" type="submit">Run questionnaire-only</button></form>')
        buttons.append(f'<a class="btn" href="/company/{slug}/questionnaire">✎ Questionnaire ({n_answered}/{total_controls})</a>')
        buttons.append(f'<a class="btn gray" href="/company/{slug}/connectors">🔑 Connectors</a>')
        scan_zone = job_note + "<p>" + " ".join(buttons) + "</p>"

    admin_consent = "" if consent.get("granted") or not has_sites else f"""
<div class="card" style="border-color:#e6d9a8;background:#fff8e6">
<b>Website scan not authorised.</b> Record the client's authorisation before running a web scan.
<form method="post" action="/company/{slug}/consent" style="margin-top:8px">
<input type="text" name="grantedBy" required placeholder="Who authorised, and how" style="max-width:520px">
<button class="btn sm" type="submit">Record authorisation</button></form></div>"""

    alert_rows = "".join(
        f"<tr><td><b>{e(a['type'])}</b></td><td>{e(a.get('controlId', ''))}</td><td>{e(a.get('detail', ''))}</td></tr>"
        for a in alerts.get("alerts", []))

    sub = cfg.get("submission", {})
    pending_banner = (f'<div class="msg" style="background:#fff8e6;border-color:#e6d9a8">🔔 <b>Client submitted their '
                      f'inputs on {e(sub.get("at",""))}</b> ({e(sub.get("by",""))}). Review and run the assessment below.</div>'
                      if cfg.get("pendingAssessment") else "")

    body = f"""{header}<div class="wrap">
<div class="msg" style="background:#eef2f6;border-color:#c9d6e2"><b>Admin / operator view</b> —
full controls. The client sees only their inputs and report.</div>
{pending_banner}
{f'<div class="msg {"err" if is_err else ""}">{e(unquote(msg))}</div>' if msg else ''}
{admin_consent}
<h2>Run assessment</h2>{scan_zone}
<h2>Coverage &amp; connectors</h2>
<table><tr><th style="width:230px">Surface</th><th style="width:120px">Status</th><th>Detail</th></tr>
<tr><td>🌐 Public websites</td><td>{'<b style="color:var(--ok)">Scanned</b>' if (snap and cmeta.get('pagesScanned')) else ('Ready' if has_sites else '—')}</td>
<td class="small">{e(', '.join(cfg.get('sites', [])) or 'no sites')}{f" · {len(cmeta.get('pagesScanned', []))} pages last scan" if snap and cmeta.get('pagesScanned') else ''}</td></tr>
<tr><td>📋 Questionnaire</td><td>{'<b style="color:var(--ok)">In use</b>' if n_answered else 'Pending'}</td>
<td class="small">{n_answered}/{total_controls} declared</td></tr>
{_connector_summary_rows(slug, conns, cmeta, manage=True)}
</table>
<h2>Reports</h2>{results}
<h2>Change alerts</h2>
<table><tr><th style="width:170px">Type</th><th style="width:90px">Control</th><th>Detail</th></tr>
{alert_rows or '<tr><td colspan="3" class="small">none — run at least two scans to compare</td></tr>'}</table>
<p style="margin:26px 0"><a href="/admin" class="small">← operations dashboard</a></p>
</div>"""
    return layout(cfg["name"], body, refresh=4 if running else None)


def _load_snapshot_by_id(slug: str, scan_id: str) -> dict | None:
    for p in list_snapshots(slug):
        if p.stem == scan_id:
            return load_json(p)
    return None


def _fmt_date(scan_id: str) -> str:
    return f"{scan_id[:4]}-{scan_id[4:6]}-{scan_id[6:8]} {scan_id[9:11]}:{scan_id[11:13]} UTC" if len(scan_id) >= 13 else scan_id


def page_history(slug: str, msg: str = "") -> bytes:
    cfg = load_client(slug)
    snaps = [load_json(p) for p in list_snapshots(slug)]
    snaps.reverse()  # newest first
    rows = []
    for sn in snaps:
        s = summarize(sn)
        sid = sn["scanId"]
        rows.append(f"""<tr>
<td><b>{e(_fmt_date(sid))}</b><div class="small">{e(sid)}</div></td>
<td><b style="color:{_score_color(s['complianceScore'])}">{s['complianceScore']}%</b></td>
<td class="small">gaps {s['counts']['GAP']} · partial {s['counts']['PARTIAL']} · TBC {s['counts']['TBC']}</td>
<td class="small">v{e(sn['rulebookVersion'])}</td>
<td><a class="btn sm" href="/company/{slug}/history/{sid}/client" target="_blank">📕 Report</a>
<a class="btn sm gray" href="/company/{slug}/history/{sid}/phase2" target="_blank">Phase 2</a>
<a class="btn sm gray" href="/company/{slug}/history/{sid}/phase1" target="_blank">Phase 1</a></td></tr>""")

    opts = "".join(f'<option value="{e(sn["scanId"])}">{e(_fmt_date(sn["scanId"]))} · {summarize(sn)["complianceScore"]}%</option>'
                   for sn in snaps)
    compare = f"""
<h2>Compare two reports</h2>
<div class="card"><form method="get" action="/company/{slug}/compare">
<div style="display:flex;gap:14px;flex-wrap:wrap;align-items:end">
<div style="flex:1;min-width:200px"><label>Report A (baseline)</label><select name="a">{opts}</select></div>
<div style="flex:1;min-width:200px"><label>Report B (compare to)</label><select name="b">{opts}</select></div>
<button class="btn" type="submit">Compare →</button></div>
<p class="small" style="margin-top:8px">Shows score change, what improved, what regressed, and any new checkpoints from a rulebook update.</p>
</form></div>""" if len(snaps) >= 2 else '<p class="small">Run at least two assessments to enable comparison.</p>'

    body = f"""
<section><div class="wrap">
<p class="small"><a href="/company/{slug}">← {e(cfg['name'])}</a></p>
<h2>Assessment history — {e(cfg['name'])}</h2>
<p class="small">Every assessment is retained with its date and can be reopened. Reports render from the
immutable snapshot taken at that time.</p>
{f'<div class="msg">{e(unquote(msg))}</div>' if msg else ''}
<table><tr><th>Date</th><th>Score</th><th>Breakdown</th><th>Rulebook</th><th>Reports</th></tr>
{''.join(rows) or '<tr><td colspan=5 class="small">No assessments yet.</td></tr>'}</table>
{compare}
</div></section>"""
    return layout("History", body)


def page_questionnaire(slug: str) -> bytes:
    cfg = load_client(slug)
    rb = load_rulebook()
    q = load_json(client_dir(slug) / "questionnaire.json", {})
    existing = {a["controlId"]: a for a in q.get("assertions", [])}
    cats = {c["id"]: c["name"] for c in rb["categories"]}

    rows, last_cat = [], None
    for c in rb["controls"]:
        if c["category"] != last_cat:
            rows.append(f'<tr><td colspan="4" class="cat">{e(c["category"])} — {e(cats[c["category"]])}</td></tr>')
            last_cat = c["category"]
        a = existing.get(c["id"], {})
        opts = '<option value="">— not answered —</option>' + "".join(
            f'<option value="{v}" {"selected" if a.get("status") == v else ""}>{v}</option>'
            for v in sorted(VALID))
        ev = e(a.get("evidence", "") if isinstance(a.get("evidence"), str) else "")
        dept = e(a.get("source", {}).get("department", "") if isinstance(a.get("source"), dict) else "")
        auto = ' <span class="small">(also auto-checked by scanner)</span>' if c["checkMethod"] in ("web", "hybrid") else ""
        rows.append(f"""<tr>
<td style="width:250px"><b>{e(c['id'])}</b> {e(c['title'])}<div class="small">{e(c['legalRef'])} · {e(c['severity'])}{auto}</div></td>
<td style="width:135px"><select name="st-{c['id']}">{opts}</select></td>
<td><textarea name="ev-{c['id']}" rows="2" placeholder="Evidence / basis for this answer">{ev}</textarea></td>
<td style="width:150px"><input type="text" name="dept-{c['id']}" value="{dept}" placeholder="Department"></td></tr>""")

    body = f"""
<section><div class="wrap">
<p class="small"><a href="/company/{slug}">← {e(cfg['name'])}</a></p>
<h2>Questionnaire — {e(cfg['name'])}</h2>
<p class="small" style="max-width:760px">Declarations for checkpoints the scanner cannot verify from outside
(internal policies, registers, workflows). A declaration can <b>confirm</b> an automated signal but can never
override a scanner-observed gap. Leave a row unanswered to keep it "to be confirmed".</p>
<form method="post" action="/company/{slug}/questionnaire">
<table><tr><th>Checkpoint</th><th>Status</th><th>Evidence</th><th>Department</th></tr>{''.join(rows)}</table>
<p><button class="btn big green" type="submit">Save answers</button>
<span class="small"> then run a scan to refresh your score.</span></p></form>
</div></section>"""
    return layout("Questionnaire", body)


def _connector_card(slug: str, key: str, title: str, blurb: str, howto: str,
                    fields: list, conn: dict, id_field: str) -> str:
    """Render one provider card. fields = [(name, label, type, default)]."""
    connected = conn.get("consent", {}).get("granted") and conn.get(id_field)
    status_line = ""
    if connected:
        idv = str(conn.get(id_field, ""))
        hint = ("••••" + idv[-4:]) if len(idv) > 4 else "••••"
        status_line = (
            f'<p style="color:var(--ok)">✅ <b>Connected</b> — {e(id_field)} {e(hint)}, '
            f'authorised {e(conn.get("consent", {}).get("date", ""))}.</p>'
            f'<form method="post" action="/company/{slug}/connectors/{key}/disconnect">'
            f'<button class="btn sm red" type="submit">Disconnect &amp; delete credentials</button></form>')
    inputs = []
    for name, label, ftype, default in fields:
        val = e(conn.get(name, default)) if ftype != "password" else ""
        ph = "leave blank to keep existing" if (ftype == "password" and connected) else ""
        inputs.append(f'<label>{e(label)}</label>'
                      f'<input type="{ftype}" name="{name}" value="{val}" placeholder="{ph}" autocomplete="off">')
    return f"""<div class="card">
<h3 style="margin-top:0">{title} <span class="small">— live, read-only</span></h3>
<p style="font-size:14px">{blurb}</p>
<div class="notice">{howto}</div>
{status_line}
<form method="post" action="/company/{slug}/connectors/{key}">
{''.join(inputs)}
<div class="consent-box"><label style="margin:0;font-weight:600">
<input type="checkbox" name="consent" value="1" style="width:auto;margin-right:8px" {'checked' if connected else ''}>
I authorise {PRODUCT_NAME} to run read-only posture checks using these credentials.</label></div>
<button class="btn green" type="submit">{'Update connection' if connected else 'Connect &amp; save'}</button>
</form></div>"""


def page_connectors(slug: str, msg: str = "", is_err: bool = False) -> bytes:
    cfg = load_client(slug)
    conns = load_json(client_dir(slug) / "connectors.json", {})

    aws_card = _connector_card(
        slug, "aws", "☁️ Amazon Web Services",
        "Verifies S3 public-access &amp; encryption, CloudTrail logging, security-group exposure, "
        "RDS encryption, and IAM hygiene (root MFA, key age).",
        "<b>Read-only credentials (2 min):</b> AWS console → IAM → create user <code>dpdpa-readonly</code> "
        "→ attach the managed policy <code>SecurityAudit</code> → create an access key → paste below.",
        [("accessKeyId", "AWS Access Key ID", "text", "AKIA..."),
         ("secretAccessKey", "AWS Secret Access Key", "password", ""),
         ("region", "Default region", "text", "ap-south-1")],
        conns.get("aws", {}), "accessKeyId")

    azure_card = _connector_card(
        slug, "azure", "🔷 Microsoft Azure",
        "Verifies storage public-access &amp; HTTPS/TLS, network security group exposure, and the "
        "Microsoft Defender for Cloud secure score.",
        "<b>Read-only app (5 min):</b> Entra admin → App registrations → new app → add a client secret → "
        "in the subscription's Access control (IAM), assign the app the <code>Reader</code> and "
        "<code>Security Reader</code> roles. Paste the tenant, client id and secret below.",
        [("tenantId", "Directory (tenant) ID", "text", ""),
         ("clientId", "Application (client) ID", "text", ""),
         ("clientSecret", "Client secret", "password", "")],
        conns.get("azure", {}), "clientId")

    intune_card = _connector_card(
        slug, "intune", "💻 Endpoints &amp; Antivirus (Microsoft Intune / Defender)",
        "Inventories managed laptops/servers (counts by OS), disk-encryption coverage, and policy "
        "compliance (antivirus, patching).",
        "<b>Read-only Graph app:</b> use the same Entra app as Azure (or a new one) and grant the "
        "<b>application</b> permission <code>DeviceManagementManagedDevices.Read.All</code> with admin consent. "
        "Paste the tenant, client id and secret below.",
        [("tenantId", "Directory (tenant) ID", "text", ""),
         ("clientId", "Application (client) ID", "text", ""),
         ("clientSecret", "Client secret", "password", "")],
        conns.get("intune", {}), "clientId")

    gcp_card = _connector_card(
        slug, "gcp", "🟡 Google Cloud",
        "Verifies bucket public-access prevention, firewall exposure, and Cloud SQL SSL enforcement.",
        "<b>Read-only token:</b> a principal with <code>roles/viewer</code> + "
        "<code>roles/iam.securityReviewer</code> generates a short-lived token with "
        "<code>gcloud auth print-access-token</code>. Paste it with your project id. "
        "(Production adds service-account-key support.)",
        [("projectId", "GCP Project ID", "text", ""),
         ("accessToken", "OAuth2 access token", "password", "")],
        conns.get("gcp", {}), "projectId")

    ad = conns.get("adgpo", {})
    ad_connected = ad.get("consent", {}).get("granted") and ad.get("collectorJson")
    ad_card = f"""<div class="card">
<h3 style="margin-top:0">🏢 Active Directory / Group Policy <span class="small">— collector paste</span></h3>
<p style="font-size:14px">Checks domain password policy, privileged-account count, stale accounts and GPO
hardening. Your <b>own</b> domain admin runs a read-only collector — we never hold domain credentials.</p>
<div class="notice"><b>How:</b> download and review
<a href="/collectors/ad-gpo-collector.ps1" target="_blank"><code>ad-gpo-collector.ps1</code></a>
(read-only PowerShell), run it on a domain-joined machine, and paste its JSON output below.
{'✅ <b>Collector output on file.</b>' if ad_connected else ''}</div>
<form method="post" action="/company/{slug}/connectors/adgpo">
<label>Collector JSON output</label>
<textarea name="collectorJson" rows="5" placeholder='{{ "passwordPolicy": {{...}}, "privilegedGroups": {{...}}, ... }}'>{e(ad.get('collectorJson','') if ad_connected else '')}</textarea>
<div class="consent-box"><label style="margin:0;font-weight:600">
<input type="checkbox" name="consent" value="1" style="width:auto;margin-right:8px" {'checked' if ad_connected else ''}>
I authorise {PRODUCT_NAME} to evaluate this directory posture output.</label></div>
<button class="btn green" type="submit">{'Update' if ad_connected else 'Submit collector output'}</button>
{f'</form><form method="post" action="/company/{slug}/connectors/adgpo/disconnect"><button class="btn sm red" type="submit">Remove</button>' if ad_connected else ''}
</form></div>"""

    fw = conns.get("firewall", {})
    fw_connected = fw.get("consent", {}).get("granted") and fw.get("configText")
    fw_card = f"""<div class="card">
<h3 style="margin-top:0">🧱 Firewall configuration <span class="small">— config paste</span></h3>
<p style="font-size:14px">Heuristically flags any-any rules, exposed management ports and missing logging
across common formats (iptables, Cisco, Fortinet, pfSense). Findings are marked for human confirmation.</p>
<div class="notice"><b>How:</b> export your firewall configuration/ruleset and paste it below.
Redact anything you consider sensitive first — we only need the rule structure.
{'✅ <b>Configuration on file.</b>' if fw_connected else ''}</div>
<form method="post" action="/company/{slug}/connectors/firewall">
<label>Firewall configuration / ruleset</label>
<textarea name="configText" rows="6" placeholder="paste firewall config or ruleset export">{e(fw.get('configText','') if fw_connected else '')}</textarea>
<div class="consent-box"><label style="margin:0;font-weight:600">
<input type="checkbox" name="consent" value="1" style="width:auto;margin-right:8px" {'checked' if fw_connected else ''}>
I authorise {PRODUCT_NAME} to evaluate this firewall configuration.</label></div>
<button class="btn green" type="submit">{'Update' if fw_connected else 'Submit configuration'}</button>
{f'</form><form method="post" action="/company/{slug}/connectors/firewall/disconnect"><button class="btn sm red" type="submit">Remove</button>' if fw_connected else ''}
</form></div>"""

    body = f"""
<section><div class="wrap" style="max-width:820px">
<p class="small"><a href="/company/{slug}">← {e(cfg['name'])}</a></p>
<h2>Connectors — infrastructure &amp; cloud</h2>
<p class="small">All connectors are read-only and run only after you authorise them here. Credentials never
leave this workspace and are never committed to source control. We store posture findings, never your data.</p>
{f'<div class="msg {"err" if is_err else ""}">{e(unquote(msg))}</div>' if msg else ''}
{aws_card}{azure_card}{intune_card}{gcp_card}{ad_card}{fw_card}
<p class="small">Credentials and collector inputs are stored in this workspace's <code>connectors.json</code> (gitignored).
For production, move them to a managed secrets vault — see docs/DOTNET-IMPLEMENTATION-GUIDE.md.</p>
</div></section>"""
    return layout("Connectors", body)


def page_rulebook(msg: str = "", is_err: bool = False) -> bytes:
    from .rulebook import all_rulebooks, IMPORT_DIR
    books = all_rulebooks()
    current = books[-1]
    rows = "".join(
        f"<tr><td><b>v{e(rb['rulebookVersion'])}</b>{' · current' if rb is current else ''}</td>"
        f"<td>{len(rb['controls'])}</td><td>{len(rb['categories'])}</td>"
        f"<td class='small'>{e(rb.get('lastUpdated',''))}</td>"
        f"<td class='small'>{'imported' if (IMPORT_DIR / ('dpdpa-rulebook.v'+rb['rulebookVersion']+'.json')).exists() else 'shipped'}</td></tr>"
        for rb in reversed(books))
    body = f"""
<section><div class="wrap" style="max-width:860px">
<p class="small"><a href="/admin">← operations dashboard</a></p>
<h2>Rulebook — the law, as data <span class="small">(CS / Legal)</span></h2>
<p class="small">The rulebook is the checkpoint universe. When MeitY updates the DPDP framework, import a new
version here. Existing assessments are untouched; the next assessment a company runs uses the latest version,
and the diff highlights any newly-introduced checkpoints. Nothing changes silently.</p>
{f'<div class="msg {"err" if is_err else ""}">{e(unquote(msg))}</div>' if msg else ''}
<table><tr><th>Version</th><th>Controls</th><th>Categories</th><th>Updated</th><th>Source</th></tr>{rows}</table>

<h2>Append new checkpoints</h2>
<div class="card"><p style="font-size:14px">Paste one or more new control objects (a JSON array). They are appended
to the current rulebook (v{e(current['rulebookVersion'])}) as a new version. Use this when the regulator adds
requirements. Each control needs at least <code>id, category, severity, title, checkMethod</code>.</p>
<form method="post" action="/admin/rulebook/append">
<label>New version number</label>
<input type="text" name="version" placeholder="e.g. {_bump(current['rulebookVersion'])}" value="{_bump(current['rulebookVersion'])}">
<label>New controls (JSON array)</label>
<textarea name="controls" rows="7" placeholder='[{{"id":"NT-07","category":"NT","severity":"medium","title":"...","legalRef":"...","description":"...","checkMethod":"questionnaire","remediation":"...","appAssist":{{"possible":true,"how":"..."}}}}]'></textarea>
<label>Note (what changed &amp; why)</label>
<input type="text" name="note" placeholder="e.g. Appended per MeitY notification dated ...">
<p><button class="btn green" type="submit">Append &amp; publish new version</button></p></form></div>

<h2>Import a full rulebook</h2>
<div class="card"><p style="font-size:14px">Alternatively paste a complete rulebook JSON (with a higher
<code>rulebookVersion</code>) prepared by counsel. It is validated and stored.</p>
<form method="post" action="/admin/rulebook/import">
<textarea name="rulebook" rows="6" placeholder='{{"rulebookVersion":"5.0.0","categories":[...],"controls":[...]}}'></textarea>
<p><button class="btn" type="submit">Validate &amp; import</button></p></form></div>
<p class="small">Imported rulebooks are stored in the data volume (<code>local/_rulebooks/</code>) and persist
across rebuilds. After importing, re-run a company's assessment to apply it — the client is notified their
report reflects the updated law.</p>
</div></section>"""
    return layout("Rulebook", body, admin=True)


def _bump(version: str) -> str:
    parts = version.split(".")
    try:
        return f"{int(parts[0]) + 1}.0.0"
    except (ValueError, IndexError):
        return "5.0.0"


def page_outbox() -> bytes:
    from . import notify as _n
    rows = "".join(
        f"<tr><td class='small'>{e(x.get('sentAt','')[:16])}</td><td>{e(x.get('slug',''))}</td>"
        f"<td>{e(x.get('to',''))}</td><td class='small'>{e(x.get('subject',''))}</td>"
        f"<td>{e(x.get('status',''))}</td></tr>" for x in _n.outbox()[:100])
    mode = "LIVE (SMTP configured)" if _n.smtp_configured() else "SIMULATED (set TRACKVAULT_SMTP_* to send real email)"
    body = f"""
<section><div class="wrap">
<p class="small"><a href="/admin">← operations dashboard</a></p>
<h2>Notification delivery log</h2>
<p class="small">Email mode: <b>{e(mode)}</b>. Every client notification is recorded here with its delivery status.</p>
<table><tr><th>Sent</th><th>Company</th><th>To</th><th>Subject</th><th>Status</th></tr>
{rows or '<tr><td colspan=5 class="small">No notifications sent yet.</td></tr>'}</table>
</div></section>"""
    return layout("Delivery log", body, admin=True)


def page_admin(msg: str = "") -> bytes:
    rows = []
    for cfg in _clients():
        slug = cfg["slug"]
        snap = _latest_snapshot(slug)
        job = _job_state(slug)
        if job and job["state"] == "running":
            status = '<span class="spin"></span> scanning…'
        elif snap:
            s = summarize(snap)
            status = (f"<b>{s['complianceScore']}%</b> &nbsp; {badge('GAP')} {s['counts']['GAP']} · "
                      f"{badge('TBC')} {s['counts']['TBC']} <span class='small'>({e(snap['scanId'])})</span>")
        else:
            status = '<span class="small">never scanned</span>'
        consent = "✅" if cfg.get("scanConsent", {}).get("granted") else "—"
        contact = e(cfg.get("contact", ""))
        auth_email = cfg.get("auth", {}).get("email", "")
        reset_label = "Reset login" if auth_email else "Create login"
        sub = cfg.get("submission", {})
        if cfg.get("pendingAssessment"):
            status = f'🔔 <b style="color:var(--bad)">Client submitted — ready to assess</b> <span class="small">({e(sub.get("at",""))})</span><br>' + status
        rows.append(f"""<tr><td><a href="/company/{slug}"><b>{e(cfg['name'])}</b></a>
<div class="small">{contact}</div></td>
<td class="small">{e(', '.join(cfg.get('sites', [])) or '(questionnaire only)')}</td>
<td style="text-align:center">{consent}</td><td>{status}</td>
<td><a class="btn sm" href="/company/{slug}">Open</a>
<form method="post" action="/admin/reset" style="margin-top:6px">
<input type="hidden" name="slug" value="{slug}">
<input type="text" name="email" value="{e(auth_email)}" placeholder="client sign-in email" style="max-width:180px;font-size:12px;padding:5px 8px">
<button class="btn sm gray" type="submit">{reset_label}</button></form></td></tr>""")
    body = f"""
<section><div class="wrap">
{f'<div class="msg">{e(unquote(msg))}</div>' if msg else ''}
<h2>Operations dashboard <span class="small">· all engagements</span></h2>
<p><a class="btn sm" href="/admin/rulebook">⚖ Rulebook (CS / Legal)</a>
<a class="btn sm gray" href="/admin/outbox">📧 Notification delivery log</a></p>
<table><tr><th>Company</th><th>Sites</th><th>Consent</th><th>Latest result</th><th></th></tr>
{''.join(rows) or '<tr><td colspan="5">No companies yet.</td></tr>'}</table>
<div class="card"><h3 style="margin-top:0">Add a company (admin quick-add)</h3>
<form method="post" action="/clients">
<label>Company name</label><input type="text" name="name" required>
<label>Websites (comma-separated, optional)</label><input type="text" name="sites">
<p><button class="btn green" type="submit">Add</button></p></form></div>
<p class="small">Data directory: <code>local/</code> (one folder per company — JSON files, no database server).
Retention: see docs/DATA-PROTECTION-POLICY.md.
<form method="post" action="/admin/logout" style="display:inline"><button class="btn sm gray" type="submit">Sign out</button></form></p>
</div></section>"""
    return layout("Admin", body, admin=True)


# --------------------------------------------------------------- handler ---

class App(BaseHTTPRequestHandler):
    server_version = "DPDPASentinel/" + __version__

    # -- helpers
    def _send(self, body: bytes, ctype="text/html; charset=utf-8", code=200, cookie: str | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, path: str, cookie: str | None = None):
        self.send_response(303)
        self.send_header("Location", path)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def _cookie(self, name: str) -> str | None:
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def _is_admin(self) -> bool:
        return self._cookie("dpdpa_session") in _sessions

    def _company_slug(self) -> str | None:
        """Slug of the signed-in company, if any."""
        return _co_sessions.get(self._cookie("dpdpa_co") or "")

    def _may_access(self, slug: str) -> bool:
        return self._is_admin() or self._company_slug() == slug

    def log_message(self, fmt, *args):
        pass

    # -- GET
    def do_GET(self):
        try:
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            parts = [p for p in u.path.split("/") if p]

            if not parts:
                return self._send(landing())
            if parts == ["start"]:
                return self._send(start_form())
            if parts == ["collectors", "ad-gpo-collector.ps1"]:
                from .workspace import REPO_ROOT
                f = REPO_ROOT / "docs" / "collectors" / "ad-gpo-collector.ps1"
                if f.is_file():
                    return self._send(f.read_bytes(), "text/plain; charset=utf-8")
                return self._send(layout("Not found", "<section><div class='wrap'><p>collector not found</p></div></section>"), code=404)
            if parts == ["login"]:
                return self._send(company_login(q.get("msg", "")))
            if parts[0] == "admin":
                if not self._is_admin():
                    return self._send(admin_login(q.get("msg", "")))
                if parts == ["admin", "rulebook"]:
                    return self._send(page_rulebook(q.get("msg", ""), q.get("err") == "1"))
                if parts == ["admin", "outbox"]:
                    return self._send(page_outbox())
                return self._send(page_admin(q.get("msg", "")))
            if parts[0] in ("company", "client") and len(parts) >= 2:
                slug = unquote(parts[1])
                if parts[0] == "client":  # legacy URLs
                    return self._redirect("/company/" + "/".join(parts[1:]))
                if not self._may_access(slug):
                    return self._redirect("/login?msg=" + quote("Please sign in to access your workspace."))
                if len(parts) == 2:
                    return self._send(page_company(slug, q.get("msg", ""), q.get("err") == "1",
                                                   is_admin=self._is_admin()))
                if parts[2] == "questionnaire":
                    return self._send(page_questionnaire(slug))
                if parts[2] == "connectors":
                    return self._send(page_connectors(slug, q.get("msg", ""), q.get("err") == "1"))
                if parts[2] == "history" and len(parts) == 2 + 1:
                    return self._send(page_history(slug, q.get("msg", "")))
                if parts[2] == "history" and len(parts) == 5:
                    sid, which = parts[3], parts[4]
                    sn = _load_snapshot_by_id(slug, sid)
                    if not sn:
                        return self._send(layout("Not found", "<section><div class='wrap'><p>Assessment not found.</p></div></section>"), code=404)
                    from .report import phase1_html, phase2_html
                    from . import report_premium
                    if which == "phase1":
                        return self._send(phase1_html(sn).encode("utf-8"))
                    if which == "phase2":
                        return self._send(phase2_html(sn).encode("utf-8"))
                    if which == "client":
                        return self._send(report_premium.build(sn).encode("utf-8"))
                if parts[2] == "compare":
                    a = _load_snapshot_by_id(slug, q.get("a", ""))
                    b = _load_snapshot_by_id(slug, q.get("b", ""))
                    if not a or not b:
                        return self._redirect(f"/company/{slug}/history?msg=" + quote("Pick two valid reports to compare."))
                    from .report import compare_html
                    return self._send(compare_html(slug, a, b).encode("utf-8"))
                if parts[2] == "report" and len(parts) == 4 and "/" not in parts[3] and "\\" not in parts[3]:
                    f = client_dir(slug) / "reports" / parts[3]
                    if f.is_file() and f.suffix in (".html", ".json"):
                        ctype = "application/json" if f.suffix == ".json" else "text/html; charset=utf-8"
                        return self._send(f.read_bytes(), ctype)
                    return self._send(layout("Not found", "<section><div class='wrap'><p>Report not generated yet — run a scan first.</p></div></section>"), code=404)
            return self._send(layout("Not found", "<section><div class='wrap'><p>404 — <a href='/'>home</a></p></div></section>"), code=404)
        except Exception as ex:
            traceback.print_exc()
            return self._send(layout("Error", f"<section><div class='wrap'><div class='msg err'>{e(type(ex).__name__)}: {e(ex)}</div></div></section>"), code=500)

    # -- POST
    def do_POST(self):
        try:
            u = urlparse(self.path)
            parts = [p for p in u.path.split("/") if p]
            form = self._form()

            if parts == ["start"]:
                name = form.get("name", "").strip()
                email = form.get("email", "").strip().lower()
                password = form.get("password", "")
                if not name:
                    return self._send(start_form("Company name is required."))
                if not email or "@" not in email:
                    return self._send(start_form("A valid work email is required — it becomes your sign-in ID."))
                if len(password) < 10:
                    return self._send(start_form("Password must be at least 10 characters."))
                if find_company_by_email(email):
                    return self._send(start_form("That email is already registered — use Company sign-in instead."))
                sites = [s.strip() for s in form.get("sites", "").split(",") if s.strip()]
                slug = init_client(name, sites)
                cfg = load_client(slug)
                cfg["contact"] = form.get("contact", "").strip()
                if not cfg.get("auth"):  # never overwrite an existing company's login
                    set_company_auth(cfg, email, password)
                if form.get("consent") == "1" and sites:
                    cfg["scanConsent"] = {"granted": True,
                                          "grantedBy": cfg["contact"] or "authorised at onboarding",
                                          "date": date.today().isoformat(),
                                          "note": "Authorised during onboarding — keep the written record on file."}
                save_json(client_dir(slug) / "client.json", cfg)
                token = secrets.token_urlsafe(24)
                _co_sessions[token] = slug
                welcome = "Workspace created — you are signed in. " + (
                    "Run your first assessment when ready." if cfg["scanConsent"].get("granted")
                    else "Record scan consent below when your organisation is ready, or start with the questionnaire.")
                return self._redirect(f"/company/{slug}?msg=" + quote(welcome),
                                      cookie=f"dpdpa_co={token}; HttpOnly; SameSite=Lax; Path=/")

            if parts == ["login"]:
                cfg = find_company_by_email(form.get("email", ""))
                auth = (cfg or {}).get("auth", {})
                if cfg and auth and hmac.compare_digest(
                        hash_password(form.get("password", ""), auth["salt"]), auth["hash"]):
                    token = secrets.token_urlsafe(24)
                    _co_sessions[token] = cfg["slug"]
                    return self._redirect(f"/company/{cfg['slug']}",
                                          cookie=f"dpdpa_co={token}; HttpOnly; SameSite=Lax; Path=/")
                return self._send(company_login("Email or password incorrect."))

            if parts == ["logout"]:
                _co_sessions.pop(self._cookie("dpdpa_co") or "", None)
                return self._redirect("/", cookie="dpdpa_co=; Max-Age=0; Path=/")

            if parts == ["admin", "login"]:
                pw = os.environ.get("DPDPA_ADMIN_PASSWORD", "dpdpa-admin")
                if hmac.compare_digest(form.get("password", ""), pw):
                    token = secrets.token_urlsafe(24)
                    _sessions.add(token)
                    return self._redirect("/admin", cookie=f"dpdpa_session={token}; HttpOnly; SameSite=Lax; Path=/")
                return self._send(admin_login("Wrong password."))

            if parts == ["admin", "logout"]:
                cookies = self.headers.get("Cookie", "")
                for part in cookies.split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "dpdpa_session":
                        _sessions.discard(v)
                return self._redirect("/", cookie="dpdpa_session=; Max-Age=0; Path=/")

            if parts == ["admin", "reset"]:
                if not self._is_admin():
                    return self._redirect("/admin")
                slug = form.get("slug", "")
                email = form.get("email", "").strip().lower()
                if not email or "@" not in email:
                    return self._redirect("/admin?msg=" + quote("A valid client email is needed to set the login."))
                other = find_company_by_email(email)
                if other and other["slug"] != slug:
                    return self._redirect("/admin?msg=" + quote(f"That email already belongs to {other['name']}."))
                cfg = load_client(slug)
                temp = "Tmp-" + secrets.token_urlsafe(9)
                set_company_auth(cfg, email, temp)
                save_json(client_dir(slug) / "client.json", cfg)
                return self._redirect("/admin?msg=" + quote(
                    f"Login for {cfg['name']} set to {email}. One-time temporary password: {temp} — "
                    f"share it with the client through a secure channel and ask them to change it "
                    f"from their workspace (Account section) after signing in."))

            if parts[:2] == ["admin", "rulebook"] and len(parts) == 3:
                if not self._is_admin():
                    return self._redirect("/admin")
                from .rulebook import load_rulebook, IMPORT_DIR
                from .workspace import save_json as _sj
                action = parts[2]
                try:
                    if action == "append":
                        version = form.get("version", "").strip()
                        new_controls = json.loads(form.get("controls", "").strip() or "[]")
                        if not isinstance(new_controls, list) or not new_controls:
                            raise ValueError("controls must be a non-empty JSON array")
                        for c in new_controls:
                            for req in ("id", "category", "severity", "title", "checkMethod"):
                                if req not in c:
                                    raise ValueError(f"a control is missing required field '{req}'")
                        rb = json.loads(json.dumps(load_rulebook()))  # deep copy of current
                        existing_ids = {c["id"] for c in rb["controls"]}
                        dupes = [c["id"] for c in new_controls if c["id"] in existing_ids]
                        if dupes:
                            raise ValueError(f"control id(s) already exist: {dupes}")
                        if not version or version in {b["rulebookVersion"] for b in __import__('dpdpa.rulebook', fromlist=['all_rulebooks']).all_rulebooks()}:
                            raise ValueError("provide a new, unused version number")
                        rb["rulebookVersion"] = version
                        rb["lastUpdated"] = date.today().isoformat()
                        rb["updateNote"] = form.get("note", "").strip() or f"Appended {len(new_controls)} control(s)."
                        rb["controls"].extend(new_controls)
                        IMPORT_DIR.mkdir(parents=True, exist_ok=True)
                        _sj(IMPORT_DIR / f"dpdpa-rulebook.v{version}.json", rb)
                        return self._redirect("/admin/rulebook?msg=" + quote(
                            f"Published rulebook v{version} with {len(new_controls)} new checkpoint(s). "
                            "Re-run a company's assessment to apply it."))
                    if action == "import":
                        rb = json.loads(form.get("rulebook", "").strip() or "{}")
                        if not rb.get("rulebookVersion") or not isinstance(rb.get("controls"), list) or not rb["controls"]:
                            raise ValueError("rulebook must have rulebookVersion and a non-empty controls array")
                        rb.setdefault("categories", [])
                        IMPORT_DIR.mkdir(parents=True, exist_ok=True)
                        _sj(IMPORT_DIR / f"dpdpa-rulebook.v{rb['rulebookVersion']}.json", rb)
                        return self._redirect("/admin/rulebook?msg=" + quote(
                            f"Imported rulebook v{rb['rulebookVersion']} ({len(rb['controls'])} controls)."))
                except (json.JSONDecodeError, ValueError) as ex:
                    return self._redirect("/admin/rulebook?err=1&msg=" + quote(f"Import failed: {ex}"))

            if parts == ["clients"]:  # admin quick-add
                if not self._is_admin():
                    return self._redirect("/admin")
                name = form.get("name", "").strip()
                if not name:
                    return self._redirect("/admin?msg=" + quote("Company name is required"))
                sites = [s.strip() for s in form.get("sites", "").split(",") if s.strip()]
                slug = init_client(name, sites)
                return self._redirect(f"/company/{slug}")

            if len(parts) == 4 and parts[0] == "company" and parts[2] == "notifications" and parts[3] == "read":
                slug = unquote(parts[1])
                if not self._may_access(slug):
                    return self._redirect("/login")
                from . import notify as _n
                _n.mark_all_read(slug)
                return self._redirect(f"/company/{slug}")

            if len(parts) >= 4 and parts[0] == "company" and parts[2] == "connectors":
                slug = unquote(parts[1])
                if not self._may_access(slug):
                    return self._redirect("/login?msg=" + quote("Please sign in to access your workspace."))
                path = client_dir(slug) / "connectors.json"
                conns = load_json(path, {})
                provider = parts[3]
                # (id_field, secret_fields, plain_fields, label)
                specs = {
                    "aws": ("accessKeyId", ["secretAccessKey"], [("region", "ap-south-1")], "AWS"),
                    "azure": ("clientId", ["clientSecret"], [("tenantId", ""), ("region", "")], "Azure"),
                    "intune": ("clientId", ["clientSecret"], [("tenantId", "")], "Intune/Defender"),
                    "gcp": ("projectId", ["accessToken"], [], "Google Cloud"),
                    "adgpo": ("collectorJson", [], [], "Active Directory / GPO"),
                    "firewall": ("configText", [], [], "Firewall config"),
                }
                if provider in specs and len(parts) == 4:
                    id_field, secret_fields, plain_fields, label = specs[provider]
                    existing = conns.get(provider, {})
                    if not form.get("consent"):
                        return self._redirect(f"/company/{slug}/connectors?err=1&msg=" + quote(f"Tick the authorisation box to connect {label}."))
                    idv = form.get(id_field, "").strip()
                    if not idv and not existing.get(id_field):
                        return self._redirect(f"/company/{slug}/connectors?err=1&msg=" + quote(f"{id_field} is required for {label}."))
                    rec = {id_field: idv or existing.get(id_field, "")}
                    for sf in secret_fields:
                        rec[sf] = form.get(sf, "") or existing.get(sf, "")
                    for pf, dflt in plain_fields:
                        rec[pf] = form.get(pf, "").strip() or existing.get(pf, dflt)
                    rec["consent"] = {"granted": True,
                                      "grantedBy": load_client(slug).get("contact", "authorised in workspace"),
                                      "date": date.today().isoformat()}
                    conns[provider] = rec
                    save_json(path, conns)
                    return self._redirect(f"/company/{slug}/connectors?msg=" + quote(f"{label} connected. Run an assessment to pull posture."))
                if provider in specs and len(parts) == 5 and parts[4] == "disconnect":
                    conns.pop(provider, None)
                    save_json(path, conns)
                    return self._redirect(f"/company/{slug}/connectors?msg=" + quote(f"{specs[provider][3]} disconnected and credentials deleted."))

            if len(parts) == 3 and parts[0] == "company":
                slug, action = unquote(parts[1]), parts[2]
                if not self._may_access(slug):
                    return self._redirect("/login?msg=" + quote("Please sign in to access your workspace."))
                cfg = load_client(slug)

                if action == "consent":
                    cfg["scanConsent"] = {"granted": True,
                                          "grantedBy": form.get("grantedBy", "").strip() or "recorded via web UI",
                                          "date": date.today().isoformat(),
                                          "note": "Recorded via web UI — keep the written authorisation on file."}
                    save_json(client_dir(slug) / "client.json", cfg)
                    return self._redirect(f"/company/{slug}?msg=" + quote("Scan authorisation recorded."))

                if action == "submit":
                    # Client action: file inputs for the engagement team. Never runs a scan.
                    cfg["submission"] = {"submitted": True, "at": date.today().isoformat(),
                                         "by": cfg.get("auth", {}).get("email", "") or cfg.get("contact", ""),
                                         "note": "Inputs submitted for assessment via workspace"}
                    cfg["pendingAssessment"] = True
                    save_json(client_dir(slug) / "client.json", cfg)
                    return self._redirect(f"/company/{slug}?msg=" + quote(
                        "Thank you — your inputs are submitted. Your DPDPA assessment team will prepare your report."))

                if action == "scan":
                    # Running an assessment is an operator-only action.
                    if not self._is_admin():
                        return self._redirect(f"/company/{slug}?err=1&msg=" + quote(
                            "Assessments are run by your DPDPA engagement team. Submit your inputs and your report will follow."))
                    skip_web = "skipweb=1" in (u.query or "")
                    if not skip_web and not cfg.get("scanConsent", {}).get("granted"):
                        return self._redirect(f"/company/{slug}?err=1&msg=" + quote("Client has not authorised the website scan yet (or run questionnaire-only)."))
                    if not skip_web and not cfg.get("sites"):
                        skip_web = True
                    if cfg.get("pendingAssessment"):  # operator is now acting on the client's submission
                        cfg["pendingAssessment"] = False
                        save_json(client_dir(slug) / "client.json", cfg)
                    _start_scan(slug, skip_web)
                    return self._redirect(f"/company/{slug}")

                if action == "password":
                    auth = cfg.get("auth", {})
                    if not auth:
                        return self._redirect(f"/company/{slug}?err=1&msg=" + quote("No login exists for this workspace yet — ask the administrator to create one."))
                    if not hmac.compare_digest(hash_password(form.get("current", ""), auth["salt"]), auth["hash"]):
                        return self._redirect(f"/company/{slug}?err=1&msg=" + quote("Current password is incorrect."))
                    if len(form.get("new", "")) < 10:
                        return self._redirect(f"/company/{slug}?err=1&msg=" + quote("New password must be at least 10 characters."))
                    set_company_auth(cfg, auth["email"], form["new"])
                    save_json(client_dir(slug) / "client.json", cfg)
                    return self._redirect(f"/company/{slug}?msg=" + quote("Password changed."))

                if action == "questionnaire":
                    path = client_dir(slug) / "questionnaire.json"
                    qn = load_json(path, {})
                    old = {a["controlId"]: a for a in qn.get("assertions", [])}
                    rb = load_rulebook()
                    assertions = []
                    for c in rb["controls"]:
                        cid = c["id"]
                        st = form.get(f"st-{cid}", "")
                        if st not in VALID:
                            continue
                        prev = old.get(cid, {})
                        src = prev.get("source", {}) if isinstance(prev.get("source"), dict) else {}
                        assertions.append({
                            "controlId": cid, "status": st,
                            "evidence": form.get(f"ev-{cid}", "").strip() or (
                                prev.get("evidence") if isinstance(prev.get("evidence"), str) else ""),
                            "source": {"department": form.get(f"dept-{cid}", "").strip() or src.get("department", ""),
                                       "respondent": "web-ui", "date": date.today().isoformat()},
                        })
                    qn["assertions"] = assertions
                    save_json(path, qn)
                    return self._redirect(f"/company/{slug}?msg=" + quote(f"Saved {len(assertions)} answers. Run an assessment to refresh your score."))

            return self._send(layout("Not found", "<section><div class='wrap'><p>404</p></div></section>"), code=404)
        except Exception as ex:
            traceback.print_exc()
            return self._send(layout("Error", f"<section><div class='wrap'><div class='msg err'>{e(type(ex).__name__)}: {e(ex)}</div></div></section>"), code=500)


def serve(slug: str | None = None, port: int = 8377, host: str = "127.0.0.1") -> None:
    with ThreadingHTTPServer((host, port), App) as httpd:
        print(f"{PRODUCT_NAME} running: http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}/  (Ctrl+C to stop)")
        httpd.serve_forever()
