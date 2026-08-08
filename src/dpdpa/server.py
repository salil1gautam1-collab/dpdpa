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
from .webui import badge, e, landing, layout, start_form, admin_login, STATUS_COLORS
from .workspace import (LOCAL_ROOT, client_dir, init_client, list_snapshots,
                        load_client, load_json, save_json)

_jobs: dict = {}
_jobs_lock = threading.Lock()
_sessions: set = set()

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
            snap = run_scan(slug, skip_web=skip_web)
            from .report import generate
            generate(slug, snap)
            from .diffalert import diff
            diff(slug)
            s = summarize(snap)
            with _jobs_lock:
                _jobs[slug] = {"state": "done",
                               "detail": f"Scan complete — compliance score {s['complianceScore']}%"}
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

def page_company(slug: str, msg: str = "", is_err: bool = False) -> bytes:
    cfg = load_client(slug)
    snap = _latest_snapshot(slug)
    job = _job_state(slug)
    running = bool(job and job["state"] == "running")
    consent = cfg.get("scanConsent", {})
    has_sites = bool(cfg.get("sites"))
    q = load_json(client_dir(slug) / "questionnaire.json", {})
    n_answered = len(q.get("assertions", []))
    alerts = load_json(client_dir(slug) / "alerts.json", {})

    # progress steps
    def step(label, state):
        return f'<span class="{state}">{label}</span>'
    steps = [step("① Company details ✓", "done"),
             step("② Scan consent " + ("✓" if consent.get("granted") else "— pending"),
                  "done" if consent.get("granted") else ("now" if has_sites else "")),
             step(f"③ Questionnaire — {n_answered}/57 answered",
                  "done" if n_answered >= 40 else ("now" if n_answered else "")),
             step("④ Scan " + ("✓" if snap else "— not yet run"), "done" if snap else "now"),
             step("⑤ Reports " + ("✓" if snap else ""), "done" if snap else "")]

    if snap:
        s = summarize(snap)
        score = s["complianceScore"]
        chips = "".join(
            f'<span class="chip"><b style="color:{STATUS_COLORS[k]}">{v}</b>{k.title() if k != "NA" else "N/A"}</span>'
            for k, v in s["counts"].items())
        head_right = f"""
<div class="donut" style="--p:{score};--dc:{_score_color(score)}"><div>{score}%<small>compliance</small></div></div>"""
        results = f"""
<div class="grid c3" style="margin-top:6px">
<div class="tile"><div class="ico">📄</div><h3>Phase 1 — Discovery</h3>
<p>Your data footprint: pages, cookies, trackers, forms, questionnaire coverage.</p>
<p style="margin-top:12px"><a class="btn sm" href="/company/{slug}/report/phase1-discovery.html">Open report</a></p></div>
<div class="tile"><div class="ico">📊</div><h3>Phase 2 — Gap Assessment</h3>
<p>All 57 checkpoints graded with severity, evidence and recommendations.</p>
<p style="margin-top:12px"><a class="btn sm" href="/company/{slug}/report/phase2-gap-assessment.html">Open report</a></p></div>
<div class="tile"><div class="ico">🧾</div><h3>Machine-readable</h3>
<p>Summary JSON for your GRC tooling or board pack automation.</p>
<p style="margin-top:12px"><a class="btn sm gray" href="/company/{slug}/report/summary.json">summary.json</a></p></div>
</div>
<p class="small">Scans on file: {len(list_snapshots(slug))} · latest {e(snap['scanId'])} · rulebook v{e(snap['rulebookVersion'])}</p>"""
    else:
        head_right = '<div class="donut" style="--p:0;--dc:var(--na)"><div>—<small>no scan yet</small></div></div>'
        chips = ""
        results = "<p class='small'>Run your first scan to generate reports.</p>"

    if running:
        scan_zone = ('<div class="card"><span class="spin"></span> <b>Scan in progress…</b> '
                     'checking your sites and evaluating all 57 checkpoints. This page refreshes automatically.</div>')
    else:
        job_note = (f'<div class="msg {"err" if job["state"] == "error" else ""}">{e(job["detail"])}</div>'
                    if job else "")
        buttons = []
        if has_sites:
            buttons.append(
                f'<form method="post" action="/company/{slug}/scan" style="display:inline">'
                f'<button class="btn green" type="submit" '
                + ("" if consent.get("granted") else 'disabled title="record scan consent first"')
                + ">▶ Run full assessment</button></form>")
        buttons.append(
            f'<form method="post" action="/company/{slug}/scan?skipweb=1" style="display:inline">'
            f'<button class="btn gray" type="submit">Run questionnaire-only assessment</button></form>')
        buttons.append(f'<a class="btn" href="/company/{slug}/questionnaire">✎ Fill questionnaire ({n_answered}/57)</a>')
        scan_zone = job_note + "<p>" + " ".join(buttons) + "</p>"

    consent_zone = "" if consent.get("granted") or not has_sites else f"""
<div class="card" style="border-color:#e6d9a8;background:#fff8e6">
<h3 style="margin-top:0">Authorise the website scan</h3>
<p style="font-size:14px">Web scanning is disabled until your organisation authorises it. Scans are passive,
read-only visits to your public pages — no credentials, no form submissions, no intrusion.</p>
<form method="post" action="/company/{slug}/consent">
<input type="text" name="grantedBy" required placeholder="Name, designation and basis (e.g. approved by R. Sharma, CTO, email dated …)" style="max-width:560px">
<p><button class="btn" type="submit">Record authorisation</button></p></form></div>"""

    alert_rows = "".join(
        f"<tr><td><b>{e(a['type'])}</b></td><td>{e(a.get('controlId', ''))}</td><td>{e(a.get('detail', ''))}</td></tr>"
        for a in alerts.get("alerts", []))

    body = f"""
<div class="ws-head"><div class="wrap flexh">
<div style="flex:1;min-width:260px"><h1>{e(cfg['name'])}</h1>
<div class="small">{e(', '.join(cfg.get('sites', [])) or 'Questionnaire-only assessment')}</div>
<div class="chips">{chips}</div></div>{head_right}</div></div>
<div class="wrap">
{f'<div class="msg {"err" if is_err else ""}">{e(unquote(msg))}</div>' if msg else ''}
<div class="steps-bar">{''.join(steps)}</div>
{consent_zone}
<h2>Assessment</h2>{scan_zone}
<h2>Reports</h2>{results}
<h2>Change alerts</h2>
<p class="small">Raised automatically when a re-scan finds a regression, a new third party, or a rulebook change.</p>
<table><tr><th style="width:170px">Type</th><th style="width:90px">Control</th><th>Detail</th></tr>
{alert_rows or '<tr><td colspan="3" class="small">none — run at least two scans to compare</td></tr>'}</table>
<p style="margin:26px 0"><a href="/" class="small">← back to home</a></p>
</div>"""
    return layout(cfg["name"], body, refresh=4 if running else None)


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
        rows.append(f"""<tr><td><a href="/company/{slug}"><b>{e(cfg['name'])}</b></a>
<div class="small">{contact}</div></td>
<td class="small">{e(', '.join(cfg.get('sites', [])) or '(questionnaire only)')}</td>
<td style="text-align:center">{consent}</td><td>{status}</td>
<td><a class="btn sm" href="/company/{slug}">Open</a></td></tr>""")
    body = f"""
<section><div class="wrap">
{f'<div class="msg">{e(unquote(msg))}</div>' if msg else ''}
<h2>Operations dashboard <span class="small">· all engagements</span></h2>
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

    def _is_admin(self) -> bool:
        cookies = self.headers.get("Cookie", "")
        for part in cookies.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "dpdpa_session" and v in _sessions:
                return True
        return False

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
            if parts[0] == "admin":
                if not self._is_admin():
                    return self._send(admin_login(q.get("msg", "")))
                return self._send(page_admin(q.get("msg", "")))
            if parts[0] in ("company", "client") and len(parts) >= 2:
                slug = unquote(parts[1])
                if parts[0] == "client":  # legacy URLs
                    return self._redirect("/company/" + "/".join(parts[1:]))
                if len(parts) == 2:
                    return self._send(page_company(slug, q.get("msg", ""), q.get("err") == "1"))
                if parts[2] == "questionnaire":
                    return self._send(page_questionnaire(slug))
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
                if not name:
                    return self._send(start_form("Company name is required."))
                sites = [s.strip() for s in form.get("sites", "").split(",") if s.strip()]
                slug = init_client(name, sites)
                cfg = load_client(slug)
                cfg["contact"] = form.get("contact", "").strip()
                if form.get("consent") == "1" and sites:
                    cfg["scanConsent"] = {"granted": True,
                                          "grantedBy": cfg["contact"] or "authorised at onboarding",
                                          "date": date.today().isoformat(),
                                          "note": "Authorised during onboarding — keep the written record on file."}
                save_json(client_dir(slug) / "client.json", cfg)
                welcome = "Workspace created. " + (
                    "Run your first assessment when ready." if cfg["scanConsent"].get("granted")
                    else "Record scan consent below when your organisation is ready, or start with the questionnaire.")
                return self._redirect(f"/company/{slug}?msg=" + quote(welcome))

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

            if parts == ["clients"]:  # admin quick-add
                if not self._is_admin():
                    return self._redirect("/admin")
                name = form.get("name", "").strip()
                if not name:
                    return self._redirect("/admin?msg=" + quote("Company name is required"))
                sites = [s.strip() for s in form.get("sites", "").split(",") if s.strip()]
                slug = init_client(name, sites)
                return self._redirect(f"/company/{slug}")

            if len(parts) == 3 and parts[0] == "company":
                slug, action = unquote(parts[1]), parts[2]
                cfg = load_client(slug)

                if action == "consent":
                    cfg["scanConsent"] = {"granted": True,
                                          "grantedBy": form.get("grantedBy", "").strip() or "recorded via web UI",
                                          "date": date.today().isoformat(),
                                          "note": "Recorded via web UI — keep the written authorisation on file."}
                    save_json(client_dir(slug) / "client.json", cfg)
                    return self._redirect(f"/company/{slug}?msg=" + quote("Scan authorisation recorded."))

                if action == "scan":
                    skip_web = "skipweb=1" in (u.query or "")
                    if not skip_web and not cfg.get("scanConsent", {}).get("granted"):
                        return self._redirect(f"/company/{slug}?err=1&msg=" + quote("Web scan blocked: record authorisation first (or run questionnaire-only)."))
                    if not skip_web and not cfg.get("sites"):
                        skip_web = True
                    _start_scan(slug, skip_web)
                    return self._redirect(f"/company/{slug}")

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
