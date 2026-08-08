"""DPDPA Sentinel web application (stdlib only — no framework).

Multi-client UI: add companies, record scan consent, fill the questionnaire in
the browser, run scans with a button, generate and view reports, see alerts.

Prototype has no authentication: bind 127.0.0.1 locally. In Docker the
container binds 0.0.0.0 internally and you publish the port to localhost.
Production (.NET port) replaces this with an authenticated multi-tenant app.
"""
from __future__ import annotations

import html
import json
import threading
import traceback
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

from . import PRODUCT_NAME, __version__
from .engine import run_scan, summarize
from .rulebook import load_rulebook
from .scanners.questionnaire import VALID
from .workspace import (LOCAL_ROOT, client_dir, init_client, list_snapshots,
                        load_client, load_json, save_json)

_jobs: dict = {}          # slug -> {"state": running|done|error, "detail": str}
_jobs_lock = threading.Lock()

_CSS = """
body{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1c2733}
.wrap{max-width:1100px;margin:0 auto;padding:20px}
header{background:#0d2137;color:#fff}
header .wrap{display:flex;justify-content:space-between;align-items:center;padding-top:14px;padding-bottom:14px}
header a{color:#fff;text-decoration:none}
h1{font-size:20px;margin:0} h2{margin:26px 0 10px;font-size:18px;border-bottom:2px solid #dde3ea;padding-bottom:6px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:14px}
th,td{border:1px solid #dde3ea;padding:8px 10px;text-align:left;vertical-align:top}
th{background:#eef2f6}
.btn{display:inline-block;background:#0d6efd;color:#fff;border:none;border-radius:6px;
padding:8px 16px;font-size:14px;cursor:pointer;text-decoration:none;margin:2px}
.btn.green{background:#1a7f37}.btn.gray{background:#607d8b}.btn.red{background:#c62828}
.btn:disabled{background:#9db2c5}
input[type=text],input[type=url],textarea,select{width:100%;box-sizing:border-box;padding:7px;
border:1px solid #b9c6d2;border-radius:5px;font-size:13px;font-family:inherit}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-size:12px;font-weight:600}
.msg{background:#e7f1ff;border:1px solid #9ec5fe;border-radius:6px;padding:10px 14px;margin:12px 0}
.err{background:#fdecea;border-color:#f5c6cb}
.card{background:#fff;border:1px solid #dde3ea;border-radius:8px;padding:16px 20px;margin:10px 0}
.cards{display:flex;gap:12px;flex-wrap:wrap}
.cards .stat{background:#fff;border:1px solid #dde3ea;border-radius:8px;padding:10px 18px;text-align:center;min-width:90px}
.stat .n{font-size:26px;font-weight:700}
.small{font-size:12px;color:#607d8b}
.cat{background:#0d2137;color:#fff;padding:6px 10px;font-size:13px}
.spin{display:inline-block;width:14px;height:14px;border:3px solid #cfe0f4;border-top-color:#0d6efd;
border-radius:50%;animation:s 1s linear infinite;vertical-align:middle}
@keyframes s{to{transform:rotate(360deg)}}
"""

_STATUS_COLORS = {"COMPLIANT": "#1a7f37", "PARTIAL": "#b58900", "GAP": "#c62828",
                  "NA": "#607d8b", "TBC": "#5c6bc0"}


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _badge(status: str) -> str:
    return f'<span class="badge" style="background:{_STATUS_COLORS.get(status, "#607d8b")}">{_e(status)}</span>'


def _page(title: str, body: str, refresh: int | None = None) -> bytes:
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return f"""<!doctype html><html><head><meta charset="utf-8">{meta}
<title>{_e(title)} — {PRODUCT_NAME}</title><style>{_CSS}</style></head><body>
<header><div class="wrap"><h1><a href="/">🛡 {PRODUCT_NAME}</a></h1>
<span class="small" style="color:#9fb3c8">v{__version__} · DPDPA 2023 + DPDP Rules 2025 · rulebook v{load_rulebook()['rulebookVersion']}</span></div></header>
<div class="wrap">{body}</div></body></html>""".encode("utf-8")


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
                               "detail": f"scan {snap['scanId']} complete — score {s['complianceScore']}%"}
        except Exception as ex:
            with _jobs_lock:
                _jobs[slug] = {"state": "error", "detail": f"{type(ex).__name__}: {ex}"}
            traceback.print_exc()

    threading.Thread(target=work, daemon=True).start()


# ---------------------------------------------------------------- pages ----

def page_dashboard(msg: str = "") -> bytes:
    rows = []
    for cfg in _clients():
        slug = cfg["slug"]
        snap = _latest_snapshot(slug)
        job = _job_state(slug)
        if job and job["state"] == "running":
            status = '<span class="spin"></span> scanning…'
        elif snap:
            s = summarize(snap)
            status = (f"<b>{s['complianceScore']}%</b> &nbsp; "
                      f"{_badge('GAP')} {s['counts']['GAP']} · {_badge('TBC')} {s['counts']['TBC']} "
                      f"<span class='small'>({snap['scanId']})</span>")
        else:
            status = '<span class="small">never scanned</span>'
        consent = "✅" if cfg.get("scanConsent", {}).get("granted") else "—"
        rows.append(f"""<tr><td><a href="/client/{slug}"><b>{_e(cfg['name'])}</b></a></td>
<td class="small">{_e(', '.join(cfg.get('sites', [])) or '(questionnaire only)')}</td>
<td style="text-align:center">{consent}</td><td>{status}</td>
<td><a class="btn" href="/client/{slug}">Open</a></td></tr>""")
    body = f"""
{f'<div class="msg">{_e(unquote(msg))}</div>' if msg else ''}
<h2>Companies</h2>
<table><tr><th>Company</th><th>Sites</th><th>Scan consent</th><th>Latest result</th><th></th></tr>
{''.join(rows) or '<tr><td colspan="5">No companies yet — add one below.</td></tr>'}</table>
<h2>Add a company</h2>
<div class="card"><form method="post" action="/clients">
<table style="border:none"><tr>
<td style="border:none;width:34%"><label>Company name<br><input type="text" name="name" required placeholder="Acme Exports Pvt Ltd"></label></td>
<td style="border:none"><label>Websites (comma-separated, optional)<br>
<input type="text" name="sites" placeholder="https://www.acme.example, https://catalog.acme.example"></label></td>
<td style="border:none;width:120px;vertical-align:bottom"><button class="btn green" type="submit">Add company</button></td>
</tr></table>
<div class="small">Scanning starts only after you record the company's written consent on its page.</div>
</form></div>"""
    return _page("Companies", body)


def page_client(slug: str, msg: str = "", is_err: bool = False) -> bytes:
    cfg = load_client(slug)
    snap = _latest_snapshot(slug)
    job = _job_state(slug)
    running = bool(job and job["state"] == "running")
    consent = cfg.get("scanConsent", {})
    alerts = load_json(client_dir(slug) / "alerts.json", {})

    if running:
        scan_zone = '<p><span class="spin"></span> <b>Scan in progress…</b> this page refreshes automatically.</p>'
    else:
        job_note = (f'<div class="msg {"err" if job["state"] == "error" else ""}">{_e(job["detail"])}</div>'
                    if job else "")
        scan_zone = f"""{job_note}
<form method="post" action="/client/{slug}/scan" style="display:inline">
<button class="btn" {'title="record consent first" disabled' if not consent.get('granted') else ''}
type="submit">▶ Run full scan (web + questionnaire)</button></form>
<form method="post" action="/client/{slug}/scan?skipweb=1" style="display:inline">
<button class="btn gray" type="submit">Run questionnaire-only scan</button></form>
<a class="btn gray" href="/client/{slug}/questionnaire">✎ Fill questionnaire</a>"""

    if snap:
        s = summarize(snap)
        stats = "".join(
            f'<div class="stat"><div class="n" style="color:{_STATUS_COLORS[k]}">{v}</div><div class="small">{k}</div></div>'
            for k, v in s["counts"].items())
        results = f"""
<div class="cards"><div class="stat"><div class="n">{s['complianceScore']}%</div><div class="small">score</div></div>{stats}</div>
<p><a class="btn green" href="/client/{slug}/report/phase1-discovery.html">📄 Phase 1 — Discovery</a>
<a class="btn green" href="/client/{slug}/report/phase2-gap-assessment.html">📄 Phase 2 — Gap Assessment</a>
<a class="btn gray" href="/client/{slug}/report/summary.json">summary.json</a></p>
<p class="small">Scans on file: {len(list_snapshots(slug))} · latest {snap['scanId']} · rulebook v{snap['rulebookVersion']}</p>"""
    else:
        results = "<p class='small'>No scans yet.</p>"

    alert_rows = "".join(
        f"<tr><td><b>{_e(a['type'])}</b></td><td>{_e(a.get('controlId', ''))}</td><td>{_e(a.get('detail', ''))}</td></tr>"
        for a in alerts.get("alerts", []))
    consent_zone = (
        f"<p>✅ Consent recorded — <span class='small'>{_e(consent.get('grantedBy', ''))} ({_e(consent.get('date', ''))})</span></p>"
        if consent.get("granted") else f"""
<form method="post" action="/client/{slug}/consent">
<p>⚠ No scan consent recorded. Web scanning is blocked until the company authorises it in writing.</p>
<input type="text" name="grantedBy" required placeholder="Who authorised, and how (e.g. email from CTO dated ...)" style="max-width:520px">
<button class="btn" type="submit">Record consent</button></form>""")

    body = f"""
<p class="small"><a href="/">← all companies</a></p>
{f'<div class="msg {"err" if is_err else ""}">{_e(unquote(msg))}</div>' if msg else ''}
<h2>{_e(cfg['name'])}</h2>
<div class="card"><b>Sites:</b> {_e(', '.join(cfg.get('sites', [])) or '(none — questionnaire only)')}
<div>{consent_zone}</div></div>
<h2>Scan</h2>{scan_zone}
<h2>Latest results</h2>{results}
<h2>Alerts (latest scan vs previous)</h2>
<table><tr><th>Type</th><th>Control</th><th>Detail</th></tr>
{alert_rows or '<tr><td colspan="3" class="small">none</td></tr>'}</table>"""
    return _page(cfg["name"], body, refresh=4 if running else None)


def page_questionnaire(slug: str) -> bytes:
    cfg = load_client(slug)
    rb = load_rulebook()
    q = load_json(client_dir(slug) / "questionnaire.json", {})
    existing = {a["controlId"]: a for a in q.get("assertions", [])}
    cats = {c["id"]: c["name"] for c in rb["categories"]}

    rows, last_cat = [], None
    for c in rb["controls"]:
        if c["category"] != last_cat:
            rows.append(f'<tr><td colspan="4" class="cat">{_e(c["category"])} — {_e(cats[c["category"]])}</td></tr>')
            last_cat = c["category"]
        a = existing.get(c["id"], {})
        opts = '<option value="">— not answered —</option>' + "".join(
            f'<option value="{v}" {"selected" if a.get("status") == v else ""}>{v}</option>'
            for v in sorted(VALID))
        ev = _e(a.get("evidence", "") if isinstance(a.get("evidence"), str)
                else (a.get("evidence", [{}])[0].get("excerpt", "") if a.get("evidence") else ""))
        dept = _e(a.get("source", {}).get("department", ""))
        auto = " <span class='small'>(also auto-checked by scanner)</span>" if c["checkMethod"] in ("web", "hybrid") else ""
        rows.append(f"""<tr>
<td style="width:220px"><b>{_e(c['id'])}</b> {_e(c['title'])}<div class="small">{_e(c['legalRef'])} · {_e(c['severity'])}{auto}</div></td>
<td style="width:130px"><select name="st-{c['id']}">{opts}</select></td>
<td><textarea name="ev-{c['id']}" rows="2" placeholder="Evidence / basis for this answer">{ev}</textarea></td>
<td style="width:150px"><input type="text" name="dept-{c['id']}" value="{dept}" placeholder="Department"></td></tr>""")

    body = f"""
<p class="small"><a href="/client/{slug}">← {_e(cfg['name'])}</a></p>
<h2>Questionnaire — {_e(cfg['name'])}</h2>
<p class="small">Manual declarations for checkpoints the scanner cannot see from outside. A declaration can
<b>confirm</b> an automated signal but can never override a scanner-observed gap. Leave a row unanswered to keep it TBC.</p>
<form method="post" action="/client/{slug}/questionnaire">
<table><tr><th>Checkpoint</th><th>Status</th><th>Evidence</th><th>Department</th></tr>{''.join(rows)}</table>
<p><button class="btn green" type="submit">Save answers</button>
<span class="small">Saving re-writes questionnaire.json; run a scan afterwards to refresh statuses.</span></p></form>"""
    return _page("Questionnaire", body)


# ------------------------------------------------------------- handler ----

class App(BaseHTTPRequestHandler):
    server_version = "DPDPASentinel/" + __version__

    def _send(self, body: bytes, ctype="text/html; charset=utf-8", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, path: str):
        self.send_response(303)
        self.send_header("Location", path)
        self.end_headers()

    def _form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        try:
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            parts = [p for p in u.path.split("/") if p]
            if not parts:
                return self._send(page_dashboard(q.get("msg", "")))
            if parts[0] == "client" and len(parts) >= 2:
                slug = unquote(parts[1])
                if len(parts) == 2:
                    return self._send(page_client(slug, q.get("msg", ""), q.get("err") == "1"))
                if parts[2] == "questionnaire":
                    return self._send(page_questionnaire(slug))
                if parts[2] == "report" and len(parts) == 4 and "/" not in parts[3] and "\\" not in parts[3]:
                    f = client_dir(slug) / "reports" / parts[3]
                    if f.is_file() and f.suffix in (".html", ".json"):
                        ctype = "application/json" if f.suffix == ".json" else "text/html; charset=utf-8"
                        return self._send(f.read_bytes(), ctype)
                    return self._send(_page("Not found", "<p>Report not generated yet — run a scan.</p>"), code=404)
            return self._send(_page("Not found", "<p>404 — <a href='/'>back</a></p>"), code=404)
        except Exception as ex:
            traceback.print_exc()
            return self._send(_page("Error", f"<div class='msg err'>{_e(type(ex).__name__)}: {_e(ex)}</div>"), code=500)

    def do_POST(self):
        try:
            u = urlparse(self.path)
            parts = [p for p in u.path.split("/") if p]
            form = self._form()

            if parts == ["clients"]:
                name = form.get("name", "").strip()
                if not name:
                    return self._redirect("/?msg=" + quote("Company name is required"))
                sites = [s.strip() for s in form.get("sites", "").split(",") if s.strip()]
                slug = init_client(name, sites)
                return self._redirect(f"/client/{slug}?msg=" + quote("Company created. Record scan consent, fill the questionnaire, then run a scan."))

            if len(parts) == 3 and parts[0] == "client":
                slug, action = unquote(parts[1]), parts[2]
                cfg = load_client(slug)

                if action == "consent":
                    cfg["scanConsent"] = {"granted": True,
                                          "grantedBy": form.get("grantedBy", "").strip() or "recorded via web UI",
                                          "date": date.today().isoformat(),
                                          "note": "Recorded via web UI — keep the written authorisation on file."}
                    save_json(client_dir(slug) / "client.json", cfg)
                    return self._redirect(f"/client/{slug}?msg=" + quote("Consent recorded."))

                if action == "scan":
                    skip_web = "skipweb=1" in (u.query or "")
                    if not skip_web and not cfg.get("scanConsent", {}).get("granted"):
                        return self._redirect(f"/client/{slug}?err=1&msg=" + quote("Web scan blocked: record consent first (or run questionnaire-only)."))
                    if not skip_web and not cfg.get("sites"):
                        skip_web = True
                    _start_scan(slug, skip_web)
                    return self._redirect(f"/client/{slug}")

                if action == "questionnaire":
                    path = client_dir(slug) / "questionnaire.json"
                    q = load_json(path, {})
                    old = {a["controlId"]: a for a in q.get("assertions", [])}
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
                    q["assertions"] = assertions
                    save_json(path, q)
                    return self._redirect(f"/client/{slug}?msg=" + quote(f"Saved {len(assertions)} answers. Run a scan to refresh statuses."))

            return self._send(_page("Not found", "<p>404</p>"), code=404)
        except Exception as ex:
            traceback.print_exc()
            return self._send(_page("Error", f"<div class='msg err'>{_e(type(ex).__name__)}: {_e(ex)}</div>"), code=500)


def serve(slug: str | None = None, port: int = 8377, host: str = "127.0.0.1") -> None:
    with ThreadingHTTPServer((host, port), App) as httpd:
        print(f"{PRODUCT_NAME} running: http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}/  (Ctrl+C to stop)")
        httpd.serve_forever()
