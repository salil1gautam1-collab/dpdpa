"""Local dashboard — serves the client's reports on 127.0.0.1.

Prototype has no authentication, so it binds loopback only. Production (.NET
port) replaces this with an authenticated multi-tenant web app.
"""
from __future__ import annotations

import http.server
import json

from .workspace import client_dir, load_json, list_snapshots


def serve(slug: str, port: int = 8377) -> None:
    root = client_dir(slug)
    reports = root / "reports"

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(reports), **kw)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                snaps = list_snapshots(slug)
                alerts = load_json(root / "alerts.json", {"alerts": []})
                rows = "".join(f"<li>{s.stem}</li>" for s in snaps[-10:])
                alert_rows = "".join(
                    f"<li><b>{a['type']}</b> {a.get('controlId','')} — {a.get('detail','')}</li>"
                    for a in alerts.get("alerts", [])) or "<li>none</li>"
                body = f"""<!doctype html><meta charset="utf-8"><title>DPDPA Sentinel — {slug}</title>
<body style="font-family:Segoe UI,sans-serif;max-width:800px;margin:40px auto">
<h1>DPDPA Sentinel — {slug}</h1>
<p><a href="/phase1-discovery.html">Phase 1 — Discovery &amp; Inventory</a> ·
<a href="/phase2-gap-assessment.html">Phase 2 — Gap Assessment</a> ·
<a href="/summary.json">summary.json</a></p>
<h2>Recent scans</h2><ul>{rows or '<li>none yet</li>'}</ul>
<h2>Latest alerts</h2><ul>{alert_rows}</ul></body>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))
                return
            super().do_GET()

        def log_message(self, fmt, *args):
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler) as httpd:
        print(f"Dashboard: http://127.0.0.1:{port}/  (Ctrl+C to stop)")
        httpd.serve_forever()
