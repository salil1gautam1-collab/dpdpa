"""Command-line interface.

  dpdpa init --client "Name" --site https://example.com [--site ...]
  dpdpa scan --client <slug> [--skip-web]
  dpdpa report --client <slug>
  dpdpa diff --client <slug>
  dpdpa serve --client <slug> [--port 8377]
  dpdpa retention --client <slug> [--apply]
  dpdpa controls [--category CK]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from . import PRODUCT_NAME, __version__
from .engine import run_scan, summarize
from .rulebook import load_rulebook
from .workspace import client_dir, init_client, list_snapshots, load_json


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dpdpa", description=f"{PRODUCT_NAME} v{__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create a client workspace under local/")
    p.add_argument("--client", required=True)
    p.add_argument("--site", action="append", default=[], help="repeatable")

    for name in ("scan", "report", "diff", "retention"):
        p = sub.add_parser(name)
        p.add_argument("--client", required=True)
        if name == "scan":
            p.add_argument("--skip-web", action="store_true", help="questionnaire-only scan")
        if name == "retention":
            p.add_argument("--apply", action="store_true")
            p.add_argument("--months", type=int, default=24)

    p = sub.add_parser("serve", help="run the web app (all companies)")
    p.add_argument("--port", type=int, default=8377)
    p.add_argument("--host", default="127.0.0.1", help="0.0.0.0 inside Docker")

    sub.add_parser("demo", help="seed two dummy companies with sample answers")

    p = sub.add_parser("controls", help="list rulebook checkpoints")
    p.add_argument("--category", default=None)

    args = ap.parse_args(argv)

    if args.cmd == "init":
        slug = init_client(args.client, args.site)
        print(f"Workspace ready: local/{slug}/")
        print("Next: set scanConsent.granted=true in client.json once written "
              "authorisation to scan is on file, then run: dpdpa scan --client", slug)

    elif args.cmd == "scan":
        snap = run_scan(args.client, skip_web=args.skip_web)
        s = summarize(snap)
        print(f"Scan {snap['scanId']} complete — rulebook v{snap['rulebookVersion']}")
        print(f"  Compliant {s['counts']['COMPLIANT']} | Partial {s['counts']['PARTIAL']} | "
              f"Gap {s['counts']['GAP']} | NA {s['counts']['NA']} | TBC {s['counts']['TBC']}")
        print(f"  Score: {s['complianceScore']}% of determined checkpoints")
        for w in snap.get("warnings", []):
            print("  warning:", w)

    elif args.cmd == "report":
        from .report import generate
        for f in generate(args.client):
            print("wrote", f)

    elif args.cmd == "diff":
        from .diffalert import diff
        res = diff(args.client)
        if not res["alerts"]:
            print(res.get("note", "No changes between the two most recent scans."))
        for a in res["alerts"]:
            print(f"[{a['type']}] {a.get('controlId', '')} {a.get('title', '')} — {a.get('detail', '')}")

    elif args.cmd == "serve":
        from .server import serve
        serve(None, args.port, args.host)

    elif args.cmd == "demo":
        from .workspace import save_json
        from .report import generate
        demos = {
            "Demo Manufacturing Co (dummy)": [
                ("NT-01", "GAP", "No privacy notice published on factory-outlet site."),
                ("CN-01", "GAP", "Single generic consent line on enquiry form."),
                ("SEC-01", "PARTIAL", "Antivirus and firewall in place; no documented safeguards policy."),
                ("RET-01", "GAP", "No retention schedule; ERP keeps records indefinitely."),
                ("PR-01", "PARTIAL", "DPA signed with cloud vendor; none with transporter or job-work partners."),
                ("BR-01", "GAP", "No incident-response plan."),
                ("CH-01", "NA", "Industrial B2B only, corporate onboarding, no consumer sign-up."),
                ("DR-01", "GAP", "No published channel for data principal requests."),
            ],
            "Acme Exports Pvt Ltd (dummy)": [
                ("NT-01", "COMPLIANT", "Privacy notice published and linked site-wide (verified by counsel)."),
                ("CN-02", "PARTIAL", "Consent checkbox on contact form; missing on newsletter form."),
                ("SEC-04", "GAP", "Web-server logs rotate after 30 days — Rule 6 needs one year."),
                ("XB-01", "PARTIAL", "Transfers to overseas buyers recorded in CRM; no formal register."),
                ("RET-01", "PARTIAL", "Retention schedule drafted, not yet approved."),
                ("BR-02", "GAP", "No Board/data-principal notification templates."),
                ("GOV-01", "COMPLIANT", "Grievance contact published in footer and notice."),
            ],
        }
        for name, rows in demos.items():
            slug = init_client(name, [])
            save_json(client_dir(slug) / "questionnaire.json", {"assertions": [
                {"controlId": cid, "status": st, "evidence": ev,
                 "source": {"department": "Demo", "respondent": "seed data", "date": "2026-08-08"}}
                for cid, st, ev in rows]})
            snap = run_scan(slug, skip_web=True)
            generate(slug, snap)
            print(f"seeded {name} -> local/{slug}/")

    elif args.cmd == "retention":
        cutoff = datetime.now(timezone.utc) - timedelta(days=30 * args.months)
        victims = [s for s in list_snapshots(args.client)
                   if datetime.strptime(s.stem, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc) < cutoff]
        if not victims:
            print(f"Nothing older than {args.months} months.")
        for v in victims:
            if args.apply:
                v.unlink()
                print("deleted", v.name)
            else:
                print("would delete", v.name, "(run with --apply)")
        if args.apply and victims:
            cert = client_dir(args.client) / "reports" / "deletion-certificate.json"
            cert.write_text(json.dumps({
                "deletedAt": datetime.now(timezone.utc).isoformat(),
                "policy": f"snapshots older than {args.months} months",
                "deleted": [v.name for v in victims]}, indent=2), encoding="utf-8")
            print("deletion certificate:", cert)

    elif args.cmd == "controls":
        rb = load_rulebook()
        for c in rb["controls"]:
            if args.category and c["category"] != args.category:
                continue
            print(f"{c['id']:8} [{c['severity']:8}] {c['checkMethod']:13} {c['title']}  ({c['legalRef']})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
