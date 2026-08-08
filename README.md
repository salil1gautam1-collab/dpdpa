# DPDPA Sentinel

A compliance scanning and gap-assessment engine for India's **Digital Personal Data
Protection Act, 2023 (DPDPA)** and the **DPDP Rules, 2025**.

It scans an organisation's public digital surface (websites, catalogs, apps),
ingests a small set of structured manual inputs (departmental questionnaires),
maps everything against a **versioned rulebook** of DPDPA checkpoints, and produces
evidence-backed reports:

- **Phase 1 — Discovery & Inventory**: what exists — channels, data categories,
  processors, systems, scan surface.
- **Phase 2 — Gap Assessment**: every checkpoint marked **Compliant / Partial /
  Gap / Not Applicable / To Be Confirmed**, each with the *evidence* of how the
  status was determined, remediation guidance, and whether this tool can assist
  in closing the gap (with the client's consent, access and permission).

Re-scans can run on a schedule or on demand; the diff engine raises alerts when
a previously-compliant point regresses or a new gap appears.

> **Disclaimer (ships in every report):** This tool identifies compliance gaps and
> provides evidence and recommendations. It is **not** a substitute for legal
> advice, and it does not by itself make an organisation compliant. Remediation
> assistance runs **only** where the organisation explicitly grants consent,
> access and permissions. Final legal interpretation rests with the
> organisation's own counsel / company secretary.

## Quick start — the app

**Docker (recommended):**

```bash
docker compose up -d
```

Open http://127.0.0.1:8377/ — a public landing page explains the product; the
**Start assessment** flow onboards a company (details + scan consent), then its
workspace offers the questionnaire, the **Run assessment** button, reports and
alerts. The **Admin** link (footer/nav) opens the operations dashboard across
all engagements — default password `dpdpa-admin`, change it via the
`DPDPA_ADMIN_PASSWORD` environment variable (set it in `docker-compose.yml`).
Client data persists in `./local` on the host (volume mount), never in the image.

**Email notifications (optional):** copy `.env.example` to `.env` and fill the
`TRACKVAULT_SMTP_*` values (host, user, password; sender defaults to
`info@dedicatusit.com`). Leave `TRACKVAULT_SMTP_HOST` blank to keep email in
**simulated** mode — notifications are created and logged but nothing is sent.
`.env` is gitignored; never commit credentials. Restart with `docker compose up -d`
after editing.

**Without Docker** (Python 3.10+, no third-party packages):

```bash
cd src
python -m dpdpa demo    # optional: seed two dummy companies
python -m dpdpa serve   # app at http://127.0.0.1:8377/
```

**CLI (same engine, scriptable / schedulable):**

```bash
python -m dpdpa init --client "Acme Ltd" --site https://www.acme.example
python -m dpdpa scan --client acme-ltd        # add --skip-web for questionnaire-only
python -m dpdpa report --client acme-ltd      # Phase 1 + Phase 2, HTML + JSON
python -m dpdpa diff --client acme-ltd        # alerts vs previous scan
python -m dpdpa retention --client acme-ltd   # apply the retention schedule
```

Run CLI commands from the `src/` directory or set `PYTHONPATH=src`.

## Repository layout

| Path | Purpose |
|---|---|
| `rulebook/` | Versioned DPDPA rulebook (`dpdpa-rulebook.v1.json`) — the checkpoint universe |
| `src/dpdpa/` | Engine: scanners, evidence store, status resolver, reports, CLI, dashboard |
| `docs/` | Architecture, .NET implementation guide, data-protection policy, disclaimer |
| `samples/` | Blank questionnaire template (Parts A–M) and example config |
| `local/` | **Gitignored.** Client configs, questionnaire answers, evidence, reports |

## Design principles

1. **Rulebook-driven** — the law lives in versioned JSON, not in code. When the
   government updates the Rules, you publish a new rulebook version; the engine
   re-evaluates and diffs.
2. **Evidence-first** — no status without evidence. Automated findings store the
   URL, matched content, headers and a SHA-256 hash; manual answers store the
   respondent, department and date.
3. **Minimal data, minimal database** — plain JSON files on disk, no server-side
   database. The tool itself avoids ingesting personal data; incidental PII in
   scanned pages is masked before storage (see `evidence.py`).
4. **The tool must itself be DPDPA-clean** — see `docs/DATA-PROTECTION-POLICY.md`
   for what it stores, for how long, and why.
5. **Portable & re-implementable** — standard-library Python, file-based state,
   documented data contracts, so a .NET (or any) team can port it in-house with
   no external dependencies. See `docs/DOTNET-IMPLEMENTATION-GUIDE.md`.

## Packaging as an executable

```bash
pip install pyinstaller
pyinstaller --onefile --name dpdpa --add-data "rulebook;rulebook" src/dpdpa/__main__.py
```

The same codebase serves the web dashboard (`dpdpa serve`), so one build covers
both the executable and web-based requirements.
