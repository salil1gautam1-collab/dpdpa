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

## Quick start

Requires Python 3.10+ (no third-party packages — standard library only).

```bash
# 1. Initialise a client workspace (kept in local/, never committed)
python -m dpdpa init --client "Acme Ltd" --site https://www.acme.example

# 2. Run a scan (website checks + any questionnaire answers present)
python -m dpdpa scan --client acme-ltd

# 3. Generate reports (Phase 1 + Phase 2, HTML + JSON)
python -m dpdpa report --client acme-ltd

# 4. Serve the dashboard locally
python -m dpdpa serve --client acme-ltd

# 5. Compare the two most recent scans and print alerts
python -m dpdpa diff --client acme-ltd
```

Run from the `src/` directory or set `PYTHONPATH=src`.

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
