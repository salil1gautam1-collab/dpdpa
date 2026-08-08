# DPDPA Sentinel — Demo Run-book

A 10–15 minute walkthrough that tells the product story end to end. Two roles:
the **client** (submits inputs, reads the report) and the **operator/admin**
(runs the assessment). Show both.

## 0. Before the demo (once)

```bash
docker compose up -d --build          # start the app
docker compose exec dpdpa python -m dpdpa demo --reset   # clean, seeded demo data
```

`demo --reset` removes any leftover `*-demo` / `*-dummy` companies and seeds a
clean set with logins printed to the console:

| Company | Client login | Password |
|---|---|---|
| Northwind Retail (demo) | it@northwind.demo | demo-client-2026 |
| Acme Exports Pvt Ltd (demo) | compliance@acme.demo | demo-client-2026 |

Admin: **http://127.0.0.1:8377/admin** — password `dpdpa-admin`.

Northwind is pre-loaded with directory (AD/GPO) and firewall inputs so the
infrastructure story is visible without live credentials. Acme is a cleaner,
mostly-compliant contrast.

> Leave **TradeIndia** in the list as the real-website example — it has live
> public sites the scanner actually reads. (Do not expose its confidential
> source documents; only the app's own findings.)

## 1. The pitch (landing page) — 1 min

Open **http://127.0.0.1:8377/**. Walk the top of the landing page:
- The law is in force; enforcement tightens Nov 2026; ₹250 cr penalties.
- "We scan your digital + cloud + endpoint footprint, map it to every DPDPA
  checkpoint, and show what's compliant, what's a gap, with evidence."
- Point at the six capability tiles and the "how it works" steps.

## 2. The client experience — 3 min

Click **Company sign-in**, log in as **it@northwind.demo / demo-client-2026**.
Show that the client sees a calm, guided workspace:
- **Three input tiles**: questionnaire, infrastructure/cloud access (with
  consent), consent. No run buttons, no operational controls.
- Open **Fill questionnaire** briefly — dropdowns per checkpoint, evidence box.
- Open **Provide access & consent** — show the six connector cards (AWS, Azure,
  Intune, GCP, AD/GPO, firewall), each read-only and consent-gated. Emphasise:
  *the client can create read-only credentials; we never change anything.*
- Back on the workspace, press **Submit my inputs** — explain it files their
  inputs with the engagement team and does **not** run anything themselves.

## 3. The operator experience — 3 min

Sign out, go to **/admin**, sign in. Show the **operations dashboard**:
- Northwind now shows **"🔔 Client submitted — ready to assess."**
- Open Northwind → the admin view has the full controls and the pending banner.
- Click **Run full assessment** (or questionnaire-only). Watch it run and the
  score appear. Explain: *running the assessment is the billable step — the
  client can't self-serve it.*

## 4. The deliverable — 3 min

On Northwind's workspace, open the **📕 Client Report (PDF)** tile:
- Cover page with the compliance-score donut.
- Executive summary + priority focus areas.
- Detailed findings, gaps-first, each with **evidence** and a recommendation,
  and "we can assist (with your consent)".
- The condensed "awaiting further input" table for not-yet-connected systems.
- Click **Save as PDF** — this is the hand-over artefact.

Then open **Phase 1 (Discovery)** and **Phase 2 (Gap Assessment)** to show the
depth behind the client report, and mention `summary.json` for GRC tooling.

## 5. The real-website proof — 2 min

Open **TradeIndia** (admin) and **Run full assessment**. Show that the scanner
actually reads the live sites — e.g. one property runs a consent platform while
the other runs Google Analytics with **no** cookie consent — a real, evidence-
backed finding produced automatically.

## 6. Close

- Rulebook is versioned (currently v4) — when MeitY updates the Rules, we ship a
  new rulebook and re-assess; nothing changes silently.
- Six live connectors, evidence on every checkpoint, deployable as an in-house
  Docker container or ported to .NET.
- Disclaimer: we identify gaps and provide evidence; remediation runs only with
  the client's consent, access and permission.

## Reset between demos

```bash
docker compose exec dpdpa python -m dpdpa demo --reset
```

## Talking points / FAQ

- **"Where's the data stored?"** Plain JSON under `./local` on your host, one
  folder per company. No database server. Credentials live in a gitignored
  `connectors.json`; production moves them to a secrets vault.
- **"Can clients run scans themselves?"** No — by design. They submit inputs;
  your team runs the assessment.
- **"Is the cloud scanning safe?"** Read-only, consent-gated, least-privilege
  credentials the client creates and can revoke. We never modify resources.
- **"What about Azure/GCP/on-prem?"** All six connectors are live: AWS, Azure,
  Microsoft Intune/Defender (endpoints & AV), GCP, Active Directory/GPO, and
  firewall config. GCP currently uses a pasted read-only token; production adds
  service-account keys.
