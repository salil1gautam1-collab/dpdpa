# .NET Implementation Guide

This prototype is standard-library Python so it runs and proves the design with
zero dependencies. The production system is intended to be re-implemented
in-house (e.g. .NET 8) with **no external/git dependency**. The data contracts
below are the spec; the Python files are the reference implementation.

## Suggested solution layout

```
Dpdpa.sln
  Dpdpa.Core/          // domain: Rulebook, Control, Finding, Evidence, Snapshot
  Dpdpa.Scanners/      // IScanner: WebScanner, QuestionnaireImporter, InfraScanner
  Dpdpa.Engine/        // StatusResolver, DiffEngine, RetentionService
  Dpdpa.Reports/       // Phase1/Phase2 renderers (Razor or string templates)
  Dpdpa.Cli/           // System.CommandLine console app → single-file publish
  Dpdpa.Web/           // ASP.NET Core minimal API + dashboard (same Core libs)
```

`dotnet publish -r win-x64 -p:PublishSingleFile=true --self-contained` gives the
executable; `Dpdpa.Web` gives the web system. One codebase, both form factors.

## Data contracts (source of truth)

All JSON, all documented by the Python reference implementation:

1. **Rulebook** — `rulebook/dpdpa-rulebook.v1.json`. Deserialise to
   `Rulebook { Version, Categories[], Controls[] }`. Never edit v1 in place;
   law changes = new file, and `DiffEngine` must surface controls whose
   definition hash changed as TBC.
2. **Client config** — `local/<slug>/client.json`: name, sites[], applicability
   overrides (`controlId → {status: "NA", reason}`), schedule.
3. **Questionnaire answers** — `local/<slug>/questionnaire.json`:
   `assertions: [{controlId, status, evidence, source: {department, respondent, date}}]`
   plus optional Parts A–M departmental blocks (see samples/).
4. **Scan snapshot** — `local/<slug>/scans/<ISO-timestamp>.json`:
   `{scanId, rulebookVersion, startedAt, findings[], resolutions[]}` where each
   resolution is `{controlId, status, basis, evidence[]}`. Snapshots are
   immutable — never rewrite one.
5. **Alerts** — `local/<slug>/alerts.json`: output of the diff engine.

## Porting notes per component

| Python file | .NET target | Notes |
|---|---|---|
| `scanners/web.py` | `WebScanner` (HttpClient) | Keep politeness: ≤1 req/s, page cap, honest UA, timeout 20s. Use HtmlAgilityPack or keep regex-based extraction (reference impl is regex — deliberately parser-free). Add a headless-browser (Playwright) mode later for JS-rendered consent banners; keep the HTTP mode as fallback. |
| `scanners/questionnaire.py` | `QuestionnaireImporter` | Pure mapping; validate against rulebook control ids. |
| `evidence.py` | `Evidence` + `PiiMasker` | Port the regexes exactly (emails, +91/10-digit mobiles, GSTIN, PAN). SHA-256 via IncrementalHash. |
| `engine.py` | `StatusResolver` | The hybrid rule is the important one: automated GAP always wins; automated OK yields PARTIAL until human confirmation. |
| `report.py` | Razor templates | Keep report JSON export byte-compatible if possible; HTML free to improve. |
| `diffalert.py` | `DiffEngine` | Also drives e-mail/webhook alerting (add `IAlertChannel`). |
| `server.py` | ASP.NET Core | Replace entirely; add authN/authZ (the prototype has none). |

## Production hardening checklist (beyond prototype)

- AuthN/AuthZ + tenant isolation; encrypt `local/` equivalent at rest (per-tenant key).
- Job scheduler (Quartz.NET / Hosted Services) for recurring scans instead of OS scheduler.
- SMTP/webhook alert channels with retry.
- Infra scanner: AWS SDK read-only checks (S3 public-access block, RDS/EBS
  encryption flags, CloudTrail on, IAM access-key age) — read-only credentials
  supplied by the client, per the consent model.
- App scanner: static manifest checks for Android/iOS packages (permissions,
  SDK inventory) — client uploads the APK/IPA.
- Evidence attachments (screenshots, PDFs) with hash + timestamp.
- Rulebook signing (detached signature) so clients can verify authenticity.
- Localisation of reports (English + Indian languages) mirroring NT-04.
