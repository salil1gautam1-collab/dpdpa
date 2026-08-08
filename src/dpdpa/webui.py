"""HTML/CSS for the public-facing web app: landing page, onboarding, company
workspace, questionnaire and admin screens. Pure string templates — stdlib only."""
from __future__ import annotations

import html

from . import PRODUCT_NAME, __version__

CSS = """
:root{--navy:#0d2137;--navy2:#14324f;--ink:#1c2733;--mut:#5b7186;--line:#dde5ed;
--bg:#f4f7fa;--card:#fff;--acc:#0d6efd;--ok:#1a7f37;--warn:#b58900;--bad:#c62828;
--na:#607d8b;--tbc:#5c6bc0;--r:12px}
*{box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;margin:0;background:var(--bg);color:var(--ink);line-height:1.55}
a{color:var(--acc)} h1,h2,h3{line-height:1.25}
.wrap{max-width:1080px;margin:0 auto;padding:0 22px}
nav{background:var(--navy);color:#fff;position:sticky;top:0;z-index:5}
nav .wrap{display:flex;align-items:center;justify-content:space-between;height:58px}
nav a{color:#e8eef5;text-decoration:none;margin-left:22px;font-size:14px}
nav .brand{font-size:17px;font-weight:700;margin:0;letter-spacing:.2px}
nav .brand a{margin:0}
.hero{background:linear-gradient(135deg,var(--navy) 0%,#123a63 60%,#0e5a8a 100%);color:#fff;padding:72px 0 84px}
.hero h1{font-size:40px;margin:0 0 14px;max-width:720px}
.hero p{font-size:19px;color:#c9d8e8;max-width:640px;margin:0 0 30px}
.btn{display:inline-block;background:var(--acc);color:#fff!important;border:none;border-radius:8px;
padding:12px 26px;font-size:15px;font-weight:600;cursor:pointer;text-decoration:none!important}
.btn.big{padding:15px 34px;font-size:17px}
.btn.ghost{background:transparent;border:2px solid #7fa8cc}
.btn.green{background:var(--ok)}.btn.gray{background:var(--na)}.btn.sm{padding:8px 16px;font-size:13px}
.btn:disabled{background:#9db2c5;cursor:not-allowed}
section{padding:56px 0}
section.alt{background:#fff}
h2.sec{font-size:28px;margin:0 0 8px;text-align:center}
p.sub{color:var(--mut);text-align:center;max-width:640px;margin:0 auto 36px}
.grid{display:grid;gap:20px}
.grid.c3{grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.grid.c4{grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
.tile{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:22px}
.tile h3{margin:6px 0 8px;font-size:17px}
.tile p{margin:0;font-size:14px;color:var(--mut)}
.tile .ico{font-size:26px}
.step{position:relative;padding-left:0}
.step .num{width:34px;height:34px;border-radius:50%;background:var(--navy);color:#fff;display:flex;
align-items:center;justify-content:center;font-weight:700;margin-bottom:10px}
.notice{background:#fff8e6;border:1px solid #e6d9a8;border-radius:var(--r);padding:16px 20px;font-size:13.5px;color:#5c4d1e}
footer{background:var(--navy);color:#9fb3c8;padding:28px 0;font-size:13px;margin-top:40px}
footer a{color:#c9d8e8}
/* forms */
label{display:block;font-size:13.5px;font-weight:600;margin:14px 0 5px}
input[type=text],input[type=url],input[type=password],textarea,select{width:100%;padding:10px 12px;
border:1px solid #b9c6d2;border-radius:8px;font-size:14px;font-family:inherit;background:#fff}
.hint{font-size:12.5px;color:var(--mut);margin-top:4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:26px 30px;margin:18px 0}
.msg{background:#e7f1ff;border:1px solid #9ec5fe;border-radius:8px;padding:11px 15px;margin:14px 0;font-size:14px}
.msg.err{background:#fdecea;border-color:#f5c6cb}
.consent-box{background:#f0f6ff;border:1.5px solid #b9d4fb;border-radius:var(--r);padding:16px 20px;margin:16px 0;font-size:14px}
/* workspace */
.ws-head{background:linear-gradient(135deg,var(--navy),#123a63);color:#fff;padding:34px 0}
.ws-head h1{margin:0 0 4px;font-size:26px}
.ws-head .small{color:#9fb3c8}
.donut{--p:0;width:118px;height:118px;border-radius:50%;flex:none;
background:conic-gradient(var(--dc) calc(var(--p)*1%),rgba(255,255,255,.15) 0);
display:flex;align-items:center;justify-content:center}
.donut>div{width:88px;height:88px;border-radius:50%;background:var(--navy2);display:flex;flex-direction:column;
align-items:center;justify-content:center;font-size:24px;font-weight:700}
.donut small{font-size:10.5px;font-weight:400;color:#9fb3c8}
.flexh{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
.chips{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
.chip{background:rgba(255,255,255,.12);border-radius:20px;padding:5px 14px;font-size:13px}
.chip b{margin-right:4px}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-size:12px;font-weight:600}
table{border-collapse:collapse;width:100%;background:#fff;font-size:14px;border-radius:var(--r);overflow:hidden}
th,td{border:1px solid var(--line);padding:9px 12px;text-align:left;vertical-align:top}
th{background:#eef2f6;font-size:13px}
.small{font-size:12.5px;color:var(--mut)}
.cat{background:var(--navy);color:#fff;padding:7px 12px;font-size:13px}
.spin{display:inline-block;width:15px;height:15px;border:3px solid #cfe0f4;border-top-color:var(--acc);
border-radius:50%;animation:s 1s linear infinite;vertical-align:middle}
@keyframes s{to{transform:rotate(360deg)}}
.steps-bar{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}
.steps-bar span{background:#fff;border:1px solid var(--line);border-radius:20px;padding:6px 15px;font-size:13px;color:var(--mut)}
.steps-bar span.done{border-color:var(--ok);color:var(--ok);font-weight:600}
.steps-bar span.now{border-color:var(--acc);color:var(--acc);font-weight:600}
@media(max-width:640px){.hero h1{font-size:30px}}
"""

STATUS_COLORS = {"COMPLIANT": "var(--ok)", "PARTIAL": "var(--warn)", "GAP": "var(--bad)",
                 "NA": "var(--na)", "TBC": "var(--tbc)"}


def e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def badge(status: str) -> str:
    return f'<span class="badge" style="background:{STATUS_COLORS.get(status, "var(--na)")}">{e(status)}</span>'


def layout(title: str, body: str, refresh: int | None = None, admin: bool = False) -> bytes:
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    admin_link = '<a href="/admin">Admin</a>' if not admin else '<a href="/admin">Dashboard</a>'
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">{meta}
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} — {PRODUCT_NAME}</title><style>{CSS}</style></head><body>
<nav><div class="wrap"><span class="brand"><a href="/">🛡 {PRODUCT_NAME}</a></span>
<span><a href="/#how">How it works</a><a href="/start">Start assessment</a><a href="/login">Company sign-in</a>{admin_link}</span></div></nav>
{body}
<footer><div class="wrap">© 2026 {PRODUCT_NAME} v{__version__} · Compliance intelligence for the Digital Personal
Data Protection Act, 2023 &amp; DPDP Rules, 2025 · This tool identifies gaps and records evidence;
it is not legal advice. Remediation assistance runs only with your written consent, access and permission.
· <a href="/admin">Admin</a></div></footer></body></html>""".encode("utf-8")


def landing() -> bytes:
    body = f"""
<div class="hero"><div class="wrap">
<h1>Is your organisation ready for India's data protection law?</h1>
<p>The DPDP Rules are in force. Soft enforcement ends November 2026, penalties reach
₹250 crore per breach — and most organisations don't know where their gaps are.
{PRODUCT_NAME} scans your digital footprint, maps it against every DPDPA checkpoint,
and shows you exactly what's compliant, what's not, and the evidence for both.</p>
<a class="btn big" href="/start">Start your assessment →</a>
&nbsp; <a class="btn big ghost" href="/#how">See how it works</a>
</div></div>

<section><div class="wrap">
<h2 class="sec">What {PRODUCT_NAME} does</h2>
<p class="sub">A rulebook-driven compliance engine — the law encoded as 57 verifiable checkpoints
across notice, consent, cookies, children's data, data principal rights, security, breach readiness,
retention, processors, cross-border transfers and governance.</p>
<div class="grid c3">
<div class="tile"><div class="ico">🔍</div><h3>Automated scanning</h3><p>We read your public websites,
catalogs and apps the way a regulator would: consent banners, trackers firing before consent,
privacy notice coverage, grievance channels, form-level consent, transport security.</p></div>
<div class="tile"><div class="ico">📋</div><h3>Minimal manual input</h3><p>What can't be seen from outside,
your teams declare through a short structured questionnaire — pre-mapped to the checkpoints,
never a 400-question ordeal.</p></div>
<div class="tile"><div class="ico">🧾</div><h3>Evidence for everything</h3><p>Every checkpoint —
compliant, gap or not-applicable — carries evidence: what was observed, where, when, with a
tamper-evident hash. Ready for your board, auditor or the Data Protection Board.</p></div>
<div class="tile"><div class="ico">📊</div><h3>Two-phase reporting</h3><p>Phase 1 inventories your data
footprint — channels, cookies, third parties, forms. Phase 2 grades all 57 checkpoints with
severity, recommendations and a compliance score.</p></div>
<div class="tile"><div class="ico">🔁</div><h3>Continuous watch</h3><p>Re-scan on schedule or on demand.
The moment a compliant point regresses or a new tracker appears, you get an alert — compliance
as a living state, not a one-time certificate.</p></div>
<div class="tile"><div class="ico">⚖️</div><h3>Evolves with the law</h3><p>The rulebook is versioned.
When MeitY notifies changes, checkpoints update and anything newly required is flagged for review —
nothing silently changes.</p></div>
</div></div></section>

<section class="alt" id="how"><div class="wrap">
<h2 class="sec">How it works</h2>
<p class="sub">From zero to a board-ready gap assessment in under an hour.</p>
<div class="grid c4">
<div class="tile step"><div class="num">1</div><h3>Tell us about your company</h3>
<p>Name, websites, and who you are. Two minutes.</p></div>
<div class="tile step"><div class="num">2</div><h3>Authorise the scan</h3>
<p>We scan only with your written consent — passive reads of public pages, nothing intrusive,
no data extracted.</p></div>
<div class="tile step"><div class="num">3</div><h3>Scan &amp; declare</h3>
<p>One click runs the automated scan; your teams answer the short questionnaire for
internal controls.</p></div>
<div class="tile step"><div class="num">4</div><h3>Get the reports</h3>
<p>Compliance score, gap list with evidence, recommendations — and what we can help fix,
with your permission.</p></div>
</div>
<p style="text-align:center;margin-top:34px"><a class="btn big" href="/start">Start your assessment →</a></p>
</div></section>

<section><div class="wrap">
<h2 class="sec">Why now</h2>
<div class="grid c3">
<div class="tile"><h3>14 Nov 2025</h3><p>DPDP Rules notified — the law became operational.</p></div>
<div class="tile"><h3>Nov 2026</h3><p>Soft-enforcement window closes; the Data Protection Board moves
to active supervision.</p></div>
<div class="tile"><h3>13 May 2027</h3><p>Final compliance deadline. Penalties up to ₹250 crore
per category of breach.</p></div>
</div>
<div class="notice" style="margin-top:26px"><b>Our commitment on your data:</b> assessment data stays in
your engagement workspace. Evidence excerpts are automatically masked for personal data before storage.
We identify gaps — we act on your systems only where you explicitly grant consent, access and permission.</div>
</div></section>"""
    return layout("DPDPA compliance, measured", body)


def start_form(msg: str = "") -> bytes:
    body = f"""
<section><div class="wrap" style="max-width:760px">
<h2 class="sec">Start your assessment</h2>
<p class="sub">Step 1 of 2 — about your company. You'll authorise the scan next.</p>
{f'<div class="msg err">{e(msg)}</div>' if msg else ''}
<div class="card"><form method="post" action="/start">
<label>Company name *</label>
<input type="text" name="name" required placeholder="e.g. Acme Exports Private Limited">
<label>Websites &amp; online catalogs (comma-separated)</label>
<input type="text" name="sites" placeholder="https://www.acme.example, https://catalog.acme.example">
<div class="hint">Leave empty for a questionnaire-only assessment (no site scanning).</div>
<label>Your name &amp; designation *</label>
<input type="text" name="contact" required placeholder="e.g. R. Sharma, Chief Technology Officer">
<label>Work email (your sign-in ID) *</label>
<input type="text" name="email" required placeholder="e.g. compliance@acme.example">
<label>Choose a password * <span class="hint" style="display:inline;font-weight:400">(minimum 10 characters)</span></label>
<input type="password" name="password" required minlength="10">
<div class="hint">You'll use this email and password to sign back in to your workspace anytime.
Passwords are stored only as salted PBKDF2 hashes.</div>
<div class="consent-box">
<label style="margin:0;font-weight:600"><input type="checkbox" name="consent" value="1" style="width:auto;margin-right:8px">
I authorise {PRODUCT_NAME} to run passive, read-only scans of the public websites listed above.</label>
<div class="hint" style="margin-top:8px">Scans are polite reads of publicly accessible pages — no credentials,
no form submissions, no vulnerability probing. You can also skip this now and record consent later;
web scanning stays disabled until you do. Questionnaire-only assessment needs no scan consent.</div>
</div>
<button class="btn big green" type="submit">Create my assessment workspace →</button>
</form></div>
<p class="small">By continuing you accept that {PRODUCT_NAME} identifies gaps and records evidence;
it is not legal advice, and remediation runs only with your explicit consent, access and permissions.</p>
</div></section>"""
    return layout("Start your assessment", body)


def company_login(msg: str = "") -> bytes:
    body = f"""
<section><div class="wrap" style="max-width:440px">
<h2 class="sec">Company sign-in</h2>
<p class="sub">Access your assessment workspace.</p>
{f'<div class="msg err">{e(msg)}</div>' if msg else ''}
<div class="card"><form method="post" action="/login">
<label>Work email</label><input type="text" name="email" required autofocus>
<label>Password</label><input type="password" name="password" required>
<p><button class="btn" type="submit">Sign in</button></p>
<div class="hint">New here? <a href="/start">Start your assessment</a> — it creates your login.
Forgotten password? Contact your engagement manager to reset it.</div>
</form></div></div></section>"""
    return layout("Company sign-in", body)


def admin_login(msg: str = "") -> bytes:
    body = f"""
<section><div class="wrap" style="max-width:420px">
<h2 class="sec">Admin sign-in</h2>
{f'<div class="msg err">{e(msg)}</div>' if msg else ''}
<div class="card"><form method="post" action="/admin/login">
<label>Password</label><input type="password" name="password" required autofocus>
<p><button class="btn" type="submit">Sign in</button></p>
<div class="hint">Default password is <code>dpdpa-admin</code> — change it by setting the
<code>DPDPA_ADMIN_PASSWORD</code> environment variable (see README).</div>
</form></div></div></section>"""
    return layout("Admin", body)
