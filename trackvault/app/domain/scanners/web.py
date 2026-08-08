"""Website scanner — passive, polite reads of a client's public pages.

Emits findings keyed by webCheckId (see rulebook controls). Finding statuses:
  ok       automated signal satisfied
  partial  some elements satisfied
  gap      signal shows the checkpoint is not met
  na       not applicable (e.g. no forms found)
  unknown  cannot be determined from outside -> engine resolves to TBC

Politeness: <=1 request/second, page cap, honest User-Agent, 20s timeout,
GET only, no form submission, no credentialed requests.
"""
from __future__ import annotations

import gzip
import re
import socket
import ssl
import time
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlparse

from ..evidence import make_evidence

USER_AGENT = "DPDPA-Sentinel/0.1 (authorized compliance scan; contact=operator)"
PAGE_CAP = 10
DELAY_S = 1.0
TIMEOUT_S = 20
MAX_BODY = 600_000

TRACKER_SIGNATURES = [
    ("Google Tag Manager", r"googletagmanager\.com"),
    ("Google Analytics / gtag", r"google-analytics\.com|gtag/js|\b_gaq\b|\bga\('create'"),
    ("Meta Pixel", r"connect\.facebook\.net|\bfbq\("),
    ("Microsoft Clarity", r"clarity\.ms"),
    ("Hotjar", r"hotjar\.com"),
    ("DoubleClick / Google Ads", r"doubleclick\.net|googleadservices|googlesyndication"),
    ("LinkedIn Insight", r"snap\.licdn\.com"),
    ("Twitter/X Pixel", r"static\.ads-twitter\.com"),
    ("TikTok Pixel", r"analytics\.tiktok\.com"),
    ("Firebase", r"firebaseio\.com|firebase-analytics"),
]

CMP_SIGNATURES = [
    ("OneTrust", r"onetrust|optanon"),
    ("Cookiebot", r"cookiebot"),
    ("CookieYes", r"cookieyes"),
    ("Osano", r"osano"),
    ("Termly", r"termly\.io"),
    ("iubenda", r"iubenda"),
    ("Usercentrics", r"usercentrics"),
    ("Didomi", r"didomi"),
    ("TrustArc", r"trustarc|truste"),
    ("Quantcast", r"quantcast"),
    ("Complianz", r"complianz"),
    ("Generic cookie banner", r"cookie[-_ ]?(consent|banner|notice|popup|bar)"),
]

PRIVACY_TOPICS = {
    "consent": r"\bconsent\b",
    "withdrawal": r"withdraw",
    "erasure/deletion": r"\berasure\b|\bdelete\b|\bdeletion\b",
    "grievance": r"grievance",
    "dpdp/board reference": r"digital personal data protection|dpdp|data protection board",
    "retention": r"retention|retain",
    "children": r"\bchild\b|\bchildren\b|\bminor\b",
    "rights of data principal": r"\bright(s)?\b",
}


class Page:
    def __init__(self, url, status=None, headers=None, body=b"", final_url=None, error=None, redirects=None):
        self.url = url
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.final_url = final_url or url
        self.error = error
        self.redirects = redirects or []

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8", errors="replace")
        except Exception:
            return ""


class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str) -> Page:
    recorder = _RedirectRecorder()
    opener = urllib.request.build_opener(recorder)
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Encoding": "gzip",
        "Accept-Language": "en-IN,en;q=0.9",
    })
    try:
        with opener.open(req, timeout=TIMEOUT_S) as resp:
            body = resp.read(MAX_BODY)
            if resp.headers.get("Content-Encoding", "") == "gzip":
                try:
                    body = gzip.decompress(body)
                except Exception:
                    pass
            # collect ALL Set-Cookie headers, not just the last
            cookies = resp.headers.get_all("Set-Cookie") or []
            headers = dict(resp.headers)
            if cookies:
                headers["Set-Cookie"] = " || ".join(cookies)
            return Page(url, resp.status, headers, body, resp.geturl(), redirects=recorder.chain)
    except urllib.error.HTTPError as e:
        return Page(url, e.code, dict(e.headers or {}), b"", error=f"HTTP {e.code}", redirects=recorder.chain)
    except Exception as e:
        return Page(url, error=f"{type(e).__name__}: {e}", redirects=recorder.chain)


def tls_probe(host: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tsock:
                cert = tsock.getpeercert()
                return {"ok": True, "protocol": tsock.version(), "cipher": tsock.cipher()[0],
                        "certExpires": cert.get("notAfter", "")}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _find_links(base_url: str, html: str) -> list[tuple[str, str]]:
    """Return (absolute_url, link_text) pairs for same-host links."""
    out = []
    host = urlparse(base_url).netloc.lower().removeprefix("www.")
    for m in re.finditer(r'<a[^>]+href=["\']([^"\'#]+)["\'][^>]*>(.*?)</a>', html, re.I | re.S):
        href, text = m.group(1).strip(), re.sub(r"<[^>]+>", " ", m.group(2))[:120].strip()
        if href.startswith(("mailto:", "tel:", "javascript:")):
            out.append((href, text))
            continue
        absu = urljoin(base_url, href)
        if urlparse(absu).netloc.lower().removeprefix("www.") == host:
            out.append((absu, text))
    return out


def _pick(links, *patterns):
    for pat in patterns:
        for url, text in links:
            if re.search(pat, url, re.I) or re.search(pat, text, re.I):
                return url
    return None


def scan_site(site: str, findings: list, meta: dict) -> None:
    """Scan one site; append finding dicts to `findings`, page inventory to meta."""
    parsed = urlparse(site if "//" in site else "https://" + site)
    host = parsed.netloc or parsed.path
    base = f"https://{host}"

    # --- transport checks -------------------------------------------------
    http_page = fetch(f"http://{host}/")
    time.sleep(DELAY_S)
    home = fetch(base + "/")
    time.sleep(DELAY_S)

    https_landed = (http_page.final_url or "").startswith("https://") or any(
        u.startswith("https://") for u in http_page.redirects)
    findings.append({
        "webCheckId": "https_redirect", "site": host,
        "status": "ok" if https_landed else ("unknown" if http_page.error and not http_page.redirects else "gap"),
        "evidence": [make_evidence("redirect-chain", f"http://{host}/",
                                   excerpt=" -> ".join(http_page.redirects) or (http_page.error or "no redirect"),
                                   note=f"final: {http_page.final_url}")],
    })

    tls = tls_probe(host)
    findings.append({
        "webCheckId": "tls_quality", "site": host,
        "status": "ok" if tls.get("ok") and tls.get("protocol") in ("TLSv1.2", "TLSv1.3") else
                  ("gap" if tls.get("ok") else "unknown"),
        "evidence": [make_evidence("tls-probe", base, excerpt=str(tls))],
    })

    if home.error and not home.body:
        findings.append({"webCheckId": "site_unreachable", "site": host, "status": "unknown",
                         "evidence": [make_evidence("fetch-error", base + "/", excerpt=home.error)]})
        return

    hdr = {k.lower(): v for k, v in home.headers.items()}
    findings.append({
        "webCheckId": "hsts", "site": host,
        "status": "ok" if "strict-transport-security" in hdr else "gap",
        "evidence": [make_evidence("http-headers", home.final_url, headers=home.headers, raw=home.body)],
    })

    sec_present = [h for h in ("x-content-type-options", "x-frame-options",
                               "referrer-policy", "content-security-policy") if h in hdr]
    findings.append({
        "webCheckId": "security_headers", "site": host,
        "status": "ok" if len(sec_present) == 4 else ("partial" if sec_present else "gap"),
        "evidence": [make_evidence("http-headers", home.final_url, headers=home.headers,
                                   note=f"present: {sec_present or 'none'}")],
    })

    server_hdr = (hdr.get("server", "") + " " + hdr.get("x-powered-by", "")).strip()
    findings.append({
        "webCheckId": "server_disclosure", "site": host,
        "status": "gap" if re.search(r"\d", server_hdr) else "ok",
        "evidence": [make_evidence("http-headers", home.final_url,
                                   excerpt=f"Server/X-Powered-By: {server_hdr or '(absent)'}")],
    })

    # --- cookies on first uncooked request --------------------------------
    set_cookies = home.headers.get("Set-Cookie", "")
    cookie_names = re.findall(r"(?:^|\|\| )\s*([^=;,\s]+)=", set_cookies)
    insecure = [c for c in set_cookies.split(" || ") if c and "secure" not in c.lower()]
    findings.append({
        "webCheckId": "cookie_flags", "site": host,
        "status": "na" if not set_cookies else ("ok" if not insecure else "partial"),
        "evidence": [make_evidence("set-cookie", home.final_url,
                                   excerpt=set_cookies[:800] or "(no cookies set)",
                                   note=f"cookies without Secure flag: {len(insecure)}")],
    })

    # --- discover key pages ------------------------------------------------
    home_html = home.text
    links = _find_links(home.final_url, home_html)
    privacy_url = _pick(links, r"privacy")
    terms_url = _pick(links, r"terms|conditions")
    contact_url = _pick(links, r"grievance|contact|support|help")

    pages = {"home": home}
    budget = PAGE_CAP - 2
    for key, url in (("privacy", privacy_url), ("terms", terms_url), ("contact", contact_url)):
        if url and not url.startswith(("mailto:", "tel:")) and budget > 0:
            pages[key] = fetch(url)
            budget -= 1
            time.sleep(DELAY_S)

    meta.setdefault("pagesScanned", []).extend(
        {"site": host, "page": k, "url": p.final_url, "status": p.status, "error": p.error}
        for k, p in pages.items())

    all_html = " ".join(p.text for p in pages.values())

    # --- trackers & CMP ----------------------------------------------------
    trackers = [name for name, pat in TRACKER_SIGNATURES if re.search(pat, home_html, re.I)]
    cmps = [name for name, pat in CMP_SIGNATURES if re.search(pat, home_html, re.I)]
    consent_mode = bool(re.search(r"gtag\(\s*['\"]consent['\"]|consent_mode|('|\")consent('|\")\s*,\s*('|\")default", home_html, re.I))

    findings.append({
        "webCheckId": "cmp_present", "site": host,
        "status": "ok" if cmps else "gap",
        "evidence": [make_evidence("html-signature", home.final_url,
                                   excerpt=f"CMP signatures found: {cmps or 'NONE'}; page hash recorded", raw=home.body)],
    })
    findings.append({
        "webCheckId": "trackers_found", "site": host,
        "status": "partial" if trackers else "ok",
        "evidence": [make_evidence("html-signature", home.final_url,
                                   excerpt=f"Third-party trackers observed: {trackers or 'none'}")],
    })
    findings.append({
        "webCheckId": "pre_consent_cookies", "site": host,
        "status": "gap" if (trackers or cookie_names) and not cmps else ("ok" if cmps else "partial"),
        "evidence": [make_evidence("first-request", home.final_url,
                                   excerpt=f"cookies set pre-consent: {cookie_names or 'none'}; "
                                           f"trackers in page source: {trackers or 'none'}; CMP: {cmps or 'none'}")],
    })
    findings.append({
        "webCheckId": "consent_mode", "site": host,
        "status": "ok" if consent_mode else ("gap" if trackers else "unknown"),
        "evidence": [make_evidence("html-signature", home.final_url,
                                   excerpt=f"Google Consent Mode signals present: {consent_mode}")],
    })
    findings.append({
        "webCheckId": "cookie_inventory", "site": host,
        "status": "unknown",
        "evidence": [make_evidence("observation", home.final_url,
                                   excerpt=f"Cookies observed on first request: {cookie_names or 'none'} — reconcile against documented cookie register")],
    })

    # --- privacy policy ----------------------------------------------------
    ppage = pages.get("privacy")
    if ppage and ppage.status == 200 and ppage.text:
        ptext = re.sub(r"<[^>]+>", " ", ppage.text)
        covered = {t: bool(re.search(pat, ptext, re.I)) for t, pat in PRIVACY_TOPICS.items()}
        ncov = sum(covered.values())
        findings.append({"webCheckId": "privacy_policy_present", "site": host, "status": "ok",
                         "evidence": [make_evidence("page", ppage.final_url, raw=ppage.body,
                                                    note="privacy policy found and fetched")]})
        findings.append({
            "webCheckId": "privacy_policy_content", "site": host,
            "status": "ok" if ncov >= 7 else ("partial" if ncov >= 4 else "gap"),
            "evidence": [make_evidence("content-analysis", ppage.final_url,
                                       excerpt="topic coverage: " + ", ".join(
                                           f"{t}={'Y' if v else 'N'}" for t, v in covered.items()))],
        })
        withdrawal = bool(re.search(r"withdraw", ptext, re.I))
        findings.append({
            "webCheckId": "withdrawal_mechanism", "site": host,
            "status": "partial" if withdrawal else "gap",
            "evidence": [make_evidence("content-analysis", ppage.final_url,
                                       excerpt=f"withdrawal mentioned in policy: {withdrawal} — self-serve mechanism needs manual verification")],
        })
        langs = bool(re.search(r"hreflang|हिन्दी|हिंदी|தமிழ்|తెలుగు|বাংলা|language selector", ppage.text, re.I))
        findings.append({
            "webCheckId": "notice_languages", "site": host,
            "status": "partial" if langs else "gap",
            "evidence": [make_evidence("content-analysis", ppage.final_url,
                                       excerpt=f"multi-language signals on notice: {langs}")],
        })
    else:
        note = "no privacy link found on homepage" if not privacy_url else \
               f"privacy link found ({privacy_url}) but fetch failed: {getattr(ppage, 'error', None) or getattr(ppage, 'status', '?')}"
        findings.append({"webCheckId": "privacy_policy_present", "site": host,
                         "status": "gap" if not privacy_url else "unknown",
                         "evidence": [make_evidence("absence", home.final_url, excerpt=note)]})
        for cid in ("privacy_policy_content", "withdrawal_mechanism", "notice_languages"):
            findings.append({"webCheckId": cid, "site": host, "status": "unknown",
                             "evidence": [make_evidence("absence", home.final_url, excerpt=note)]})

    findings.append({
        "webCheckId": "terms_present", "site": host,
        "status": "ok" if terms_url else "gap",
        "evidence": [make_evidence("link-discovery", home.final_url,
                                   excerpt=f"terms link: {terms_url or 'not found'}")],
    })

    # --- grievance / DSR discovery -----------------------------------------
    grievance_hit = re.search(r"grievance|nodal officer|data protection officer|\bdpo\b", all_html, re.I)
    dsr_hit = re.search(r"(access|correct|delete|erase).{0,60}(personal data|your data|my data)|data principal", all_html, re.I)
    findings.append({
        "webCheckId": "grievance_contact", "site": host,
        "status": "partial" if grievance_hit else "gap",
        "evidence": [make_evidence("content-analysis", home.final_url,
                                   excerpt=f"grievance/DPO reference found: {bool(grievance_hit)}"
                                           + (f" (match: '{grievance_hit.group(0)[:60]}')" if grievance_hit else ""))],
    })
    findings.append({
        "webCheckId": "dsr_channel", "site": host,
        "status": "partial" if (grievance_hit and dsr_hit) else ("partial" if dsr_hit else "gap"),
        "evidence": [make_evidence("content-analysis", home.final_url,
                                   excerpt=f"rights-request language found: {bool(dsr_hit)}")],
    })

    # --- forms & consent controls ------------------------------------------
    form_reports, forms_with_pd = [], 0
    with_consent = 0
    for key, p in pages.items():
        for fm in re.finditer(r"<form\b.*?</form>", p.text, re.I | re.S):
            fhtml = fm.group(0)
            inputs = re.findall(r"<(?:input|textarea|select)[^>]*>", fhtml, re.I)
            pd_fields = [i for i in inputs if re.search(
                r'type=["\'](?:email|tel)|name=["\'][^"\']*(name|email|phone|mobile|contact|company)', i, re.I)]
            if not pd_fields:
                continue
            forms_with_pd += 1
            has_checkbox = bool(re.search(r'type=["\']checkbox', fhtml, re.I))
            consent_text = bool(re.search(r"consent|agree|privacy policy|terms", fhtml, re.I))
            ok = has_checkbox and consent_text
            with_consent += ok
            form_reports.append({"page": p.final_url, "personalDataFields": len(pd_fields),
                                 "consentControl": ok})
    if forms_with_pd == 0:
        status = "unknown"  # many sites render forms via JS; absence of <form> is not proof
        note = "no static forms with personal-data fields found (site may render forms via JavaScript — verify with browser-mode scan)"
    elif with_consent == forms_with_pd:
        status, note = "ok", f"all {forms_with_pd} forms have consent controls"
    elif with_consent:
        status, note = "partial", f"{with_consent}/{forms_with_pd} forms have consent controls"
    else:
        status, note = "gap", f"none of {forms_with_pd} personal-data forms shows a consent control"
    findings.append({
        "webCheckId": "forms_consent", "site": host, "status": status,
        "evidence": [make_evidence("form-analysis", home.final_url, excerpt=note + " | " + str(form_reports)[:900])],
    })
    meta.setdefault("formsFound", []).extend(form_reports)
    meta.setdefault("trackersObserved", {})[host] = trackers
    meta.setdefault("cookiesObserved", {})[host] = cookie_names
    meta.setdefault("cmpObserved", {})[host] = cmps


def run(sites: list[str]) -> tuple[list, dict]:
    findings: list = []
    meta: dict = {}
    for site in sites:
        scan_site(site, findings, meta)
    return findings, meta
