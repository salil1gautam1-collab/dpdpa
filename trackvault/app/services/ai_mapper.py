"""AI-assisted mapping: read an arbitrary client document and PROPOSE which DPDPA
checkpoints it addresses, with a status and the source sentence.

Privacy by design: the default provider is a **self-hosted** model (Ollama) — the
document never leaves your environment, and there are no per-token API costs.
The provider is behind a thin adapter, so a different backend can be swapped in
via config without touching the rest of the app.

Nothing here writes to the questionnaire. It only produces *suggestions* that an
operator reviews and confirms — the human is always the final decision.
"""
from __future__ import annotations

import json
import re
import urllib.request

from ..config import get_settings

VALID_STATUS = {"COMPLIANT", "PARTIAL", "GAP", "NA", "TBC"}


def provider_available() -> tuple[bool, str]:
    s = get_settings()
    if s.ai_provider == "none":
        return False, "AI-assisted import is disabled (TRACKVAULT_AI_PROVIDER=none)."
    if s.ai_provider == "ollama":
        try:
            req = urllib.request.Request(s.ai_base_url.rstrip("/") + "/api/tags")
            with urllib.request.urlopen(req, timeout=5) as r:
                tags = json.loads(r.read().decode("utf-8"))
            models = [m.get("name", "") for m in tags.get("models", [])]
            if not any(s.ai_model.split(":")[0] in m for m in models):
                return False, (f"Self-hosted model '{s.ai_model}' is not pulled yet. "
                               f"Run:  docker compose exec ollama ollama pull {s.ai_model}")
            return True, f"Self-hosted model {s.ai_model} ready (no data leaves your environment)."
        except Exception as ex:
            return False, (f"Self-hosted AI service not reachable at {s.ai_base_url} "
                           f"({type(ex).__name__}). Start the 'ollama' service.")
    return False, f"Unknown AI provider '{s.ai_provider}'."


# ---- Retrieval helpers: shrink the model's job from "86 controls" to "~8 candidates" ----

_STOP = {"the", "and", "for", "with", "that", "this", "are", "not", "our", "your", "you",
         "from", "have", "has", "was", "were", "will", "any", "all", "data", "personal",
         "such", "which", "must", "should", "when", "where", "into", "per", "via", "used",
         "use", "using", "under", "over", "been", "being", "does", "may", "can", "shall"}


def _tokens(text: str) -> set:
    return {w for w in re.findall(r"[a-z]{3,}", (text or "").lower()) if w not in _STOP}


def _control_keywords(controls: list[dict], cats: dict) -> dict:
    """Per-control keyword set from its title + category name, for cheap keyword retrieval."""
    kw = {}
    for c in controls:
        kw[c["id"]] = _tokens(c["title"]) | _tokens(cats.get(c["category"], ""))
    return kw


def _chunks(text: str, size: int = 1600) -> list[str]:
    """Split the document into passages on blank lines / row boundaries, then pack up to
    ~size chars each so each model call sees a small, coherent slice."""
    paras = [p.strip() for p in re.split(r"\n\s*\n|\r\n\r\n", text) if p.strip()]
    if len(paras) <= 1:
        paras = [p.strip() for p in text.splitlines() if p.strip()]
    out, buf = [], ""
    for p in paras:
        if len(buf) + len(p) + 1 > size and buf:
            out.append(buf)
            buf = p
        else:
            buf = f"{buf}\n{p}" if buf else p
    if buf:
        out.append(buf)
    return out


def _shortlist(chunk: str, kw: dict, controls_by_id: dict, top: int = 8) -> list[dict]:
    """Return the controls whose keywords overlap this passage most — the candidates
    we'll actually ask the model about."""
    toks = _tokens(chunk)
    scored = []
    for cid, words in kw.items():
        hits = len(words & toks)
        if hits:
            scored.append((hits, cid))
    scored.sort(reverse=True)
    return [controls_by_id[cid] for _, cid in scored[:top]]


def _catalogue(controls: list[dict], cats: dict) -> str:
    return "\n".join(f"{c['id']} [{cats.get(c['category'], c['category'])}] {c['title']}"
                     for c in controls)


def _prompt(candidates: list[dict], cats: dict, passage: str) -> list[dict]:
    system = (
        "You are a DPDPA (India Digital Personal Data Protection Act) compliance analyst reading a "
        "passage from a CLIENT'S OWN document. For each candidate checkpoint, decide what the passage "
        "actually STATES about it:\n"
        "- it is missing / not done / not compliant → GAP\n"
        "- it is planned, being drafted, or only partly in place → PARTIAL\n"
        "- it is explicitly affirmed as implemented → COMPLIANT (you MUST copy the affirming "
        "sentence into sourceQuote)\n"
        "- it does not apply to this organisation → NA\n"
        "- the topic is mentioned but its implementation status is NOT stated → TBC\n"
        "CRITICAL: never output COMPLIANT merely because the topic appears — a heading, a column "
        "name, or a question about a topic is NOT compliance. When in doubt, use TBC.\n"
        "evidence must paraphrase what the DOCUMENT says (never repeat the checkpoint title). "
        "sourceQuote must be an exact sentence copied from the passage.\n"
        "Example — passage says 'Privacy notice yet to be published on the website': "
        '{"controlId":"NT-01","status":"GAP","evidence":"Notice not yet published on the site",'
        '"sourceQuote":"Privacy notice yet to be published on the website","confidence":"high"}\n'
        "Example — passage says 'Cookie banner: to be discussed with vendor': "
        '{"controlId":"CK-01","status":"TBC","evidence":"Cookie banner still under discussion",'
        '"sourceQuote":"Cookie banner: to be discussed with vendor","confidence":"medium"}\n'
        "Skip candidates the passage does not genuinely address. "
        'Respond ONLY as JSON: {"mappings": [ ... ]}. If nothing matches, return {"mappings": []}.')
    user = (f"CANDIDATE CHECKPOINTS:\n{_catalogue(candidates, cats)}\n\n"
            f"PASSAGE:\n{passage}\n\n"
            'Return {"mappings":[{"controlId":...,"status":...,"evidence":...,"sourceQuote":...,"confidence":...}]}')
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _call_ollama(messages: list[dict], timeout: float | None = None) -> str:
    s = get_settings()
    payload = json.dumps({
        "model": s.ai_model, "messages": messages, "stream": False,
        "format": "json", "options": {"temperature": 0.1},
    }).encode("utf-8")
    req = urllib.request.Request(s.ai_base_url.rstrip("/") + "/api/chat", data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout or s.ai_timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data.get("message", {}).get("content", "")


def _extract_items(parsed):
    """Be forgiving about the shape the model returns: {mappings:[...]},
    a bare list, {controls:[...]}, or a dict keyed by control id."""
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ("mappings", "controls", "checkpoints", "results", "items"):
            v = parsed.get(key)
            if isinstance(v, list):
                return v
        # dict keyed by control id -> list of objects carrying the id
        if parsed and all(isinstance(v, dict) for v in parsed.values()):
            return [{"controlId": k, **v} for k, v in parsed.items()]
    return []


_CONF_RANK = {"high": 3, "medium": 2, "low": 1, "": 0}


def propose_mappings(doc_text: str, controls: list[dict], cats: dict) -> tuple[list[dict], str]:
    """Read the document in small passages, and for each passage ask the model only about
    the ~8 checkpoints whose keywords appear there. This keeps every model call small and
    fast (reliable on a CPU, no timeouts) and accumulates results across the whole document.

    The model's answers are matched leniently against the catalogue (ids normalized so
    'SEC-1' -> 'SEC-01'; loose status words mapped to the five canonical statuses). A human
    reviews and confirms every suggestion — nothing here is authoritative."""
    from .import_parser import build_id_lookup, match_control_id, normalize_status

    s = get_settings()
    ok, note = provider_available()
    if not ok:
        return [], note
    doc_text = (doc_text or "")[: s.ai_max_doc_chars]
    if not doc_text.strip():
        return [], ("We couldn't read any text from that file. If it's a scanned image or a photo, "
                    "please share a Word/Excel/PDF with selectable text.")

    lookup = build_id_lookup(c["id"] for c in controls)
    by_id = {c["id"]: c for c in controls}
    kw = _control_keywords(controls, cats)
    passages = _chunks(doc_text)

    # Rank passages by how "compliance-dense" they are, and cap how many we process so a
    # huge document still finishes in bounded time. per_call keeps any single call short.
    passages.sort(key=lambda p: len(_shortlist(p, kw, by_id, top=20)), reverse=True)
    max_calls = getattr(s, "ai_max_chunks", 10) or 10
    per_call = min(45, s.ai_timeout)

    best: dict = {}
    calls = errors = 0
    for passage in passages:
        if calls >= max_calls:
            break
        candidates = _shortlist(passage, kw, by_id, top=8)
        if not candidates:
            continue
        calls += 1
        try:
            items = _extract_items(json.loads(_call_ollama(_prompt(candidates, cats, passage),
                                                           timeout=per_call)))
        except Exception:
            errors += 1
            continue
        allowed = {c["id"] for c in candidates}
        for m in items if isinstance(items, list) else []:
            if not isinstance(m, dict):
                continue
            cid = match_control_id(str(m.get("controlId") or m.get("id") or ""), lookup)
            st = normalize_status(str(m.get("status") or ""))
            if not cid or not st or cid not in allowed:
                continue
            cand = {
                "controlId": cid, "status": st,
                "evidence": str(m.get("evidence", ""))[:400],
                "sourceQuote": str(m.get("sourceQuote", "") or m.get("quote", ""))[:300],
                "confidence": str(m.get("confidence", "")).lower()[:10] or "medium",
            }
            # keep the highest-confidence hit per checkpoint across passages
            prev = best.get(cid)
            if not prev or _CONF_RANK.get(cand["confidence"], 0) > _CONF_RANK.get(prev["confidence"], 0):
                best[cid] = cand

    out = sorted(best.values(), key=lambda x: x["controlId"])
    truncated = " (large document — analysed the most relevant sections)" if calls >= max_calls else ""

    if not out:
        if calls == 0:
            return [], ("The document didn't contain wording that lines up with the DPDPA checkpoints. "
                        "The template or paste option below is the reliable path for this one.")
        if errors == calls:
            return [], ("The assistant service didn't respond in time. It may still be loading the model — "
                        "try once more, or use the template/paste option below, which always works.")
        return [], ("The assistant read the document but couldn't confidently match it to any checkpoint. "
                    "This is common with short or free-form notes — the template or paste option below is the reliable path.")
    return out, (f"The assistant suggested {len(out)} checkpoint answer(s) from the document{truncated}. "
                 "Review each one — nothing is applied until you approve it.")
