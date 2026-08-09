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


def _catalogue(controls: list[dict], cats: dict) -> str:
    lines = []
    for c in controls:
        lines.append(f"{c['id']} [{cats.get(c['category'], c['category'])}] {c['title']}")
    return "\n".join(lines)


def _prompt(controls: list[dict], cats: dict, doc_text: str) -> list[dict]:
    system = (
        "You are a DPDPA (India Digital Personal Data Protection Act) compliance analyst. "
        "You are given a catalogue of compliance checkpoints (id, area, title) and a client's "
        "document written in their own words/format. Map the document's content onto the "
        "checkpoints. For each checkpoint you find clear evidence for, output an object with: "
        "controlId (must be an id from the catalogue), status (one of COMPLIANT, PARTIAL, GAP, NA, TBC), "
        "evidence (a short paraphrase), sourceQuote (the exact sentence/phrase from the document you "
        "used), and confidence (high, medium, or low). Only include checkpoints you have real evidence "
        "for — do not guess. Map 'not compliant'/'no policy'/'missing' to GAP, partial arrangements to "
        "PARTIAL, clearly-in-place controls to COMPLIANT, and 'does not apply' to NA. "
        'Respond ONLY as JSON: {"mappings": [ ... ]}.')
    user = (f"CHECKPOINT CATALOGUE:\n{_catalogue(controls, cats)}\n\n"
            f"CLIENT DOCUMENT:\n{doc_text}\n\n"
            'Return {"mappings":[{"controlId":...,"status":...,"evidence":...,"sourceQuote":...,"confidence":...}]}')
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _call_ollama(messages: list[dict]) -> str:
    s = get_settings()
    payload = json.dumps({
        "model": s.ai_model, "messages": messages, "stream": False,
        "format": "json", "options": {"temperature": 0.1},
    }).encode("utf-8")
    req = urllib.request.Request(s.ai_base_url.rstrip("/") + "/api/chat", data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=s.ai_timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data.get("message", {}).get("content", "")


def propose_mappings(doc_text: str, controls: list[dict], cats: dict) -> tuple[list[dict], str]:
    """Return (suggestions, note). suggestions validated against the catalogue."""
    s = get_settings()
    ok, note = provider_available()
    if not ok:
        return [], note
    doc_text = (doc_text or "")[: s.ai_max_doc_chars]
    if not doc_text.strip():
        return [], "No readable text found in the document."
    valid_ids = {c["id"] for c in controls}
    try:
        raw = _call_ollama(_prompt(controls, cats, doc_text))
        parsed = json.loads(raw)
        items = parsed.get("mappings", parsed if isinstance(parsed, list) else [])
    except Exception as ex:
        return [], f"AI mapping failed: {type(ex).__name__}: {ex}"

    out, seen = [], set()
    for m in items if isinstance(items, list) else []:
        cid = str(m.get("controlId", "")).strip().upper()
        st = str(m.get("status", "")).strip().upper()
        if cid not in valid_ids or st not in VALID_STATUS or cid in seen:
            continue
        seen.add(cid)
        out.append({
            "controlId": cid, "status": st,
            "evidence": str(m.get("evidence", ""))[:400],
            "sourceQuote": str(m.get("sourceQuote", ""))[:300],
            "confidence": str(m.get("confidence", "")).lower()[:10] or "medium",
        })
    return out, f"{len(out)} suggestion(s) proposed by the self-hosted model — review before applying."
