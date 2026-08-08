"""Tiny JSON-over-HTTPS helper shared by the cloud connectors (stdlib only)."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 25
UA = "DPDPA-Sentinel/0.1 (read-only posture scan)"


def get(url: str, headers: dict | None = None) -> tuple[int, dict | list | None, str]:
    """GET a JSON endpoint. Returns (status, parsed_or_None, raw_text)."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(2_000_000).decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw), raw
            except json.JSONDecodeError:
                return resp.status, None, raw
    except urllib.error.HTTPError as ex:
        raw = ex.read(100_000).decode("utf-8", errors="replace")
        try:
            return ex.code, json.loads(raw), raw
        except json.JSONDecodeError:
            return ex.code, None, raw
    except Exception as ex:
        return 0, None, f"network-error: {type(ex).__name__}: {ex}"


def post_form(url: str, fields: dict, headers: dict | None = None) -> tuple[int, dict | None, str]:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("User-Agent", UA)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(500_000).decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw), raw
            except json.JSONDecodeError:
                return resp.status, None, raw
    except urllib.error.HTTPError as ex:
        raw = ex.read(100_000).decode("utf-8", errors="replace")
        try:
            return ex.code, json.loads(raw), raw
        except json.JSONDecodeError:
            return ex.code, None, raw
    except Exception as ex:
        return 0, None, f"network-error: {type(ex).__name__}: {ex}"


def error_summary(parsed, raw: str) -> str:
    """Best-effort human-readable error from a cloud API JSON body."""
    if isinstance(parsed, dict):
        err = parsed.get("error")
        if isinstance(err, dict):
            return err.get("message") or err.get("code") or json.dumps(err)[:200]
        if isinstance(err, str):
            return parsed.get("error_description", err)
    return (raw or "unknown")[:200]
