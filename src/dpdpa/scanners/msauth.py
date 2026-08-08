"""Microsoft Entra (Azure AD) OAuth2 client-credentials token — shared by the
Azure and Intune/Defender connectors. Pure stdlib: the client secret is sent
directly to the token endpoint (no signing), so no crypto dependency needed.
"""
from __future__ import annotations

from .httpjson import post_form, error_summary


def get_token(tenant_id: str, client_id: str, client_secret: str, scope: str) -> tuple[str | None, str]:
    """Returns (access_token, error). One of the two is set."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    code, parsed, raw = post_form(url, {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    })
    if code == 200 and isinstance(parsed, dict) and parsed.get("access_token"):
        return parsed["access_token"], ""
    return None, f"token request failed (HTTP {code}): {error_summary(parsed, raw)}"
