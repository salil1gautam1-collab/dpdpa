#!/usr/bin/env python3
"""Generate strong production secrets for TrackVault.

Usage:  python scripts/generate_keys.py
Copy the output into your .env (never commit it).
"""
import base64
import secrets


def main() -> None:
    secret_key = secrets.token_urlsafe(48)
    encryption_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    admin_password = secrets.token_urlsafe(18)
    print("# --- Generated TrackVault secrets — paste into .env, keep private ---")
    print(f"TRACKVAULT_SECRET_KEY={secret_key}")
    print(f"TRACKVAULT_ENCRYPTION_KEY={encryption_key}")
    print(f"TRACKVAULT_BOOTSTRAP_ADMIN_PASSWORD={admin_password}")
    print("#")
    print("# Rotating TRACKVAULT_ENCRYPTION_KEY makes existing encrypted connector")
    print("# credentials unreadable — re-enter connectors after a key change.")


if __name__ == "__main__":
    main()
