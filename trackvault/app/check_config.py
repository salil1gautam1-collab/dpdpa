"""Startup gate: in production, refuse to boot with insecure configuration.

Run by the entrypoint before the app starts. Exit non-zero (which stops the
container) if any blocking issue is found.
"""
from __future__ import annotations

import sys

from .config import get_settings


def main() -> int:
    s = get_settings()
    if not s.is_production:
        print(f"[config] environment={s.environment} (development checks only)")
        return 0
    issues = s.production_issues()
    if issues:
        print("REFUSING TO START — production configuration is insecure:", file=sys.stderr)
        for i in issues:
            print(f"  ✗ {i}", file=sys.stderr)
        print("\nFix these environment variables and redeploy. "
              "See scripts/generate_keys.py and DEPLOYMENT.md.", file=sys.stderr)
        return 1
    print("[config] production configuration OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
