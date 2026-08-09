"""Assessment frameworks — the platform is framework-agnostic by design.

The engine assesses whatever a versioned rulebook defines, and the whole intake
flow (template → customer documents → consented access → evidence-backed
report) doesn't care which law the controls encode. Activating a new framework
is therefore CONTENT work: encode its controls (with counsel review) as a new
rulebook, flip its status here, and the rest of the product lights up.

Until then, coming-soon frameworks are visible everywhere and companies can
register interest — which is sales signal today and instant activation later.
"""
from __future__ import annotations

FRAMEWORKS: dict[str, dict] = {
    "dpdpa": {
        "name": "DPDPA (India)",
        "long": "Digital Personal Data Protection Act 2023 + DPDP Rules 2025",
        "icon": "🇮🇳",
        "status": "active",
        "blurb": "86 checkpoints across notice, consent, security, breach readiness, "
                 "retention, processors, cross-border transfers and governance.",
    },
    "gdpr": {
        "name": "GDPR (EU)",
        "long": "General Data Protection Regulation",
        "icon": "🇪🇺",
        "status": "coming-soon",
        "blurb": "For organisations serving European customers — lawful bases, DSARs, "
                 "DPIAs, transfers.",
    },
    "hipaa": {
        "name": "HIPAA (US)",
        "long": "Health Insurance Portability and Accountability Act",
        "icon": "🏥",
        "status": "coming-soon",
        "blurb": "For handlers of US health information — privacy, security and breach "
                 "notification rules.",
    },
    "soc2": {
        "name": "SOC 2",
        "long": "Service Organization Control 2 (AICPA Trust Services)",
        "icon": "🛡️",
        "status": "coming-soon",
        "blurb": "The trust report enterprise buyers ask SaaS vendors for — security, "
                 "availability, confidentiality.",
    },
    "iso27001": {
        "name": "ISO/IEC 27001",
        "long": "Information Security Management Systems",
        "icon": "🌐",
        "status": "coming-soon",
        "blurb": "The international ISMS standard — Annex A controls, risk treatment, "
                 "certification readiness.",
    },
}


def active_ids() -> list[str]:
    return [k for k, v in FRAMEWORKS.items() if v["status"] == "active"]


def coming_soon() -> dict[str, dict]:
    return {k: v for k, v in FRAMEWORKS.items() if v["status"] == "coming-soon"}
