"""Pure security-critical unit tests — no database required."""
import os

os.environ.setdefault("TRACKVAULT_SECRET_KEY", "test-secret-key-at-least-32-chars-long")

from app.crypto import decrypt_secret, encrypt_secret  # noqa: E402
from app.security import hash_password, verify_password  # noqa: E402
from app import ratelimit  # noqa: E402
from app.domain import engine  # noqa: E402


def test_secret_encryption_roundtrip():
    secret = {"secretAccessKey": "wJalrXUtnFEMI/EXAMPLE", "extra": "value"}
    token = encrypt_secret(secret)
    assert "wJalrXUtnFEMI" not in token           # ciphertext must not contain plaintext
    assert "EXAMPLE" not in token
    assert decrypt_secret(token) == secret


def test_secret_decrypt_tampered_returns_empty():
    token = encrypt_secret({"a": "b"})
    assert decrypt_secret(token[:-4] + "AAAA") == {}   # tampered token rejected
    assert decrypt_secret("") == {}


def test_password_hash_is_not_plaintext_and_verifies():
    h = hash_password("Sup3r-Secret-Passphrase!")
    assert "Sup3r-Secret-Passphrase!" not in h
    assert h.startswith("$argon2")
    assert verify_password(h, "Sup3r-Secret-Passphrase!") is True
    assert verify_password(h, "wrong") is False


def test_rate_limiter_blocks_after_limit():
    key = "unit-test-ip"
    assert all(ratelimit.allow(key, limit=3, window_seconds=60) for _ in range(3))
    assert ratelimit.allow(key, limit=3, window_seconds=60) is False


def test_engine_hybrid_scanner_gap_beats_declaration():
    control = {"id": "CK-01", "checkMethod": "hybrid", "webCheckId": "cmp_present"}
    web = {"cmp_present": [{"webCheckId": "cmp_present", "status": "gap",
                            "evidence": [{"kind": "html-signature"}]}]}
    # Client declares COMPLIANT, but the scanner observed a gap -> GAP wins.
    assertions = {"CK-01": {"status": "COMPLIANT", "evidence": [{"kind": "declaration"}]}}
    res = engine.resolve(control, web, assertions, {})
    assert res["status"] == "GAP"
    assert "conflict" in res


def test_engine_summary_score():
    snap = {"resolutions": [
        {"status": "COMPLIANT", "category": "NT"},
        {"status": "GAP", "category": "NT"},
        {"status": "PARTIAL", "category": "CN"},
        {"status": "NA", "category": "CH"},
    ]}
    s = engine.summarize(snap)
    # determined = 3 (compliant+partial+gap); score = (1 + 0.5) / 3 * 100 = 50.0
    assert s["determined"] == 3
    assert s["complianceScore"] == 50.0
