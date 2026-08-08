"""Tests for the smart customer-data import parser (no DB)."""
import os

os.environ.setdefault("TRACKVAULT_SECRET_KEY", "test-secret-key-at-least-32-chars-long")

from app.services import import_parser as ip  # noqa: E402

LOOKUP = ip.build_id_lookup(["SEC-01", "CN-02", "RET-01", "NT-05"])


def test_status_word_mapping():
    assert ip.normalize_status("gap") == "GAP"
    assert ip.normalize_status("Not Compliant") == "GAP"
    assert ip.normalize_status("compliant") == "COMPLIANT"
    assert ip.normalize_status("Partially") == "PARTIAL"
    assert ip.normalize_status("N/A") == "NA"
    assert ip.normalize_status("to be confirmed") == "TBC"
    assert ip.normalize_status("") is None


def test_fuzzy_control_id_matching():
    assert ip.match_control_id("SEC-01", LOOKUP) == "SEC-01"
    assert ip.match_control_id("sec 01", LOOKUP) == "SEC-01"
    assert ip.match_control_id("SEC01", LOOKUP) == "SEC-01"
    assert ip.match_control_id("sec-1", LOOKUP) == "SEC-01"
    assert ip.match_control_id("ZZ-99", LOOKUP) is None


def test_parse_simple_comma_lines():
    text = ("SEC-01, gap, Security marked not compliant, IT\n"
            "CN-02 | gap | No consent checkbox\n"
            "RET-01: partial: Retention schedule in draft")
    rows = ip.parse_text(text, LOOKUP)
    by = {r["controlId"]: r for r in rows}
    assert by["SEC-01"]["status"] == "GAP"
    assert by["SEC-01"]["department"] == "IT"
    assert "consent checkbox" in by["CN-02"]["evidence"]
    assert by["RET-01"]["status"] == "PARTIAL"


def test_parse_csv_with_headers():
    data = ("Control,Status,Remarks,Owner\n"
            "SEC-01,Non-compliant,No policy,Security\n"
            "NT-05,Compliant,Notice served,Legal\n").encode()
    rows = ip.parse_csv(data, LOOKUP)
    by = {r["controlId"]: r for r in rows}
    assert by["SEC-01"]["status"] == "GAP"
    assert by["SEC-01"]["department"] == "Security"
    assert by["NT-05"]["status"] == "COMPLIANT"


def test_parse_json_still_supported():
    text = '{"assertions":[{"controlId":"SEC-01","status":"GAP","evidence":"x","source":{"department":"IT"}}]}'
    rows = ip.parse_text(text, LOOKUP)
    assert rows[0]["controlId"] == "SEC-01"
    assert rows[0]["department"] == "IT"


def test_garbage_lines_ignored():
    text = "This is just a heading\nSome prose about compliance\nSEC-01 gap actual answer"
    rows = ip.parse_text(text, LOOKUP)
    assert len(rows) == 1 and rows[0]["controlId"] == "SEC-01"
