"""Backward compatibility tests — ensures v1 API consumers don't break on v2.

These tests define the CONTRACT that must never be broken, regardless of
what new features are added. All tests should pass on both v1 and v2.
"""

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import EUAIActChecker, create_server


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

V1_COMPLIANCE_FIELDS = {
    "compliance_status",
    "compliance_score",
    "compliance_percentage",
    "risk_category",
    "description",
    "requirements",
}


def _make_checker(path: Path) -> EUAIActChecker:
    return EUAIActChecker(str(path))


def _minimal_scan_result() -> dict:
    """Minimal scan result structure expected by generate_report."""
    return {
        "files_scanned": 0,
        "ai_files": [],
        "detected_models": {},
    }


# ---------------------------------------------------------------------------
# 1. All v1 fields present for risk_category="high"
# ---------------------------------------------------------------------------

def test_check_compliance_v1_fields_high(tmp_path):
    """check_compliance('high') must return all v1 fields."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")
    for field in V1_COMPLIANCE_FIELDS:
        assert field in result, (
            f"v1 field '{field}' missing from check_compliance('high') output"
        )


# ---------------------------------------------------------------------------
# 2. All v1 fields present for risk_category="limited"
# ---------------------------------------------------------------------------

def test_check_compliance_v1_fields_limited(tmp_path):
    """check_compliance('limited') must return all v1 fields."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("limited")
    for field in V1_COMPLIANCE_FIELDS:
        assert field in result, (
            f"v1 field '{field}' missing from check_compliance('limited') output"
        )


# ---------------------------------------------------------------------------
# 3. All v1 fields present for risk_category="minimal"
# ---------------------------------------------------------------------------

def test_check_compliance_v1_fields_minimal(tmp_path):
    """check_compliance('minimal') must return all v1 fields."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("minimal")
    for field in V1_COMPLIANCE_FIELDS:
        assert field in result, (
            f"v1 field '{field}' missing from check_compliance('minimal') output"
        )


# ---------------------------------------------------------------------------
# 4. compliance_status is a dict (not a list or other type)
# ---------------------------------------------------------------------------

def test_compliance_status_is_dict(tmp_path):
    """compliance_status must be a dict — v1 consumers iterate .items()."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")
    assert isinstance(result["compliance_status"], dict), (
        f"compliance_status must be dict, got {type(result['compliance_status'])}"
    )


# ---------------------------------------------------------------------------
# 5. compliance_score matches "N/M" format
# ---------------------------------------------------------------------------

def test_compliance_score_format(tmp_path):
    """compliance_score must match the pattern 'digit/digit' (e.g. '2/6')."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")
    score = result["compliance_score"]
    assert re.match(r"^\d+/\d+$", str(score)), (
        f"compliance_score '{score}' does not match expected 'N/M' format"
    )


# ---------------------------------------------------------------------------
# 6. compliance_percentage is numeric
# ---------------------------------------------------------------------------

def test_compliance_percentage_is_float_or_int(tmp_path):
    """compliance_percentage must be a numeric type (int or float)."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("limited")
    pct = result["compliance_percentage"]
    assert isinstance(pct, (int, float)), (
        f"compliance_percentage must be numeric, got {type(pct)}: {pct}"
    )


# ---------------------------------------------------------------------------
# 7. generate_report v1 keys present
# ---------------------------------------------------------------------------

def test_generate_report_v1_keys_present(tmp_path):
    """generate_report output must contain all v1 top-level keys."""
    checker = _make_checker(tmp_path)
    scan_result = _minimal_scan_result()
    compliance_result = checker.check_compliance("limited")
    report = checker.generate_report(scan_result, compliance_result)

    expected_keys = {
        "report_date",
        "project_path",
        "scan_summary",
        "compliance_summary",
        "detailed_findings",
        "recommendations",
    }
    for key in expected_keys:
        assert key in report, (
            f"v1 key '{key}' missing from generate_report output"
        )


# ---------------------------------------------------------------------------
# 8. scan_project v1 keys present
# ---------------------------------------------------------------------------

def test_scan_project_v1_keys_present(tmp_path):
    """scan_project output must contain all v1 top-level keys."""
    # Create a minimal Python file so the scanner has something to traverse
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")

    checker = _make_checker(tmp_path)
    result = checker.scan_project()

    expected_keys = {"files_scanned", "ai_files", "detected_models"}
    for key in expected_keys:
        assert key in result, (
            f"v1 key '{key}' missing from scan_project output"
        )
