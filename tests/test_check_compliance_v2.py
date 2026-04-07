"""Tests for check_compliance v2 — content scoring, article mapping, backward compat.

These tests define the TARGET behaviour. They will FAIL until server.py is updated
to implement content scoring (v2). Do not modify these tests to make them pass —
implement the feature in server.py instead.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import EUAIActChecker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RISK_MANAGEMENT_REQUIRED_SECTIONS = [
    "Risk Identification",
    "Risk Mitigation",
    "Residual Risks",
    "Testing & Validation",
    "Review Schedule",
]

RISK_MANAGEMENT_KEYWORDS = ["risk", "mitigation", "testing", "lifecycle"]


def _make_checker(path: Path) -> EUAIActChecker:
    return EUAIActChecker(str(path))


def _rich_risk_management(path: Path) -> None:
    """Write a RISK_MANAGEMENT.md that covers all required sections and keywords."""
    content = "\n".join([
        "# Risk Management System",
        "",
        "## Risk Identification",
        "This document identifies all risks associated with the AI lifecycle.",
        "We assess risk at each stage of the risk management process.",
        "",
        "## Risk Mitigation",
        "Each risk has a corresponding mitigation strategy.",
        "Mitigation measures are reviewed and updated regularly.",
        "",
        "## Residual Risks",
        "After mitigation, residual risks are documented and accepted by management.",
        "",
        "## Testing & Validation",
        "All mitigation strategies undergo testing before deployment.",
        "Validation includes both automated testing and manual review.",
        "",
        "## Review Schedule",
        "Risk management reviews are conducted quarterly.",
        "Annual full review of all identified risks.",
        "",
        "## Lifecycle Considerations",
        "Risk management spans the entire AI lifecycle from design to decommission.",
    ])
    (path / "RISK_MANAGEMENT.md").write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Empty file → score near 0
# ---------------------------------------------------------------------------

def test_empty_file_scores_zero(tmp_path):
    """An empty RISK_MANAGEMENT.md (< 50 chars) should score 0 or 5 (empty penalty)."""
    (tmp_path / "RISK_MANAGEMENT.md").write_text("", encoding="utf-8")
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")

    assert "content_scores" in result, "v2: 'content_scores' key missing from output"
    score = result["content_scores"].get("RISK_MANAGEMENT.md", 0)
    assert score <= 5, (
        f"Expected empty file to score <= 5, got {score}"
    )


# ---------------------------------------------------------------------------
# 2. Non-existent file → score 0
# ---------------------------------------------------------------------------

def test_nonexistent_file_scores_zero(tmp_path):
    """A missing RISK_MANAGEMENT.md should score 0."""
    # tmp_path is empty — no RISK_MANAGEMENT.md created
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")

    assert "content_scores" in result, "v2: 'content_scores' key missing from output"
    score = result["content_scores"].get("RISK_MANAGEMENT.md", 0)
    assert score == 0, f"Expected missing file to score 0, got {score}"


# ---------------------------------------------------------------------------
# 3. Rich file → score >= 70
# ---------------------------------------------------------------------------

def test_complete_file_scores_high(tmp_path):
    """RISK_MANAGEMENT.md with all required sections + keywords should score >= 70."""
    _rich_risk_management(tmp_path)
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")

    assert "content_scores" in result, "v2: 'content_scores' key missing from output"
    score = result["content_scores"].get("RISK_MANAGEMENT.md", 0)
    assert score >= 70, (
        f"Expected complete file to score >= 70, got {score}"
    )


# ---------------------------------------------------------------------------
# 4. content_scores present in output
# ---------------------------------------------------------------------------

def test_content_scores_present_in_output(tmp_path):
    """check_compliance must return 'content_scores' key."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")
    assert "content_scores" in result, (
        "'content_scores' key missing — v2 not yet implemented"
    )


# ---------------------------------------------------------------------------
# 5. article_map present in output
# ---------------------------------------------------------------------------

def test_article_map_present_in_output(tmp_path):
    """check_compliance must return 'article_map' key."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")
    assert "article_map" in result, (
        "'article_map' key missing — v2 not yet implemented"
    )


# ---------------------------------------------------------------------------
# 6. compliance_status still present (backward compat)
# ---------------------------------------------------------------------------

def test_backward_compat_compliance_status_still_present(tmp_path):
    """v2 must keep 'compliance_status' (v1 field)."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")
    assert "compliance_status" in result


# ---------------------------------------------------------------------------
# 7. compliance_score still present (backward compat)
# ---------------------------------------------------------------------------

def test_backward_compat_compliance_score_still_present(tmp_path):
    """v2 must keep 'compliance_score' (v1 field)."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")
    assert "compliance_score" in result


# ---------------------------------------------------------------------------
# 8. compliance_percentage still present (backward compat)
# ---------------------------------------------------------------------------

def test_backward_compat_compliance_percentage_still_present(tmp_path):
    """v2 must keep 'compliance_percentage' (v1 field)."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")
    assert "compliance_percentage" in result


# ---------------------------------------------------------------------------
# 9. Path traversal → rejected
# ---------------------------------------------------------------------------

def test_path_traversal_rejected(tmp_path):
    """check_compliance called on a path traversal attempt must return an error."""
    # We create a checker with a traversal-like path string
    checker = EUAIActChecker("/../../../etc/passwd")
    result = checker.check_compliance("high")
    assert "error" in result, (
        "Expected path traversal to return an error dict, got: "
        + str(result)
    )


# ---------------------------------------------------------------------------
# 10. article_map has the correct articles for high-risk category
# ---------------------------------------------------------------------------

def test_article_map_has_correct_articles_for_high(tmp_path):
    """For risk_category='high', article_map must include keys: 9, 10, 11, 13, 14, 15."""
    checker = _make_checker(tmp_path)
    result = checker.check_compliance("high")

    assert "article_map" in result, "v2: 'article_map' key missing from output"
    article_map = result["article_map"]

    expected_articles = {"9", "10", "11", "13", "14", "15"}
    actual_keys = set(str(k) for k in article_map.keys())
    missing = expected_articles - actual_keys
    assert not missing, (
        f"article_map missing expected article keys: {missing}. "
        f"Got: {actual_keys}"
    )
