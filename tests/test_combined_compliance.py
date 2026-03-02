"""Tests for combined_compliance_report tool and its helper functions.

Covers: _compute_combined_requirements, _generate_combined_insight,
        combined_compliance_report MCP tool (via direct function call).
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import (
    _compute_combined_requirements,
    _generate_combined_insight,
    EUAIActChecker,
    GDPRChecker,
)


# ============================================================
# _compute_combined_requirements
# ============================================================

class TestComputeCombinedRequirements:
    def test_pii_high_risk_is_critical(self):
        result = _compute_combined_requirements(["openai"], ["pii_fields"], "high")
        assert result["priority"] == "critical"
        assert "ai_processing_personal_data" in result["overlap_type"]

    def test_pii_limited_risk_is_high(self):
        result = _compute_combined_requirements(["openai"], ["pii_fields"], "limited")
        assert result["priority"] == "high"

    def test_database_queries_high_risk_is_critical(self):
        result = _compute_combined_requirements(["anthropic"], ["database_queries"], "high")
        assert result["priority"] == "critical"

    def test_tracking_limited_is_high(self):
        result = _compute_combined_requirements(["huggingface"], ["user_tracking"], "limited")
        assert result["priority"] == "high"
        assert "ai_automated_tracking" in result["overlap_type"]

    def test_tracking_minimal_is_medium(self):
        result = _compute_combined_requirements(["openai"], ["user_tracking"], "minimal")
        assert result["priority"] == "medium"

    def test_geolocation_is_medium(self):
        result = _compute_combined_requirements(["openai"], ["geolocation"], "limited")
        assert result["priority"] == "medium"
        assert "ai_geolocation_processing" in result["overlap_type"]

    def test_uploads_is_medium(self):
        result = _compute_combined_requirements(["langchain"], ["file_uploads"], "limited")
        assert result["priority"] == "medium"
        assert "ai_processing_user_uploads" in result["overlap_type"]

    def test_cookies_generates_requirement(self):
        result = _compute_combined_requirements(["openai"], ["cookie_operations"], "limited")
        assert "ai_cookie_tracking" in result["overlap_type"]
        assert any("ePrivacy" in r for r in result["requirements"])

    def test_no_specific_overlap_returns_default(self):
        result = _compute_combined_requirements(["openai"], ["consent_mechanism"], "limited")
        assert "dual_regulation_applies" in result["overlap_type"]
        assert len(result["requirements"]) >= 1

    def test_pii_includes_dpia_requirement(self):
        result = _compute_combined_requirements(["openai"], ["pii_fields"], "high")
        assert any("DPIA" in r for r in result["requirements"])

    def test_pii_includes_art11_requirement(self):
        result = _compute_combined_requirements(["openai"], ["pii_fields"], "limited")
        assert any("Art. 11" in r for r in result["requirements"])

    def test_tracking_includes_art22_requirement(self):
        result = _compute_combined_requirements(["openai"], ["user_tracking"], "limited")
        assert any("Art. 22" in r for r in result["requirements"])

    def test_high_risk_pii_adds_human_oversight(self):
        result = _compute_combined_requirements(["openai"], ["pii_fields"], "high")
        assert any("Art. 14" in r for r in result["requirements"])

    def test_multiple_gdpr_categories(self):
        result = _compute_combined_requirements(
            ["openai"], ["pii_fields", "user_tracking", "geolocation"], "high"
        )
        # All three overlap types should be present
        assert "ai_processing_personal_data" in result["overlap_type"]
        assert "ai_automated_tracking" in result["overlap_type"]
        assert "ai_geolocation_processing" in result["overlap_type"]
        assert result["priority"] == "critical"

    def test_requirements_are_non_empty_strings(self):
        result = _compute_combined_requirements(["openai"], ["pii_fields"], "limited")
        assert all(isinstance(r, str) and len(r) > 0 for r in result["requirements"])


# ============================================================
# _generate_combined_insight
# ============================================================

class TestGenerateCombinedInsight:
    def _make_flag(self, priority: str) -> dict:
        return {
            "file": "app.py",
            "priority": priority,
            "overlap_type": ["ai_processing_personal_data"],
            "combined_requirements": ["DPIA required"],
            "eu_ai_act": {"frameworks": ["openai"], "risk_category": "high"},
            "gdpr": {"patterns": ["pii_fields"]},
        }

    def test_no_overlap_with_ai_no_pii(self):
        eu_scan = {"ai_files": [{"file": "app.py", "frameworks": ["openai"]}]}
        gdpr_scan = {"processing_summary": {"processes_personal_data": False}}
        insight = _generate_combined_insight([], eu_scan, gdpr_scan)
        assert "AI frameworks detected" in insight
        assert "no personal data" in insight

    def test_no_overlap_no_ai(self):
        eu_scan = {"ai_files": []}
        gdpr_scan = {"processing_summary": {"processes_personal_data": True}}
        insight = _generate_combined_insight([], eu_scan, gdpr_scan)
        assert "No AI frameworks" in insight

    def test_no_overlap_both_detected(self):
        eu_scan = {"ai_files": [{"file": "a.py", "frameworks": ["openai"]}]}
        gdpr_scan = {"processing_summary": {"processes_personal_data": True}}
        insight = _generate_combined_insight([], eu_scan, gdpr_scan)
        assert "No file-level overlap" in insight

    def test_critical_flags_mention_dpia(self):
        flags = [self._make_flag("critical")]
        insight = _generate_combined_insight(flags, {}, {})
        assert "DPIA" in insight or "critical" in insight.lower()

    def test_high_flags_mention_priority(self):
        flags = [self._make_flag("high")]
        insight = _generate_combined_insight(flags, {}, {})
        assert "high priority" in insight.lower() or "high" in insight.lower()

    def test_medium_flags_returns_general_message(self):
        flags = [self._make_flag("medium")]
        insight = _generate_combined_insight(flags, {}, {})
        assert "hotspot" in insight.lower()

    def test_insight_is_non_empty_string(self):
        flags = [self._make_flag("high")]
        insight = _generate_combined_insight(flags, {}, {})
        assert isinstance(insight, str) and len(insight) > 10


# ============================================================
# combined_compliance_report — end-to-end via EUAIActChecker + GDPRChecker
# ============================================================

class TestCombinedComplianceReportIntegration:
    """Tests the full correlation logic using real scanner outputs on tmp projects."""

    def test_dual_flagged_file_detected(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "import openai\nclient = openai.OpenAI()\nemail = user.email\nfirst_name = user.first_name\n"
        )
        eu = EUAIActChecker(str(tmp_path))
        eu_scan = eu.scan_project()
        gdpr = GDPRChecker(str(tmp_path))
        gdpr_scan = gdpr.scan_project()

        ai_map = {e["file"]: e["frameworks"] for e in eu_scan.get("ai_files", [])}
        gdpr_map = {e["file"]: e["categories"] for e in gdpr_scan.get("flagged_files", [])}
        overlap = set(ai_map.keys()) & set(gdpr_map.keys())

        assert "app.py" in overlap

    def test_no_overlap_when_no_pii(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\nclient = openai.OpenAI()\n")
        eu = EUAIActChecker(str(tmp_path))
        eu_scan = eu.scan_project()
        gdpr = GDPRChecker(str(tmp_path))
        gdpr_scan = gdpr.scan_project()

        ai_map = {e["file"]: e["frameworks"] for e in eu_scan.get("ai_files", [])}
        gdpr_map = {e["file"]: e["categories"] for e in gdpr_scan.get("flagged_files", [])}
        overlap = set(ai_map.keys()) & set(gdpr_map.keys())

        assert len(overlap) == 0

    def test_no_overlap_when_no_ai(self, tmp_path):
        (tmp_path / "app.py").write_text("email = user.email\nfirst_name = user.first_name\n")
        eu = EUAIActChecker(str(tmp_path))
        eu_scan = eu.scan_project()
        gdpr = GDPRChecker(str(tmp_path))
        gdpr_scan = gdpr.scan_project()

        ai_map = {e["file"]: e["frameworks"] for e in eu_scan.get("ai_files", [])}
        gdpr_map = {e["file"]: e["categories"] for e in gdpr_scan.get("flagged_files", [])}
        overlap = set(ai_map.keys()) & set(gdpr_map.keys())

        assert len(overlap) == 0

    def test_overlap_with_tracking(self, tmp_path):
        (tmp_path / "tracking.py").write_text(
            "import anthropic\nclient = anthropic.Anthropic()\nanalytics.track(user_id, 'page_view')\n"
        )
        eu = EUAIActChecker(str(tmp_path))
        eu_scan = eu.scan_project()
        gdpr = GDPRChecker(str(tmp_path))
        gdpr_scan = gdpr.scan_project()

        ai_map = {e["file"]: e["frameworks"] for e in eu_scan.get("ai_files", [])}
        gdpr_map = {e["file"]: e["categories"] for e in gdpr_scan.get("flagged_files", [])}
        overlap = set(ai_map.keys()) & set(gdpr_map.keys())

        assert "tracking.py" in overlap
        combined = _compute_combined_requirements(
            ai_map["tracking.py"], gdpr_map["tracking.py"], "limited"
        )
        assert "ai_automated_tracking" in combined["overlap_type"]

    def test_combined_requirements_structure(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "from langchain.llms import OpenAI\nllm = OpenAI()\nemail = user.email\n"
        )
        eu = EUAIActChecker(str(tmp_path))
        eu_scan = eu.scan_project()
        gdpr = GDPRChecker(str(tmp_path))
        gdpr_scan = gdpr.scan_project()

        ai_map = {e["file"]: e["frameworks"] for e in eu_scan.get("ai_files", [])}
        gdpr_map = {e["file"]: e["categories"] for e in gdpr_scan.get("flagged_files", [])}
        overlap = set(ai_map.keys()) & set(gdpr_map.keys())

        assert "app.py" in overlap
        combined = _compute_combined_requirements(
            ai_map["app.py"], gdpr_map["app.py"], "limited"
        )
        assert isinstance(combined["overlap_type"], list)
        assert isinstance(combined["requirements"], list)
        assert combined["priority"] in ("critical", "high", "medium", "low")
