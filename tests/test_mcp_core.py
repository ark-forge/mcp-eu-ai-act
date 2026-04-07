#!/usr/bin/env python3
"""
Core pytest suite for MCP EU AI Act Compliance Scanner.
Tests the 3 main tools: scan_project, check_compliance, regulation info.
Plus error handling for invalid inputs.

Task #1248 — QG dimension: Testing
"""

import sys
import tempfile
import shutil
from pathlib import Path

import pytest

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from server import (
    EUAIActChecker,
    MCPServer,
    RISK_CATEGORIES,
    ACTIONABLE_GUIDANCE,
    RISK_CATEGORY_INDICATORS,
    COMPLIANCE_TEMPLATES,
    _validate_project_path,
)


# ── Fixtures ──────────────────────────────────────────────


@pytest.fixture
def tmp_project(tmp_path):
    """Create a temporary project directory."""
    project = tmp_path / "sample_project"
    project.mkdir()
    return project


@pytest.fixture
def ai_project(tmp_project):
    """Create a sample project with multiple AI frameworks."""
    (tmp_project / "main.py").write_text(
        "import openai\n"
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "response = openai.ChatCompletion.create(model='gpt-4')\n"
    )
    (tmp_project / "ml.py").write_text(
        "from transformers import AutoModel\n"
        "import torch\n"
        "model = AutoModel.from_pretrained('bert-base')\n"
    )
    (tmp_project / "requirements.txt").write_text(
        "openai>=1.0.0\n"
        "anthropic>=0.18.0\n"
        "transformers>=4.30.0\n"
        "torch>=2.0.0\n"
        "langchain>=0.1.0\n"
    )
    (tmp_project / "README.md").write_text(
        "# Sample AI Project\n\n"
        "This project uses AI and machine learning for NLP tasks.\n"
    )
    return tmp_project


@pytest.fixture
def mcp_server():
    """Create a MCPServer legacy interface."""
    return MCPServer()


# ══════════════════════════════════════════════════════════
# 1. scan_project — Detect AI frameworks in sample project
# ══════════════════════════════════════════════════════════


class TestScanProject:
    """Tests for scan_project: detects AI frameworks in code and config."""

    def test_detects_openai_in_source(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        results = checker.scan_project()
        assert "openai" in results["detected_models"]

    def test_detects_anthropic_in_source(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        results = checker.scan_project()
        assert "anthropic" in results["detected_models"]

    def test_detects_huggingface_in_source(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        results = checker.scan_project()
        assert "huggingface" in results["detected_models"]

    def test_detects_pytorch_in_source(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        results = checker.scan_project()
        assert "pytorch" in results["detected_models"]

    def test_detects_langchain_in_config(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        results = checker.scan_project()
        assert "langchain" in results["detected_models"]

    def test_scan_returns_correct_structure(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        results = checker.scan_project()
        assert "files_scanned" in results
        assert "ai_files" in results
        assert "detected_models" in results
        assert isinstance(results["files_scanned"], int)
        assert isinstance(results["ai_files"], list)
        assert isinstance(results["detected_models"], dict)

    def test_scan_counts_files_correctly(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        results = checker.scan_project()
        # main.py + ml.py + requirements.txt = 3 files scanned
        assert results["files_scanned"] >= 3

    def test_scan_empty_project_returns_zero(self, tmp_project):
        checker = EUAIActChecker(str(tmp_project))
        results = checker.scan_project()
        assert results["files_scanned"] == 0
        assert results["detected_models"] == {}
        assert results["ai_files"] == []

    def test_scan_ai_files_have_framework_info(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        results = checker.scan_project()
        for ai_file in results["ai_files"]:
            assert "file" in ai_file
            assert "frameworks" in ai_file
            assert len(ai_file["frameworks"]) > 0

    def test_scan_via_mcp_server(self, mcp_server, ai_project):
        """Test scan_project through MCPServer legacy interface."""
        result = mcp_server.handle_request(
            "scan_project", {"project_path": str(ai_project)}
        )
        assert result["tool"] == "scan_project"
        assert "openai" in result["results"]["detected_models"]
        assert "anthropic" in result["results"]["detected_models"]

    def test_scan_detects_subdirectory_files(self, tmp_project):
        """Scan is recursive into subdirectories."""
        src = tmp_project / "src" / "ai"
        src.mkdir(parents=True)
        (src / "model.py").write_text("from groq import Groq\nclient = Groq()")
        checker = EUAIActChecker(str(tmp_project))
        results = checker.scan_project()
        assert "groq" in results["detected_models"]


# ══════════════════════════════════════════════════════════
# 2. check_compliance — Returns valid JSON with risk_level
# ══════════════════════════════════════════════════════════


class TestCheckCompliance:
    """Tests for check_compliance: returns structured JSON with risk info."""

    def test_limited_risk_returns_valid_structure(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        checker.scan_project()
        result = checker.check_compliance("limited")
        assert result["risk_category"] == "limited"
        assert "compliance_status" in result
        assert "compliance_score" in result
        assert "compliance_percentage" in result
        assert "requirements" in result
        assert "description" in result

    def test_high_risk_returns_valid_structure(self, tmp_project):
        (tmp_project / "README.md").write_text("# Project")
        checker = EUAIActChecker(str(tmp_project))
        result = checker.check_compliance("high")
        assert result["risk_category"] == "high"
        status = result["compliance_status"]
        assert "technical_documentation" in status
        assert "risk_management" in status
        assert "transparency" in status
        assert "data_governance" in status
        assert "human_oversight" in status
        assert "robustness" in status

    def test_minimal_risk_returns_valid_structure(self, tmp_project):
        (tmp_project / "README.md").write_text("# Minimal project")
        checker = EUAIActChecker(str(tmp_project))
        result = checker.check_compliance("minimal")
        assert result["risk_category"] == "minimal"
        assert "basic_documentation" in result["compliance_status"]
        assert result["compliance_status"]["basic_documentation"] is True

    def test_compliance_score_format(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        checker.scan_project()
        result = checker.check_compliance("limited")
        # Score format is "N/M"
        score = result["compliance_score"]
        parts = score.split("/")
        assert len(parts) == 2
        assert int(parts[0]) >= 0
        assert int(parts[1]) > 0

    def test_compliance_percentage_is_number(self, ai_project):
        checker = EUAIActChecker(str(ai_project))
        checker.scan_project()
        result = checker.check_compliance("limited")
        pct = result["compliance_percentage"]
        assert isinstance(pct, (int, float))
        assert 0 <= pct <= 100

    def test_full_compliance_high_risk(self, tmp_project):
        """All docs present with substantive content → 100% compliance score."""
        (tmp_project / "README.md").write_text("# Project\n\nThis project uses AI models for General Description and Architecture.")
        (tmp_project / "TECHNICAL_DOCUMENTATION.md").write_text(
            "# Technical Documentation\n\n## General Description\nSystem overview.\n\n"
            "## Architecture\nThe architecture and training data are documented here.\n\n"
            "## Training Data\nTraining data sources and performance metrics.\n"
            "This document describes the architecture and performance in detail.\n" * 5
        )
        (tmp_project / "RISK_MANAGEMENT.md").write_text(
            "# Risk Management\n\n## System Description\nAI risk system.\n\n"
            "## Risk Identification\nAll risks are identified here.\n\n"
            "## Risk Mitigation\nMitigation strategies for each risk.\n\n"
            "The residual risk after mitigation is documented. Risk and mitigation reviewed regularly.\n" * 5
        )
        (tmp_project / "TRANSPARENCY.md").write_text(
            "# Transparency\n\n## System Description\nAI system overview.\n\n"
            "## Capabilities and Limitations\nCapabilities and deployer instructions.\n\n"
            "## Human Oversight Instructions\nTransparency requirements and instructions for deployer oversight.\n" * 5
        )
        (tmp_project / "DATA_GOVERNANCE.md").write_text(
            "# Data Governance\n\n## Data Sources\nData source description.\n\n"
            "## Data Quality Criteria\nQuality criteria and preprocessing steps.\n\n"
            "## Data Preprocessing\nPreprocessing pipeline documentation.\n"
            "Data source quality and preprocessing details.\n" * 5
        )
        (tmp_project / "HUMAN_OVERSIGHT.md").write_text(
            "# Human Oversight\n\n## Oversight Mechanism\nHuman oversight process.\n\n"
            "## Responsible Persons\nNamed persons responsible for oversight.\n\n"
            "## Intervention Mechanisms\nOverride and intervention mechanisms.\n"
            "Human oversight and override procedures are documented here.\n" * 5
        )
        (tmp_project / "ROBUSTNESS.md").write_text(
            "# Robustness\n\n## Accuracy\nAccuracy metrics and benchmarks.\n\n"
            "## Robustness Testing\nRobustness and adversarial testing results.\n\n"
            "## Cybersecurity\nCybersecurity measures.\n"
            "Accuracy and robustness adversarial testing documented here.\n" * 5
        )
        checker = EUAIActChecker(str(tmp_project))
        result = checker.check_compliance("high")
        assert result["compliance_percentage"] == 100.0
        assert all(result["compliance_status"].values())

    def test_check_compliance_via_mcp_server(self, mcp_server, ai_project):
        """Test check_compliance through MCPServer legacy interface."""
        result = mcp_server.handle_request(
            "check_compliance",
            {"project_path": str(ai_project), "risk_category": "limited"},
        )
        assert result["tool"] == "check_compliance"
        assert result["results"]["risk_category"] == "limited"
        assert "compliance_score" in result["results"]

    def test_unacceptable_risk_has_empty_status(self, tmp_project):
        """Unacceptable risk has no compliance checks (prohibited)."""
        checker = EUAIActChecker(str(tmp_project))
        result = checker.check_compliance("unacceptable")
        assert result["risk_category"] == "unacceptable"
        assert len(result["compliance_status"]) == 0


# ══════════════════════════════════════════════════════════
# 3. Regulation info — Non-empty text for known articles
# ══════════════════════════════════════════════════════════


class TestRegulationInfo:
    """Tests for regulation data: RISK_CATEGORIES, ACTIONABLE_GUIDANCE,
    RISK_CATEGORY_INDICATORS, and suggest_risk_category tool."""

    def test_all_risk_categories_have_description(self):
        for cat, info in RISK_CATEGORIES.items():
            assert "description" in info
            assert len(info["description"]) > 0, f"Empty description for {cat}"

    def test_all_risk_categories_have_requirements(self):
        for cat, info in RISK_CATEGORIES.items():
            assert "requirements" in info
            assert isinstance(info["requirements"], list)
            assert len(info["requirements"]) > 0, f"No requirements for {cat}"

    def test_four_risk_categories_exist(self):
        expected = {"unacceptable", "high", "limited", "minimal"}
        assert set(RISK_CATEGORIES.keys()) == expected

    def test_actionable_guidance_has_eu_articles(self):
        """Each guidance entry references an EU AI Act article."""
        for key, guidance in ACTIONABLE_GUIDANCE.items():
            assert "eu_article" in guidance, f"Missing eu_article in {key}"
            assert len(guidance["eu_article"]) > 0, f"Empty eu_article in {key}"

    def test_actionable_guidance_has_how_steps(self):
        """Each guidance entry has concrete how-to steps."""
        for key, guidance in ACTIONABLE_GUIDANCE.items():
            assert "how" in guidance, f"Missing 'how' in {key}"
            assert isinstance(guidance["how"], list)
            assert len(guidance["how"]) > 0, f"No how steps for {key}"

    def test_actionable_guidance_has_what_and_why(self):
        for key, guidance in ACTIONABLE_GUIDANCE.items():
            assert "what" in guidance and len(guidance["what"]) > 0
            assert "why" in guidance and len(guidance["why"]) > 0

    def test_risk_category_indicators_have_keywords(self):
        """Each risk category indicator has keywords for matching."""
        for cat, info in RISK_CATEGORY_INDICATORS.items():
            assert "keywords" in info
            assert len(info["keywords"]) > 0, f"No keywords for {cat}"

    def test_suggest_risk_category_chatbot(self, mcp_server):
        """suggest_risk_category returns 'limited' for chatbot description."""
        result = mcp_server.handle_request(
            "suggest_risk_category",
            {"system_description": "chatbot for customer support"},
        )
        assert result["results"]["suggested_category"] == "limited"
        assert result["results"]["confidence"] in ("low", "medium", "high")

    def test_suggest_risk_category_recruitment(self, mcp_server):
        """suggest_risk_category returns 'high' for recruitment."""
        result = mcp_server.handle_request(
            "suggest_risk_category",
            {"system_description": "AI tool for recruitment and hiring decisions"},
        )
        assert result["results"]["suggested_category"] == "high"

    def test_suggest_risk_category_social_scoring(self, mcp_server):
        """suggest_risk_category returns 'unacceptable' for social scoring."""
        result = mcp_server.handle_request(
            "suggest_risk_category",
            {"system_description": "social scoring system for citizens"},
        )
        assert result["results"]["suggested_category"] == "unacceptable"

    def test_suggest_risk_category_spam_filter(self, mcp_server):
        """suggest_risk_category returns 'minimal' for spam filter."""
        result = mcp_server.handle_request(
            "suggest_risk_category",
            {"system_description": "spam filter for emails"},
        )
        assert result["results"]["suggested_category"] == "minimal"

    def test_compliance_templates_exist_for_high_risk(self):
        """Templates exist for all required high-risk documents."""
        expected = [
            "risk_management",
            "technical_documentation",
            "data_governance",
            "human_oversight",
            "robustness",
            "transparency",
        ]
        for tmpl in expected:
            assert tmpl in COMPLIANCE_TEMPLATES, f"Missing template: {tmpl}"
            assert "filename" in COMPLIANCE_TEMPLATES[tmpl]
            assert "content" in COMPLIANCE_TEMPLATES[tmpl]
            assert len(COMPLIANCE_TEMPLATES[tmpl]["content"]) > 100


# ══════════════════════════════════════════════════════════
# 4. Error handling — Invalid inputs → clear messages
# ══════════════════════════════════════════════════════════


class TestErrorHandling:
    """Tests for proper error handling on invalid inputs."""

    def test_scan_nonexistent_path(self):
        checker = EUAIActChecker("/nonexistent/path/to/project")
        result = checker.scan_project()
        assert "error" in result
        assert "does not exist" in result["error"]

    def test_compliance_invalid_risk_category(self, tmp_project):
        checker = EUAIActChecker(str(tmp_project))
        result = checker.check_compliance("invalid_category")
        assert "error" in result
        assert "Invalid risk category" in result["error"]

    def test_mcp_server_unknown_tool(self, mcp_server):
        result = mcp_server.handle_request("nonexistent_tool", {})
        assert "error" in result
        assert "Unknown tool" in result["error"]
        assert "available_tools" in result

    def test_mcp_server_missing_params(self, mcp_server):
        result = mcp_server.handle_request("scan_project", {})
        assert "error" in result

    def test_validate_blocked_path(self):
        """Scanning blocked paths returns security error."""
        is_safe, msg = _validate_project_path("/etc/passwd")
        assert is_safe is False
        assert "Access denied" in msg

    def test_validate_blocked_path_home(self):
        is_safe, msg = _validate_project_path("/home/ubuntu/.ssh")
        assert is_safe is False
        assert "Access denied" in msg

    def test_scan_blocked_path_returns_error(self):
        """EUAIActChecker.scan_project blocks sensitive paths."""
        checker = EUAIActChecker("/etc")
        result = checker.scan_project()
        assert "error" in result
        assert "Access denied" in result["error"]

    def test_compliance_templates_unacceptable_returns_error(self, mcp_server):
        """Requesting templates for unacceptable risk returns error."""
        result = mcp_server.handle_request(
            "generate_compliance_templates", {"risk_category": "unacceptable"}
        )
        assert "error" in result

    def test_scan_project_binary_file_no_crash(self, tmp_project):
        """Scanning a project with binary files doesn't crash."""
        (tmp_project / "binary.py").write_bytes(b"\x00\x80\xff\xfe" * 100)
        checker = EUAIActChecker(str(tmp_project))
        result = checker.scan_project()
        assert "files_scanned" in result
        assert result["files_scanned"] == 1
