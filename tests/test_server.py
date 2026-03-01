#!/usr/bin/env python3
"""
Pytest unit tests for the MCP EU AI Act server.
Covers: scan endpoint, rate limiting, error handling, path validation,
API key management, risk category suggestion, compliance templates.
"""

import json
import os
import shutil
import sys
import tempfile
import time
from enum import Enum
from pathlib import Path

import pytest

# Add parent directory to path for import
sys.path.insert(0, str(Path(__file__).parent.parent))

from server import (
    AI_MODEL_PATTERNS,
    ACTIONABLE_GUIDANCE,
    BLOCKED_PATHS,
    COMPLIANCE_TEMPLATES,
    CONFIG_DEPENDENCY_PATTERNS,
    EUAIActChecker,
    FREE_TIER_DAILY_LIMIT,
    MCPServer,
    RISK_CATEGORIES,
    RISK_CATEGORY_INDICATORS,
    ApiKeyManager,
    RateLimiter,
    RateLimitMiddleware,
    _add_banner,
    _extract_api_key,
    _get_header,
    _validate_project_path,
    create_server,
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def tmp_project(tmp_path):
    """Create a temporary project directory."""
    project = tmp_path / "test_project"
    project.mkdir()
    return project


@pytest.fixture
def checker(tmp_project):
    """Create an EUAIActChecker for the temp project."""
    return EUAIActChecker(str(tmp_project))


@pytest.fixture
def mcp_server():
    """Create an MCPServer (legacy interface)."""
    return MCPServer()


@pytest.fixture
def rate_limiter():
    """Create a fresh RateLimiter with low limit for testing."""
    return RateLimiter(max_requests=3)


# ============================================================
# 1. Scan Endpoint — Valid Response & Framework Detection
# ============================================================

class TestScanEndpoint:
    """Tests for scan_project: valid responses and framework detection."""

    def test_scan_empty_project(self, checker):
        """Scanning an empty project returns zeroed results."""
        results = checker.scan_project()
        assert results["files_scanned"] == 0
        assert results["ai_files"] == []
        assert results["detected_models"] == {}

    def test_scan_detects_openai(self, tmp_project):
        """OpenAI usage is detected in Python source."""
        (tmp_project / "main.py").write_text(
            "import openai\nresponse = openai.ChatCompletion.create(model='gpt-4')"
        )
        checker = EUAIActChecker(str(tmp_project))
        results = checker.scan_project()
        assert results["files_scanned"] == 1
        assert "openai" in results["detected_models"]
        assert len(results["ai_files"]) == 1
        assert results["ai_files"][0]["file"] == "main.py"
        assert "openai" in results["ai_files"][0]["frameworks"]

    def test_scan_detects_anthropic(self, tmp_project):
        """Anthropic usage is detected."""
        (tmp_project / "ai.py").write_text(
            "from anthropic import Anthropic\nclient = Anthropic()\n"
            "msg = client.messages.create(model='claude-sonnet')"
        )
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "anthropic" in results["detected_models"]

    def test_scan_detects_huggingface(self, tmp_project):
        """HuggingFace transformers are detected."""
        (tmp_project / "ml.py").write_text("from transformers import AutoModel, AutoTokenizer")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "huggingface" in results["detected_models"]

    def test_scan_detects_pytorch(self, tmp_project):
        """PyTorch is detected."""
        (tmp_project / "model.py").write_text("import torch\nclass Net(torch.nn.Module): pass")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "pytorch" in results["detected_models"]

    def test_scan_detects_tensorflow(self, tmp_project):
        """TensorFlow is detected."""
        (tmp_project / "train.py").write_text("import tensorflow as tf\nmodel = tf.keras.Sequential()")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "tensorflow" in results["detected_models"]

    def test_scan_detects_langchain(self, tmp_project):
        """LangChain is detected."""
        (tmp_project / "chain.py").write_text("from langchain import LLMChain")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "langchain" in results["detected_models"]

    def test_scan_detects_gemini(self, tmp_project):
        """Google Gemini is detected in source and config."""
        (tmp_project / "app.py").write_text(
            "from google.generativeai import GenerativeModel\nmodel = GenerativeModel('gemini-1.5-flash')"
        )
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "gemini" in results["detected_models"]

    def test_scan_detects_mistral(self, tmp_project):
        """Mistral is detected."""
        (tmp_project / "app.py").write_text("from mistralai import Mistral\nclient = Mistral(api_key='xxx')")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "mistral" in results["detected_models"]

    def test_scan_detects_cohere(self, tmp_project):
        """Cohere is detected."""
        (tmp_project / "app.py").write_text("import cohere\nco = cohere.Client('xxx')")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "cohere" in results["detected_models"]

    def test_scan_detects_aws_bedrock(self, tmp_project):
        """AWS Bedrock is detected."""
        (tmp_project / "app.py").write_text('client = boto3.client("bedrock-runtime")\nclient.invoke_model(body=b"{}")')
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "aws_bedrock" in results["detected_models"]

    def test_scan_detects_azure_openai(self, tmp_project):
        """Azure OpenAI is detected."""
        (tmp_project / "app.py").write_text("from openai import AzureOpenAI\nclient = AzureOpenAI()")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "azure_openai" in results["detected_models"]

    def test_scan_detects_ollama(self, tmp_project):
        """Ollama is detected."""
        (tmp_project / "app.py").write_text("import ollama\nollama.chat(model='llama2')")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "ollama" in results["detected_models"]

    def test_scan_detects_llamaindex(self, tmp_project):
        """LlamaIndex is detected."""
        (tmp_project / "app.py").write_text("from llama_index.core import VectorStoreIndex")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "llamaindex" in results["detected_models"]

    def test_scan_detects_replicate(self, tmp_project):
        """Replicate is detected."""
        (tmp_project / "app.py").write_text("import replicate\nreplicate.run('meta/llama-2-70b')")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "replicate" in results["detected_models"]

    def test_scan_detects_groq(self, tmp_project):
        """Groq is detected."""
        (tmp_project / "app.py").write_text("from groq import Groq\nclient = Groq()")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "groq" in results["detected_models"]

    def test_scan_multiple_frameworks(self, tmp_project):
        """Multiple frameworks are detected across files."""
        (tmp_project / "a.py").write_text("import openai")
        (tmp_project / "b.py").write_text("from anthropic import Anthropic")
        (tmp_project / "c.py").write_text("from transformers import AutoModel")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert results["files_scanned"] == 3
        assert "openai" in results["detected_models"]
        assert "anthropic" in results["detected_models"]
        assert "huggingface" in results["detected_models"]
        assert len(results["ai_files"]) == 3

    def test_scan_recursive_subdirectories(self, tmp_project):
        """Scan finds files in nested subdirectories."""
        deep = tmp_project / "src" / "models" / "deep"
        deep.mkdir(parents=True)
        (deep / "model.py").write_text("import torch")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "pytorch" in results["detected_models"]

    def test_scan_all_code_extensions(self, tmp_project):
        """All supported code extensions are scanned."""
        extensions = [".py", ".js", ".ts", ".java", ".go", ".rs", ".cpp", ".c"]
        for ext in extensions:
            (tmp_project / f"file{ext}").write_text("import openai")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert results["files_scanned"] == len(extensions)

    def test_scan_ignores_non_code_files(self, tmp_project):
        """Non-code files are not scanned."""
        (tmp_project / "data.json").write_text('{"import": "openai"}')
        (tmp_project / "readme.txt").write_text("import openai")
        (tmp_project / "image.png").write_bytes(b"\x89PNG")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert results["files_scanned"] == 0
        assert results["ai_files"] == []

    def test_scan_config_requirements_txt(self, tmp_project):
        """Dependencies in requirements.txt are detected."""
        (tmp_project / "requirements.txt").write_text("openai>=1.0.0\ntorch>=2.0\nmistralai>=0.1.0\n")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "openai" in results["detected_models"]
        assert "pytorch" in results["detected_models"]
        assert "mistral" in results["detected_models"]

    def test_scan_config_package_json(self, tmp_project):
        """Dependencies in package.json are detected."""
        (tmp_project / "package.json").write_text(
            '{"dependencies": {"@mistralai/client": "^1.0", "@google/generative-ai": "^0.5"}}'
        )
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "mistral" in results["detected_models"]
        assert "gemini" in results["detected_models"]

    def test_scan_config_bare_package_name(self, tmp_project):
        """Bare package names (no version specifier) are detected."""
        (tmp_project / "requirements.txt").write_text("azure-ai-openai\n")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert "azure_openai" in results["detected_models"]

    def test_scan_config_file_adds_source_key(self, tmp_project):
        """Config-detected frameworks include source='config' in ai_files."""
        (tmp_project / "requirements.txt").write_text("openai>=1.0.0\n")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        config_files = [f for f in results["ai_files"] if f.get("source") == "config"]
        assert len(config_files) == 1

    def test_scan_binary_file_no_crash(self, tmp_project):
        """Binary files with code extension don't crash the scanner."""
        (tmp_project / "binary.py").write_bytes(b"\x00\x01\x02\x03\xff\xfe")
        results = EUAIActChecker(str(tmp_project)).scan_project()
        assert results["files_scanned"] == 1


# ============================================================
# 2. Rate Limiting — Rejection After Quota
# ============================================================

class TestRateLimiter:
    """Tests for the IP rate limiter."""

    def test_allows_under_limit(self, rate_limiter):
        """First request under limit is allowed."""
        allowed, remaining = rate_limiter.check("1.2.3.4")
        assert allowed is True
        assert remaining == 2

    def test_blocks_after_limit_exceeded(self, rate_limiter):
        """Request is blocked once limit is reached."""
        for _ in range(3):
            rate_limiter.check("1.2.3.4")
        allowed, remaining = rate_limiter.check("1.2.3.4")
        assert allowed is False
        assert remaining == 0

    def test_remaining_decrements_correctly(self):
        """Remaining count decrements with each call."""
        rl = RateLimiter(max_requests=5)
        _, r1 = rl.check("10.0.0.1")
        _, r2 = rl.check("10.0.0.1")
        _, r3 = rl.check("10.0.0.1")
        assert r1 == 4
        assert r2 == 3
        assert r3 == 2

    def test_separate_ips_independent(self, rate_limiter):
        """Different IPs have independent counters."""
        for _ in range(3):
            rate_limiter.check("1.1.1.1")
        blocked, _ = rate_limiter.check("1.1.1.1")
        assert blocked is False
        allowed, remaining = rate_limiter.check("2.2.2.2")
        assert allowed is True
        assert remaining == 2

    def test_resets_after_date_change(self):
        """Counter resets when the UTC date changes."""
        rl = RateLimiter(max_requests=1)
        rl.check("5.5.5.5")
        # Simulate yesterday's date to trigger reset
        rl._clients["5.5.5.5"]["date"] = "2020-01-01"
        allowed, remaining = rl.check("5.5.5.5")
        assert allowed is True
        assert remaining == 0

    def test_default_limit_matches_constant(self):
        """Default limit matches FREE_TIER_DAILY_LIMIT."""
        rl = RateLimiter()
        assert rl.max_requests == FREE_TIER_DAILY_LIMIT
        assert rl.max_requests == 10

    def test_cleanup_removes_expired_entries(self):
        """Cleanup removes expired entries, keeps active ones."""
        rl = RateLimiter(max_requests=5)
        rl.check("old.ip")
        rl._clients["old.ip"]["date"] = "2020-01-01"
        rl.check("new.ip")
        rl.cleanup()
        assert "old.ip" not in rl._clients
        assert "new.ip" in rl._clients

    def test_exact_limit_boundary(self):
        """The Nth request (at exactly the limit) is allowed; N+1 is blocked."""
        rl = RateLimiter(max_requests=2)
        a1, r1 = rl.check("x")
        a2, r2 = rl.check("x")
        a3, r3 = rl.check("x")
        assert a1 is True and r1 == 1
        assert a2 is True and r2 == 0
        assert a3 is False and r3 == 0

    def test_single_request_limit(self):
        """Rate limiter works with max_requests=1."""
        rl = RateLimiter(max_requests=1)
        allowed, remaining = rl.check("once")
        assert allowed is True
        assert remaining == 0
        blocked, _ = rl.check("once")
        assert blocked is False


# ============================================================
# 3. Error Handling — Invalid Input
# ============================================================

class TestErrorHandling:
    """Tests for error handling with invalid inputs."""

    def test_scan_nonexistent_path(self):
        """Scanning a non-existent path returns an error."""
        results = EUAIActChecker("/non/existent/path").scan_project()
        assert "error" in results
        assert "does not exist" in results["error"]

    def test_compliance_invalid_risk_category(self, checker):
        """Invalid risk category returns an error with valid list."""
        results = checker.check_compliance("bogus_category")
        assert "error" in results
        assert "Invalid risk category" in results["error"]
        assert "bogus_category" in results["error"]

    def test_legacy_server_unknown_tool(self, mcp_server):
        """Unknown tool name returns an error."""
        result = mcp_server.handle_request("nonexistent_tool", {})
        assert "error" in result
        assert "Unknown tool" in result["error"]
        assert "available_tools" in result

    def test_legacy_server_missing_param(self, mcp_server):
        """Missing required parameter causes an error."""
        result = mcp_server.handle_request("scan_project", {"wrong_param": "value"})
        assert "error" in result
        assert "Error executing" in result["error"]

    def test_scan_permission_denied_file(self, tmp_project):
        """Unreadable file is handled gracefully (no crash, no detection)."""
        f = tmp_project / "secret.py"
        f.write_text("import openai")
        os.chmod(str(f), 0o000)
        try:
            results = EUAIActChecker(str(tmp_project)).scan_project()
            assert results["files_scanned"] == 1
            assert len(results["ai_files"]) == 0
        finally:
            os.chmod(str(f), 0o644)

    def test_compliance_templates_unacceptable_risk(self):
        """Requesting templates for unacceptable risk returns an error."""
        server = MCPServer()
        result = server.handle_request("generate_compliance_templates", {"risk_category": "unacceptable"})
        assert "error" in result

    def test_compliance_unacceptable_risk_empty_status(self, tmp_project):
        """Unacceptable risk has empty compliance_status (prohibited)."""
        checker = EUAIActChecker(str(tmp_project))
        results = checker.check_compliance("unacceptable")
        assert results["risk_category"] == "unacceptable"
        assert len(results["compliance_status"]) == 0


# ============================================================
# 4. Path Validation / Security
# ============================================================

class TestPathValidation:
    """Tests for _validate_project_path security checks."""

    @pytest.mark.parametrize("blocked_path", [
        "/etc", "/etc/passwd", "/root", "/root/.ssh",
        "/home", "/home/ubuntu", "/proc", "/sys",
    ])
    def test_blocked_paths_denied(self, blocked_path):
        """Sensitive system paths are blocked."""
        is_safe, error_msg = _validate_project_path(blocked_path)
        assert is_safe is False
        assert "Access denied" in error_msg

    def test_valid_tmp_path_allowed(self, tmp_project):
        """Valid temp paths are allowed."""
        is_safe, error_msg = _validate_project_path(str(tmp_project))
        assert is_safe is True
        assert error_msg == ""

    def test_scan_blocked_path_returns_error(self):
        """Scanning a blocked path returns error, not results."""
        checker = EUAIActChecker("/etc")
        results = checker.scan_project()
        assert "error" in results
        assert "Access denied" in results["error"]
        assert results["detected_models"] == {}


# ============================================================
# 5. Compliance Checks
# ============================================================

class TestComplianceChecks:
    """Tests for check_compliance across risk categories."""

    def test_limited_risk_with_readme(self, tmp_project):
        """Limited risk: README with AI keyword passes transparency + disclosure."""
        (tmp_project / "README.md").write_text("# Project\nThis uses AI and machine learning.")
        checker = EUAIActChecker(str(tmp_project))
        results = checker.check_compliance("limited")
        assert results["risk_category"] == "limited"
        assert results["compliance_status"]["transparency"] is True
        assert results["compliance_status"]["user_disclosure"] is True
        assert "compliance_score" in results
        assert "compliance_percentage" in results

    def test_limited_risk_without_readme(self, tmp_project):
        """Limited risk without README fails transparency checks."""
        checker = EUAIActChecker(str(tmp_project))
        results = checker.check_compliance("limited")
        assert results["compliance_status"]["transparency"] is False
        assert results["compliance_status"]["user_disclosure"] is False
        assert results["compliance_percentage"] == 0.0

    def test_high_risk_full_compliance(self, tmp_project):
        """High risk with all docs passes 100%."""
        (tmp_project / "README.md").write_text("# Project")
        (tmp_project / "RISK_MANAGEMENT.md").write_text("# Risk")
        (tmp_project / "TRANSPARENCY.md").write_text("# Transparency")
        (tmp_project / "DATA_GOVERNANCE.md").write_text("# Data")
        (tmp_project / "HUMAN_OVERSIGHT.md").write_text("# Human")
        (tmp_project / "ROBUSTNESS.md").write_text("# Robustness")
        checker = EUAIActChecker(str(tmp_project))
        results = checker.check_compliance("high")
        assert all(results["compliance_status"].values())
        assert results["compliance_percentage"] == 100.0
        assert results["compliance_score"] == "6/6"

    def test_high_risk_missing_docs(self, tmp_project):
        """High risk without docs fails checks."""
        checker = EUAIActChecker(str(tmp_project))
        results = checker.check_compliance("high")
        assert results["compliance_status"]["risk_management"] is False
        assert results["compliance_status"]["data_governance"] is False
        assert results["compliance_percentage"] < 100

    def test_minimal_risk_with_readme(self, tmp_project):
        """Minimal risk: README present passes basic_documentation."""
        (tmp_project / "README.md").write_text("# Basic project")
        checker = EUAIActChecker(str(tmp_project))
        results = checker.check_compliance("minimal")
        assert results["risk_category"] == "minimal"
        assert results["compliance_status"]["basic_documentation"] is True

    def test_docs_in_docs_directory(self, tmp_project):
        """Files in docs/ subdirectory are found by _check_file_exists."""
        (tmp_project / "docs").mkdir()
        (tmp_project / "docs" / "RISK_MANAGEMENT.md").write_text("# Risk")
        checker = EUAIActChecker(str(tmp_project))
        assert checker._check_file_exists("RISK_MANAGEMENT.md") is True

    def test_technical_docs_check(self, tmp_project):
        """_check_technical_docs detects README.md or docs/ dir."""
        checker = EUAIActChecker(str(tmp_project))
        assert checker._check_technical_docs() is False
        (tmp_project / "README.md").write_text("# Docs")
        assert checker._check_technical_docs() is True

    def test_ai_disclosure_various_keywords(self, tmp_project):
        """AI disclosure detects various AI-related keywords."""
        keywords = ["ai", "artificial intelligence", "machine learning",
                     "deep learning", "gpt", "claude", "llm"]
        for kw in keywords:
            (tmp_project / "README.md").write_text(f"# Project using {kw}")
            checker = EUAIActChecker(str(tmp_project))
            assert checker._check_ai_disclosure(), f"Failed for keyword: {kw}"

    def test_content_marking_detection(self, tmp_project):
        """Content marking detects AI-generated labels."""
        (tmp_project / "gen.py").write_text("# This code is generated by AI\ndef f(): pass")
        checker = EUAIActChecker(str(tmp_project))
        assert checker._check_content_marking() is True

    def test_content_marking_french(self, tmp_project):
        """French content marking is detected."""
        (tmp_project / "output.py").write_text("# Contenu généré par IA\ndef g(): pass")
        checker = EUAIActChecker(str(tmp_project))
        assert checker._check_content_marking() is True


# ============================================================
# 6. Report Generation
# ============================================================

class TestReportGeneration:
    """Tests for generate_report."""

    def test_report_structure(self, tmp_project):
        """Report contains all required sections."""
        (tmp_project / "main.py").write_text("import openai")
        (tmp_project / "README.md").write_text("# AI Project using AI")
        checker = EUAIActChecker(str(tmp_project))
        scan = checker.scan_project()
        compliance = checker.check_compliance("limited")
        report = checker.generate_report(scan, compliance)
        assert "report_date" in report
        assert "project_path" in report
        assert "scan_summary" in report
        assert "compliance_summary" in report
        assert "detailed_findings" in report
        assert "recommendations" in report

    def test_report_scan_summary(self, tmp_project):
        """Report scan_summary reflects actual scan results."""
        (tmp_project / "main.py").write_text("import openai")
        checker = EUAIActChecker(str(tmp_project))
        scan = checker.scan_project()
        compliance = checker.check_compliance("limited")
        report = checker.generate_report(scan, compliance)
        assert report["scan_summary"]["files_scanned"] == 1
        assert "openai" in report["scan_summary"]["frameworks_detected"]

    def test_recommendations_pass_fail(self, tmp_project):
        """Recommendations include PASS and FAIL entries."""
        checker = EUAIActChecker(str(tmp_project))
        compliance_pass = {
            "risk_category": "limited",
            "compliance_status": {"transparency": True, "user_disclosure": False},
        }
        recs = checker._generate_recommendations(compliance_pass)
        statuses = [r["status"] for r in recs]
        assert "PASS" in statuses
        assert "FAIL" in statuses

    def test_recommendations_high_risk_includes_db_registration(self, tmp_project):
        """High risk recommendations include EU database registration."""
        checker = EUAIActChecker(str(tmp_project))
        compliance = {
            "risk_category": "high",
            "compliance_status": {"risk_management": False, "technical_documentation": True},
        }
        recs = checker._generate_recommendations(compliance)
        assert any(r.get("check") == "eu_database_registration" for r in recs)

    def test_recommendations_fail_has_guidance(self, tmp_project):
        """FAIL recommendations include actionable guidance fields."""
        checker = EUAIActChecker(str(tmp_project))
        compliance = {
            "risk_category": "limited",
            "compliance_status": {"transparency": False},
        }
        recs = checker._generate_recommendations(compliance)
        fail = next(r for r in recs if r["status"] == "FAIL")
        assert "what" in fail
        assert "why" in fail
        assert "how" in fail
        assert isinstance(fail["how"], list)


# ============================================================
# 7. Risk Category Suggestion
# ============================================================

class TestSuggestRiskCategory:
    """Tests for suggest_risk_category logic."""

    def test_chatbot_suggests_limited(self, mcp_server):
        """'chatbot' maps to limited risk."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "chatbot for customer support"}
        )
        assert result["results"]["suggested_category"] == "limited"

    def test_recruitment_suggests_high(self, mcp_server):
        """'recruitment' maps to high risk."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "AI tool for recruitment and hiring"}
        )
        assert result["results"]["suggested_category"] == "high"

    def test_social_scoring_suggests_unacceptable(self, mcp_server):
        """'social scoring' maps to unacceptable risk."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "social scoring system for citizens"}
        )
        assert result["results"]["suggested_category"] == "unacceptable"

    def test_spam_filter_suggests_minimal(self, mcp_server):
        """'spam filter' maps to minimal risk."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "spam filter for email"}
        )
        assert result["results"]["suggested_category"] == "minimal"

    def test_no_match_defaults_limited(self, mcp_server):
        """Unrecognized description defaults to limited with low confidence."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "a generic software tool"}
        )
        assert result["results"]["suggested_category"] == "limited"
        assert result["results"]["confidence"] == "low"

    def test_multiple_keywords_high_confidence(self, mcp_server):
        """Multiple keyword matches yield high confidence."""
        result = mcp_server.handle_request(
            "suggest_risk_category",
            {"system_description": "AI for recruitment, hiring, and credit scoring"},
        )
        assert result["results"]["confidence"] == "high"

    def test_relevant_articles_present(self, mcp_server):
        """suggest_risk_category includes relevant_articles field."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "AI tool for recruitment"}
        )
        assert "relevant_articles" in result["results"]
        assert isinstance(result["results"]["relevant_articles"], list)

    def test_relevant_articles_high_risk_recruitment(self, mcp_server):
        """Recruitment keyword maps to Annex III(4)(a)."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "AI tool for recruitment"}
        )
        articles = result["results"]["relevant_articles"]
        assert "Annex III(4)(a)" in articles

    def test_relevant_articles_unacceptable_social_scoring(self, mcp_server):
        """Social scoring maps to Art. 5(1)(c)."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "social scoring system"}
        )
        articles = result["results"]["relevant_articles"]
        assert "Art. 5(1)(c)" in articles

    def test_relevant_articles_limited_chatbot(self, mcp_server):
        """Chatbot maps to Art. 52(1)."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "chatbot for customer support"}
        )
        articles = result["results"]["relevant_articles"]
        assert "Art. 52(1)" in articles

    def test_relevant_articles_empty_for_no_match(self, mcp_server):
        """No keyword match → empty relevant_articles list."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "a generic software tool"}
        )
        assert result["results"]["relevant_articles"] == []

    def test_all_matches_enriched_with_article(self, mcp_server):
        """all_matches entries include article and description fields."""
        result = mcp_server.handle_request(
            "suggest_risk_category", {"system_description": "AI tool for recruitment and hiring"}
        )
        high_matches = result["results"]["all_matches"].get("high", {})
        assert "matched_keywords" in high_matches
        for entry in high_matches["matched_keywords"]:
            assert "keyword" in entry
            # Keywords with known article mappings should have article field
            if entry["keyword"] in ("recruitment", "hiring"):
                assert "article" in entry
                assert entry["article"] == "Annex III(4)(a)"

    def test_relevant_articles_sorted_art5_before_annex(self, mcp_server):
        """Art. 5 articles appear before Annex III in sorted relevant_articles."""
        # social scoring (Art. 5) + biometric (Annex III)
        result = mcp_server.handle_request(
            "suggest_risk_category",
            {"system_description": "social scoring system using biometric identification real-time"},
        )
        articles = result["results"]["relevant_articles"]
        if "Art. 5(1)(c)" in articles and "Art. 5(1)(h)" in articles:
            idx_5c = articles.index("Art. 5(1)(c)")
            idx_5h = articles.index("Art. 5(1)(h)")
            annex_indices = [i for i, a in enumerate(articles) if a.startswith("Annex")]
            for annex_idx in annex_indices:
                assert idx_5c < annex_idx
                assert idx_5h < annex_idx


# ============================================================
# 8. API Key Manager
# ============================================================

class TestApiKeyManager:
    """Tests for ApiKeyManager."""

    def test_verify_nonexistent_key(self, tmp_path):
        """Non-existent key returns None."""
        fake_path = tmp_path / "no_keys.json"
        mgr = ApiKeyManager(path=fake_path, data_path=tmp_path / "no_data.json")
        assert mgr.verify("nonexistent_key") is None

    def test_verify_valid_key_list_format(self, tmp_path):
        """Valid key in list format is accepted."""
        keys_file = tmp_path / "api_keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key": "test_key_123", "email": "test@example.com", "active": True, "plan": "pro"}]
        }))
        mgr = ApiKeyManager(path=keys_file, data_path=tmp_path / "no.json")
        result = mgr.verify("test_key_123")
        assert result is not None
        assert result["plan"] == "pro"
        assert result["email"] == "test@example.com"

    def test_verify_valid_key_dict_format(self, tmp_path):
        """Valid key in dict format is accepted."""
        data_file = tmp_path / "data_keys.json"
        data_file.write_text(json.dumps({
            "mcp_pro_abc": {"email": "pro@test.com", "active": True, "tier": "pro"}
        }))
        mgr = ApiKeyManager(path=tmp_path / "no.json", data_path=data_file)
        result = mgr.verify("mcp_pro_abc")
        assert result is not None
        assert result["plan"] == "pro"

    def test_verify_inactive_key_rejected(self, tmp_path):
        """Inactive key is rejected."""
        keys_file = tmp_path / "api_keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key": "inactive_key", "email": "x@y.com", "active": False, "plan": "pro"}]
        }))
        mgr = ApiKeyManager(path=keys_file, data_path=tmp_path / "no.json")
        assert mgr.verify("inactive_key") is None

    def test_get_entry_returns_full_data(self, tmp_path):
        """get_entry returns the full entry for a key."""
        keys_file = tmp_path / "api_keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key": "k1", "email": "e@e.com", "active": True, "plan": "pro", "scans_total": 42}]
        }))
        mgr = ApiKeyManager(path=keys_file, data_path=tmp_path / "no.json")
        entry = mgr.get_entry("k1")
        assert entry["scans_total"] == 42

    def test_get_entry_unknown_key_empty_dict(self, tmp_path):
        """get_entry for unknown key returns empty dict."""
        mgr = ApiKeyManager(path=tmp_path / "no.json", data_path=tmp_path / "no2.json")
        assert mgr.get_entry("unknown") == {}

    def test_corrupt_json_handled(self, tmp_path):
        """Corrupt JSON file is handled gracefully."""
        bad_file = tmp_path / "api_keys.json"
        bad_file.write_text("{invalid json")
        mgr = ApiKeyManager(path=bad_file, data_path=tmp_path / "no.json")
        assert mgr.verify("anything") is None


# ============================================================
# 9. Header / API Key Extraction Helpers
# ============================================================

class TestHeaderHelpers:
    """Tests for _get_header and _extract_api_key."""

    def test_get_header_found(self):
        """_get_header extracts an existing header."""
        scope = {"headers": [(b"content-type", b"application/json"), (b"x-api-key", b"my_key")]}
        assert _get_header(scope, b"x-api-key") == "my_key"

    def test_get_header_missing(self):
        """_get_header returns None for missing header."""
        scope = {"headers": [(b"content-type", b"application/json")]}
        assert _get_header(scope, b"x-api-key") is None

    def test_get_header_no_headers(self):
        """_get_header returns None if no headers key."""
        assert _get_header({}, b"x-api-key") is None

    def test_extract_api_key_from_header(self):
        """_extract_api_key finds key in X-API-Key header."""
        scope = {"headers": [(b"x-api-key", b"key123")]}
        assert _extract_api_key(scope) == "key123"

    def test_extract_api_key_from_bearer(self):
        """_extract_api_key finds key in Authorization: Bearer header."""
        scope = {"headers": [(b"authorization", b"Bearer token456")]}
        assert _extract_api_key(scope) == "token456"

    def test_extract_api_key_prefers_x_api_key(self):
        """_extract_api_key prefers X-API-Key over Bearer."""
        scope = {"headers": [
            (b"x-api-key", b"preferred"),
            (b"authorization", b"Bearer fallback"),
        ]}
        assert _extract_api_key(scope) == "preferred"

    def test_extract_api_key_no_key(self):
        """_extract_api_key returns None when no key present."""
        scope = {"headers": [(b"content-type", b"text/html")]}
        assert _extract_api_key(scope) is None


# ============================================================
# 10. Banner, Constants & create_server
# ============================================================

class TestMiscellaneous:
    """Tests for _add_banner, constants, and create_server."""

    def test_add_banner(self):
        """_add_banner adds the upgrade key."""
        result = _add_banner({"data": 1})
        assert "upgrade" in result
        assert "Pro" in result["upgrade"]
        assert result["data"] == 1

    def test_all_16_frameworks_in_patterns(self):
        """All 16 expected frameworks exist in both pattern dicts."""
        expected = [
            "openai", "anthropic", "huggingface", "tensorflow", "pytorch", "langchain",
            "gemini", "vertex_ai", "mistral", "cohere", "aws_bedrock", "azure_openai",
            "ollama", "llamaindex", "replicate", "groq",
        ]
        for fw in expected:
            assert fw in AI_MODEL_PATTERNS, f"Missing in AI_MODEL_PATTERNS: {fw}"
            assert fw in CONFIG_DEPENDENCY_PATTERNS, f"Missing in CONFIG_DEPENDENCY_PATTERNS: {fw}"

    def test_risk_categories_complete(self):
        """All 4 risk categories are defined with required fields."""
        for cat in ["unacceptable", "high", "limited", "minimal"]:
            assert cat in RISK_CATEGORIES
            assert "description" in RISK_CATEGORIES[cat]
            assert "requirements" in RISK_CATEGORIES[cat]
            assert len(RISK_CATEGORIES[cat]["requirements"]) > 0

    def test_compliance_templates_have_content(self):
        """Each compliance template has filename and content."""
        for key, tmpl in COMPLIANCE_TEMPLATES.items():
            assert "filename" in tmpl
            assert "content" in tmpl
            assert tmpl["filename"].endswith(".md")
            assert len(tmpl["content"]) > 100

    def test_actionable_guidance_keys(self):
        """Actionable guidance has required fields for each check."""
        for key, guidance in ACTIONABLE_GUIDANCE.items():
            assert "what" in guidance
            assert "why" in guidance
            assert "how" in guidance
            assert isinstance(guidance["how"], list)

    def test_create_server_returns_mcp(self):
        """create_server() returns a FastMCP instance."""
        mcp = create_server()
        assert mcp is not None

    def test_create_server_has_expected_tools(self):
        """All expected MCP tools are registered."""
        mcp = create_server()
        tool_names = list(mcp._tool_manager._tools.keys())
        expected = [
            "scan_project", "check_compliance", "generate_report",
            "suggest_risk_category", "generate_compliance_templates",
            "validate_api_key",
            "gdpr_scan_project", "gdpr_check_compliance",
            "gdpr_generate_report", "gdpr_generate_templates",
        ]
        for name in expected:
            assert name in tool_names, f"Missing MCP tool: {name}"

    def test_legacy_server_list_tools(self, mcp_server):
        """Legacy server lists all 5 tools."""
        result = mcp_server.list_tools()
        assert len(result["tools"]) == 5
        names = [t["name"] for t in result["tools"]]
        assert "scan_project" in names
        assert "generate_report" in names

    def test_legacy_server_scan_project(self, mcp_server, tmp_project):
        """Legacy server scan_project returns correct structure."""
        (tmp_project / "test.py").write_text("import torch")
        result = mcp_server.handle_request("scan_project", {"project_path": str(tmp_project)})
        assert result["tool"] == "scan_project"
        assert "pytorch" in result["results"]["detected_models"]

    def test_legacy_server_generate_report(self, mcp_server, tmp_project):
        """Legacy server generate_report returns a dated report."""
        result = mcp_server.handle_request(
            "generate_report", {"project_path": str(tmp_project), "risk_category": "limited"}
        )
        assert "report_date" in result["results"]

    def test_legacy_server_generate_templates(self, mcp_server):
        """Legacy server generate_compliance_templates returns templates."""
        result = mcp_server.handle_request("generate_compliance_templates", {"risk_category": "high"})
        assert result["results"]["templates_count"] == 6


# ============================================================
# 11. RateLimitMiddleware — ASGI Tests
# ============================================================

class TestRateLimitMiddleware:
    """Tests for the ASGI RateLimitMiddleware."""

    @pytest.fixture
    def captured_responses(self):
        """Capture ASGI send() calls."""
        responses = []

        async def send(message):
            responses.append(message)

        return responses, send

    @staticmethod
    def _make_scope(path="/mcp", method="POST", headers=None, client=("127.0.0.1", 12345), scope_type="http"):
        """Helper to build an ASGI scope dict."""
        return {
            "type": scope_type,
            "path": path,
            "method": method,
            "headers": headers or [],
            "client": client,
        }

    @staticmethod
    def _make_receive(body: bytes):
        """Helper to build an ASGI receive callable that returns body."""
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        return receive

    @staticmethod
    def _make_receive_chunked(chunks: list[bytes]):
        """Helper for multi-chunk body."""
        idx = 0

        async def receive():
            nonlocal idx
            if idx < len(chunks):
                chunk = chunks[idx]
                idx += 1
                more = idx < len(chunks)
                return {"type": "http.request", "body": chunk, "more_body": more}
            return {"type": "http.request", "body": b"", "more_body": False}

        return receive

    @pytest.mark.asyncio
    async def test_non_http_scope_passthrough(self):
        """Non-HTTP scopes (websocket, lifespan) pass through to wrapped app."""
        called_with = {}

        async def mock_app(scope, receive, send):
            called_with["scope"] = scope

        middleware = RateLimitMiddleware(mock_app)
        scope = {"type": "websocket", "path": "/ws"}
        await middleware(scope, None, None)
        assert called_with["scope"]["type"] == "websocket"

    @pytest.mark.asyncio
    async def test_get_request_passthrough(self):
        """GET requests pass through without rate limiting."""
        received_body = {}

        async def mock_app(scope, receive, send):
            received_body["called"] = True

        middleware = RateLimitMiddleware(mock_app)
        scope = self._make_scope(method="GET")
        async def noop_send(msg):
            pass

        await middleware(scope, self._make_receive(b""), noop_send)
        assert received_body["called"] is True

    @pytest.mark.asyncio
    async def test_verify_key_valid(self, tmp_path, captured_responses):
        """POST /api/verify-key with valid key returns 200."""
        responses, send = captured_responses
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key": "valid_key_1", "email": "user@test.com", "active": True, "plan": "pro"}]
        }))

        import server as srv
        original_mgr = srv._api_key_manager
        srv._api_key_manager = ApiKeyManager(path=keys_file, data_path=tmp_path / "no.json")
        try:
            middleware = RateLimitMiddleware(None)
            scope = self._make_scope(path="/api/verify-key", method="POST")
            body = json.dumps({"key": "valid_key_1"}).encode()
            await middleware(scope, self._make_receive(body), send)

            assert responses[0]["status"] == 200
            resp_body = json.loads(responses[1]["body"])
            assert resp_body["valid"] is True
            assert resp_body["plan"] == "pro"
        finally:
            srv._api_key_manager = original_mgr

    @pytest.mark.asyncio
    async def test_verify_key_invalid(self, captured_responses):
        """POST /api/verify-key with invalid key returns 401."""
        responses, send = captured_responses
        middleware = RateLimitMiddleware(None)
        scope = self._make_scope(path="/api/verify-key", method="POST")
        body = json.dumps({"key": "bad_key"}).encode()
        await middleware(scope, self._make_receive(body), send)

        assert responses[0]["status"] == 401
        resp_body = json.loads(responses[1]["body"])
        assert resp_body["valid"] is False

    @pytest.mark.asyncio
    async def test_verify_key_bad_json(self, captured_responses):
        """POST /api/verify-key with invalid JSON returns 400."""
        responses, send = captured_responses
        middleware = RateLimitMiddleware(None)
        scope = self._make_scope(path="/api/verify-key", method="POST")
        await middleware(scope, self._make_receive(b"not json{"), send)

        assert responses[0]["status"] == 400
        resp_body = json.loads(responses[1]["body"])
        assert resp_body["valid"] is False

    @pytest.mark.asyncio
    async def test_tools_call_rate_limited(self, captured_responses):
        """tools/call requests are rate limited per IP."""
        responses, send = captured_responses
        rl = RateLimiter(max_requests=1)
        rl._clients.clear()  # Avoid persistence pollution from prior tests

        import server as srv
        original_rl = srv._rate_limiter
        srv._rate_limiter = rl
        try:
            async def mock_app(scope, receive, send):
                pass

            middleware = RateLimitMiddleware(mock_app)
            body = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": 1}).encode()

            # First call — allowed (passes through to mock_app)
            scope1 = self._make_scope(client=("10.0.0.1", 5000))
            await middleware(scope1, self._make_receive(body), send)
            assert len(responses) == 0  # passed through to mock_app

            # Second call — blocked (429)
            responses_list = []

            async def send2(msg):
                responses_list.append(msg)

            scope2 = self._make_scope(client=("10.0.0.1", 5001))
            await middleware(scope2, self._make_receive(body), send2)
            assert responses_list[0]["status"] == 429
            resp_body = json.loads(responses_list[1]["body"])
            assert resp_body["error"]["code"] == -32000
            # Verify rate limit headers are present
            headers = dict(responses_list[0]["headers"])
            assert b"x-ratelimit-remaining" in headers
            assert b"x-ratelimit-reset" in headers
        finally:
            srv._rate_limiter = original_rl

    @pytest.mark.asyncio
    async def test_pro_key_bypasses_rate_limit(self, tmp_path):
        """Pro API key bypasses rate limiting on tools/call."""
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key": "pro_key_bypass", "email": "pro@x.com", "active": True, "plan": "pro"}]
        }))

        import server as srv
        original_mgr = srv._api_key_manager
        original_rl = srv._rate_limiter
        srv._api_key_manager = ApiKeyManager(path=keys_file, data_path=tmp_path / "no.json")
        srv._rate_limiter = RateLimiter(max_requests=0)  # Block all free tier
        try:
            app_called = {"count": 0, "body": None}

            async def mock_app(scope, receive, send):
                app_called["count"] += 1
                msg = await receive()
                app_called["body"] = msg.get("body")

            middleware = RateLimitMiddleware(mock_app)
            body = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": 5}).encode()
            scope = self._make_scope(headers=[(b"x-api-key", b"pro_key_bypass")])
            async def noop_send(msg):
                pass

            await middleware(scope, self._make_receive(body), noop_send)

            assert app_called["count"] == 1
            assert app_called["body"] == body  # body replayed correctly
        finally:
            srv._api_key_manager = original_mgr
            srv._rate_limiter = original_rl

    @pytest.mark.asyncio
    async def test_ip_from_x_forwarded_for_uses_last(self):
        """IP is extracted from last entry in X-Forwarded-For (closest proxy)."""
        import server as srv
        original_rl = srv._rate_limiter
        rl = RateLimiter(max_requests=1)
        rl._clients.clear()  # Avoid persistence pollution from prior tests
        srv._rate_limiter = rl
        try:
            async def mock_app(scope, receive, send):
                pass

            middleware = RateLimitMiddleware(mock_app)
            body = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": 1}).encode()
            scope = self._make_scope(
                headers=[(b"x-forwarded-for", b"203.0.113.50, 10.0.0.1")],
                client=("127.0.0.1", 5000),
            )

            async def noop_send(msg):
                pass

            await middleware(scope, self._make_receive(body), noop_send)

            # Last XFF entry (10.0.0.1) is the real IP appended by the trusted proxy
            # First entry (203.0.113.50) is client-controlled and must NOT be trusted
            assert "10.0.0.1" in rl._clients
            assert "203.0.113.50" not in rl._clients
            assert "127.0.0.1" not in rl._clients
        finally:
            srv._rate_limiter = original_rl

    @pytest.mark.asyncio
    async def test_ip_from_x_real_ip_preferred(self):
        """X-Real-IP takes priority over X-Forwarded-For."""
        import server as srv
        original_rl = srv._rate_limiter
        rl = RateLimiter(max_requests=1)
        rl._clients.clear()  # Avoid persistence pollution from prior tests
        srv._rate_limiter = rl
        try:
            async def mock_app(scope, receive, send):
                pass

            middleware = RateLimitMiddleware(mock_app)
            body = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": 1}).encode()
            scope = self._make_scope(
                headers=[
                    (b"x-real-ip", b"198.51.100.42"),
                    (b"x-forwarded-for", b"203.0.113.50, 10.0.0.1"),
                ],
                client=("127.0.0.1", 5000),
            )

            async def noop_send(msg):
                pass

            await middleware(scope, self._make_receive(body), noop_send)

            # X-Real-IP should be preferred over XFF
            assert "198.51.100.42" in rl._clients
            assert "10.0.0.1" not in rl._clients
            assert "203.0.113.50" not in rl._clients
        finally:
            srv._rate_limiter = original_rl

    @pytest.mark.asyncio
    async def test_non_tools_call_post_passthrough(self):
        """POST requests that are not tools/call pass through without rate limiting."""
        app_called = {"count": 0}

        async def mock_app(scope, receive, send):
            app_called["count"] += 1

        import server as srv
        original_rl = srv._rate_limiter
        srv._rate_limiter = RateLimiter(max_requests=0)  # Block all
        try:
            middleware = RateLimitMiddleware(mock_app)
            body = json.dumps({"jsonrpc": "2.0", "method": "initialize", "id": 1}).encode()
            scope = self._make_scope()
            async def noop_send(msg):
                pass

            await middleware(scope, self._make_receive(body), noop_send)
            assert app_called["count"] == 1
        finally:
            srv._rate_limiter = original_rl

    @pytest.mark.asyncio
    async def test_body_replay_preserves_content(self):
        """Buffered body is correctly replayed to the inner app."""
        received_bodies = []

        async def mock_app(scope, receive, send):
            msg = await receive()
            received_bodies.append(msg["body"])
            msg2 = await receive()
            received_bodies.append(msg2["body"])

        middleware = RateLimitMiddleware(mock_app)
        original_body = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": 99, "params": {"name": "scan_project"}}).encode()
        scope = self._make_scope(client=("192.168.1.1", 5000))
        async def noop_send(msg):
            pass

        await middleware(scope, self._make_receive(original_body), noop_send)

        assert received_bodies[0] == original_body
        assert received_bodies[1] == b""  # second read returns empty

    @pytest.mark.asyncio
    async def test_verify_key_chunked_body(self, captured_responses):
        """verify-key endpoint handles multi-chunk body."""
        responses, send = captured_responses
        middleware = RateLimitMiddleware(None)
        scope = self._make_scope(path="/api/verify-key", method="POST")
        chunks = [b'{"ke', b'y": "test_key"}']
        await middleware(scope, self._make_receive_chunked(chunks), send)

        assert responses[0]["status"] == 401  # key doesn't exist but JSON parsed OK
        resp_body = json.loads(responses[1]["body"])
        assert resp_body["valid"] is False
        assert "Invalid or inactive" in resp_body["error"]

    @pytest.mark.asyncio
    async def test_json_response_format(self, captured_responses):
        """_json_response sends correct headers and body."""
        responses, send = captured_responses
        middleware = RateLimitMiddleware(None)
        await middleware._json_response(send, 200, {"test": True})

        assert responses[0]["type"] == "http.response.start"
        assert responses[0]["status"] == 200
        headers = dict(responses[0]["headers"])
        assert headers[b"content-type"] == b"application/json"
        assert responses[1]["type"] == "http.response.body"
        assert json.loads(responses[1]["body"]) == {"test": True}


# ============================================================
# 12. MCP Tool Wrappers (create_server)
# ============================================================

class TestMCPToolWrappers:
    """Tests for MCP tools registered via create_server()."""

    @pytest.fixture
    def mcp(self):
        return create_server()

    def _call_tool(self, mcp, name, arguments):
        """Call a FastMCP tool function directly via the tool manager."""
        tool = mcp._tool_manager._tools[name]
        fn = tool.fn
        # For enum parameters defined inside create_server() closure (e.g. ProcessingRole),
        # resolve string values to enum instances using the function's default values.
        if fn.__defaults__:
            import inspect
            params = list(inspect.signature(fn).parameters.values())
            defaults_offset = len(params) - len(fn.__defaults__)
            for i, default in enumerate(fn.__defaults__):
                param = params[defaults_offset + i]
                if param.name in arguments and isinstance(arguments[param.name], str) and hasattr(default, "__class__") and issubclass(type(default), Enum):
                    enum_cls = type(default)
                    arguments[param.name] = enum_cls(arguments[param.name])
        return fn(**arguments)

    def test_scan_project_tool(self, mcp, tmp_project):
        """scan_project MCP tool returns results with banner."""
        (tmp_project / "app.py").write_text("import openai")
        result = self._call_tool(mcp, "scan_project", {"project_path": str(tmp_project)})
        assert "openai" in result["detected_models"]
        assert "upgrade" in result  # banner added

    def test_scan_project_blocked_path(self, mcp):
        """scan_project rejects blocked paths."""
        result = self._call_tool(mcp, "scan_project", {"project_path": "/etc/passwd"})
        assert "error" in result
        assert "Access denied" in result["error"]

    def test_check_compliance_tool(self, mcp, tmp_project):
        """check_compliance MCP tool returns compliance with banner."""
        (tmp_project / "README.md").write_text("# AI project using machine learning")
        from server import RiskCategory
        result = self._call_tool(mcp, "check_compliance", {
            "project_path": str(tmp_project),
            "risk_category": RiskCategory.limited,
        })
        assert result["risk_category"] == "limited"
        assert "compliance_score" in result
        assert "upgrade" in result

    def test_check_compliance_blocked_path(self, mcp):
        """check_compliance rejects blocked paths."""
        from server import RiskCategory
        result = self._call_tool(mcp, "check_compliance", {
            "project_path": "/root",
            "risk_category": RiskCategory.limited,
        })
        assert "error" in result

    def test_generate_report_tool(self, mcp, tmp_project):
        """generate_report MCP tool returns full report with banner."""
        (tmp_project / "main.py").write_text("import torch")
        (tmp_project / "README.md").write_text("# Test")
        from server import RiskCategory
        result = self._call_tool(mcp, "generate_report", {
            "project_path": str(tmp_project),
            "risk_category": RiskCategory.limited,
        })
        assert "report_date" in result
        assert "recommendations" in result
        assert "upgrade" in result

    def test_suggest_risk_category_tool(self, mcp):
        """suggest_risk_category MCP tool returns suggestion with banner."""
        result = self._call_tool(mcp, "suggest_risk_category", {
            "system_description": "chatbot for customer support"
        })
        assert result["suggested_category"] == "limited"
        assert "upgrade" in result

    def test_generate_compliance_templates_tool(self, mcp):
        """generate_compliance_templates MCP tool returns templates."""
        from server import RiskCategory
        result = self._call_tool(mcp, "generate_compliance_templates", {
            "risk_category": RiskCategory.high,
        })
        assert result["templates_count"] == 6
        assert "risk_management" in result["templates"]

    def test_generate_compliance_templates_unacceptable(self, mcp):
        """Unacceptable risk returns prohibition error."""
        from server import RiskCategory
        result = self._call_tool(mcp, "generate_compliance_templates", {
            "risk_category": RiskCategory.unacceptable,
        })
        assert "error" in result

    def test_validate_api_key_invalid(self, mcp):
        """validate_api_key with invalid key returns not valid."""
        result = self._call_tool(mcp, "validate_api_key", {"api_key": "bogus_key"})
        assert result["valid"] is False

    def test_validate_api_key_valid(self, mcp, tmp_path):
        """validate_api_key with valid key returns tier and usage."""
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key": "test_val_key", "email": "v@t.com", "active": True, "plan": "pro", "scans_total": 10}]
        }))
        import server as srv
        original_mgr = srv._api_key_manager
        srv._api_key_manager = ApiKeyManager(path=keys_file, data_path=tmp_path / "no.json")
        try:
            result = self._call_tool(mcp, "validate_api_key", {"api_key": "test_val_key"})
            assert result["valid"] is True
            assert result["tier"] == "pro"
            assert result["usage"]["scans_total"] == 10
        finally:
            srv._api_key_manager = original_mgr

    def test_gdpr_scan_project_tool(self, mcp, tmp_project):
        """gdpr_scan_project MCP tool works and adds banner."""
        (tmp_project / "app.py").write_text("email = user.email\nname = user.first_name")
        result = self._call_tool(mcp, "gdpr_scan_project", {"project_path": str(tmp_project)})
        assert "upgrade" in result

    def test_gdpr_scan_blocked_path(self, mcp):
        """gdpr_scan_project rejects blocked paths."""
        result = self._call_tool(mcp, "gdpr_scan_project", {"project_path": "/etc"})
        assert "error" in result

    def test_gdpr_check_compliance_tool(self, mcp, tmp_project):
        """gdpr_check_compliance MCP tool returns compliance."""
        result = self._call_tool(mcp, "gdpr_check_compliance", {
            "project_path": str(tmp_project),
            "processing_role": "controller",
        })
        assert "upgrade" in result

    def test_gdpr_generate_report_tool(self, mcp, tmp_project):
        """gdpr_generate_report MCP tool returns report."""
        result = self._call_tool(mcp, "gdpr_generate_report", {
            "project_path": str(tmp_project),
            "processing_role": "controller",
        })
        assert "upgrade" in result

    def test_gdpr_generate_templates_tool(self, mcp):
        """gdpr_generate_templates MCP tool returns templates."""
        result = self._call_tool(mcp, "gdpr_generate_templates", {
            "processing_role": "controller",
        })
        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
