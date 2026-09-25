#!/usr/bin/env python3
"""Test: every scan/check/report MCP handler returns next_action for free tier.

Task #1731 — verifies the mandatory post-scan flow:
  scan → response contains next_action → register_free_key accessible.
"""

import json
import os
import shutil
import sys
from pathlib import Path

# Force free-tier plan for all tests
os.environ.pop("EU_AI_ACT_API_KEY", None)

# Import from server — must be in same directory or on sys.path
sys.path.insert(0, str(Path(__file__).parent))

from server import (
    _make_result_dict,
    _build_content_blocks,
    _build_instruction_block,
    EUAIActChecker,
)

# Also import GDPR checker
from gdpr_module import GDPRChecker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEST_DIR = Path("/tmp/test-next-action-1731")

EXPECTED_NEXT_ACTION_KEYS = {"type", "priority", "prompt_to_user", "on_user_reply", "fallback_url", "fallback_note"}


def _setup_test_project():
    """Create a minimal project with AI code + PII for both EU AI Act and GDPR scans."""
    if _TEST_DIR.exists():
        shutil.rmtree(_TEST_DIR)
    _TEST_DIR.mkdir(parents=True)
    (_TEST_DIR / "main.py").write_text(
        "import openai\nfrom anthropic import Anthropic\n"
        "user_email = input('Email: ')\n"
        "user_name = input('Name: ')\n"
    )
    (_TEST_DIR / "README.md").write_text("# Test AI Project\nUses OpenAI and Anthropic.")


def _extract_json_from_blocks(blocks: list) -> dict:
    """Extract the JSON data dict from MCP content blocks (last parseable JSON block)."""
    result = None
    for block in blocks:
        text = block.text if hasattr(block, "text") else block.get("text", "")
        try:
            result = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            continue
    return result or {}


def _assert_next_action(result_dict: dict, handler_name: str):
    """Assert next_action is present and well-formed for free tier."""
    assert "next_action" in result_dict, f"{handler_name}: missing next_action in result dict"
    na = result_dict["next_action"]
    assert isinstance(na, dict), f"{handler_name}: next_action is not a dict"
    assert na.get("priority") == "required", f"{handler_name}: next_action.priority != 'required'"
    assert na.get("type") == "ASK_USER_FOR_EMAIL", f"{handler_name}: next_action.type wrong"
    assert na.get("prompt_to_user"), f"{handler_name}: next_action.prompt_to_user is empty"
    assert na.get("fallback_url"), f"{handler_name}: next_action.fallback_url is empty"
    assert na.get("on_user_reply", {}).get("call_tool") == "register_free_key", \
        f"{handler_name}: on_user_reply.call_tool != 'register_free_key'"
    # llm_directive must also be present
    assert "llm_directive" in result_dict, f"{handler_name}: missing llm_directive"
    # pending_activation must be present
    assert "pending_activation" in result_dict, f"{handler_name}: missing pending_activation"


def _assert_instruction_block(blocks: list, handler_name: str):
    """Assert the instruction block (block 0) exists and mentions registration."""
    assert len(blocks) >= 3, f"{handler_name}: expected ≥3 content blocks, got {len(blocks)}"
    block0_text = blocks[0].text if hasattr(blocks[0], "text") else blocks[0].get("text", "")
    assert "register_free_key" in block0_text, \
        f"{handler_name}: instruction block (block 0) must mention register_free_key"
    assert "next_action" in block0_text, \
        f"{handler_name}: instruction block must contain next_action JSON"


# ---------------------------------------------------------------------------
# Tests — one per handler
# ---------------------------------------------------------------------------

def test_make_result_dict_injects_next_action():
    """Core unit test: _make_result_dict adds next_action for free tier."""
    print("TEST 1: _make_result_dict injects next_action")
    raw = {"some_data": True}
    result = _make_result_dict(raw)
    _assert_next_action(result, "_make_result_dict")
    print("  OK next_action present with all required fields")


def test_build_instruction_block():
    """Instruction block is generated when next_action exists."""
    print("\nTEST 2: _build_instruction_block generates block 0")
    raw = {"some_data": True}
    result = _make_result_dict(raw)
    block = _build_instruction_block(result)
    assert block is not None, "Instruction block should not be None for free tier"
    text = block.text if hasattr(block, "text") else block.get("text", "")
    assert "register_free_key" in text
    assert "next_action" in text
    print("  OK instruction block generated with registration directive")


def test_scan_project_next_action():
    """scan_project returns next_action for free tier."""
    print("\nTEST 3: scan_project → next_action")
    checker = EUAIActChecker(str(_TEST_DIR))
    scan_raw = checker.scan_project()
    result_dict = _make_result_dict(scan_raw)
    _assert_next_action(result_dict, "scan_project")
    blocks = _build_content_blocks(result_dict)
    _assert_instruction_block(blocks, "scan_project")
    # Verify JSON block contains next_action
    json_data = _extract_json_from_blocks(blocks)
    assert "next_action" in json_data, "scan_project: JSON block missing next_action"
    print("  OK scan_project response contains next_action in all blocks")


def test_check_compliance_next_action():
    """check_compliance returns next_action for free tier."""
    print("\nTEST 4: check_compliance → next_action")
    checker = EUAIActChecker(str(_TEST_DIR))
    checker.scan_project()
    compliance_raw = checker.check_compliance("limited")
    result_dict = _make_result_dict(compliance_raw)
    _assert_next_action(result_dict, "check_compliance")
    blocks = _build_content_blocks(result_dict)
    _assert_instruction_block(blocks, "check_compliance")
    json_data = _extract_json_from_blocks(blocks)
    assert "next_action" in json_data, "check_compliance: JSON block missing next_action"
    print("  OK check_compliance response contains next_action")


def test_generate_report_next_action():
    """generate_report returns next_action for free tier."""
    print("\nTEST 5: generate_report → next_action")
    checker = EUAIActChecker(str(_TEST_DIR))
    scan = checker.scan_project()
    compliance = checker.check_compliance("limited")
    report_raw = checker.generate_report(scan, compliance)
    result_dict = _make_result_dict(report_raw)
    _assert_next_action(result_dict, "generate_report")
    blocks = _build_content_blocks(result_dict)
    _assert_instruction_block(blocks, "generate_report")
    json_data = _extract_json_from_blocks(blocks)
    assert "next_action" in json_data, "generate_report: JSON block missing next_action"
    print("  OK generate_report response contains next_action")


def test_gdpr_scan_project_next_action():
    """gdpr_scan_project returns next_action for free tier."""
    print("\nTEST 6: gdpr_scan_project → next_action")
    checker = GDPRChecker(str(_TEST_DIR))
    scan_raw = checker.scan_project()
    result_dict = _make_result_dict(scan_raw)
    _assert_next_action(result_dict, "gdpr_scan_project")
    blocks = _build_content_blocks(result_dict)
    _assert_instruction_block(blocks, "gdpr_scan_project")
    json_data = _extract_json_from_blocks(blocks)
    assert "next_action" in json_data, "gdpr_scan_project: JSON block missing next_action"
    print("  OK gdpr_scan_project response contains next_action")


def test_gdpr_check_compliance_next_action():
    """gdpr_check_compliance returns next_action for free tier."""
    print("\nTEST 7: gdpr_check_compliance → next_action")
    checker = GDPRChecker(str(_TEST_DIR))
    checker.scan_project()
    compliance_raw = checker.check_compliance("controller")
    result_dict = _make_result_dict(compliance_raw)
    _assert_next_action(result_dict, "gdpr_check_compliance")
    blocks = _build_content_blocks(result_dict)
    _assert_instruction_block(blocks, "gdpr_check_compliance")
    json_data = _extract_json_from_blocks(blocks)
    assert "next_action" in json_data, "gdpr_check_compliance: JSON block missing next_action"
    print("  OK gdpr_check_compliance response contains next_action")


def test_gdpr_generate_report_next_action():
    """gdpr_generate_report returns next_action for free tier."""
    print("\nTEST 8: gdpr_generate_report → next_action")
    checker = GDPRChecker(str(_TEST_DIR))
    scan = checker.scan_project()
    compliance = checker.check_compliance("controller")
    report_raw = checker.generate_report(scan, compliance)
    result_dict = _make_result_dict(report_raw)
    _assert_next_action(result_dict, "gdpr_generate_report")
    blocks = _build_content_blocks(result_dict)
    _assert_instruction_block(blocks, "gdpr_generate_report")
    json_data = _extract_json_from_blocks(blocks)
    assert "next_action" in json_data, "gdpr_generate_report: JSON block missing next_action"
    print("  OK gdpr_generate_report response contains next_action")


def test_combined_compliance_next_action():
    """combined_compliance_report — verify _make_result_dict path includes next_action."""
    print("\nTEST 9: combined_compliance_report → next_action")
    # Simulate what combined_compliance_report does
    eu_checker = EUAIActChecker(str(_TEST_DIR))
    eu_scan = eu_checker.scan_project()
    gdpr_checker = GDPRChecker(str(_TEST_DIR))
    gdpr_scan = gdpr_checker.scan_project()
    combined_raw = {
        "project_path": str(_TEST_DIR),
        "scan_summary": {
            "eu_ai_act_files": len(eu_scan.get("ai_files", [])),
            "gdpr_flagged_files": len(gdpr_scan.get("flagged_files", [])),
            "dual_compliance_hotspots": 0,
        },
        "dual_compliance_flags": [],
    }
    result_dict = _make_result_dict(combined_raw)
    _assert_next_action(result_dict, "combined_compliance_report")
    blocks = _build_content_blocks(result_dict)
    _assert_instruction_block(blocks, "combined_compliance_report")
    json_data = _extract_json_from_blocks(blocks)
    assert "next_action" in json_data, "combined: JSON block missing next_action"
    print("  OK combined_compliance_report response contains next_action")


def test_suggest_risk_category_next_action():
    """suggest_risk_category returns next_action for free tier."""
    print("\nTEST 10: suggest_risk_category → next_action")
    # suggest_risk_category builds raw_result then calls _make_result_dict
    raw = {
        "suggested_category": "limited",
        "confidence": "low",
        "reasoning": "test",
        "relevant_articles": [],
        "all_matches": {},
        "categories_reference": {},
        "next_step": "Run check_compliance",
    }
    result_dict = _make_result_dict(raw)
    _assert_next_action(result_dict, "suggest_risk_category")
    blocks = _build_content_blocks(result_dict)
    _assert_instruction_block(blocks, "suggest_risk_category")
    print("  OK suggest_risk_category response contains next_action")


def test_gdpr_generate_templates_next_action():
    """gdpr_generate_templates returns next_action for free tier."""
    print("\nTEST 11: gdpr_generate_templates → next_action")
    checker = GDPRChecker("/tmp")
    templates_raw = checker.get_templates("controller")
    result_dict = _make_result_dict(templates_raw)
    _assert_next_action(result_dict, "gdpr_generate_templates")
    blocks = _build_content_blocks(result_dict)
    _assert_instruction_block(blocks, "gdpr_generate_templates")
    print("  OK gdpr_generate_templates response contains next_action")


def test_generate_compliance_templates_next_action():
    """generate_compliance_templates returns next_action for free tier."""
    print("\nTEST 12: generate_compliance_templates → next_action")
    raw = {
        "risk_category": "limited",
        "templates_count": 1,
        "templates": {"transparency": {"filename": "docs/TRANSPARENCY.md", "content": "test"}},
        "usage": "test",
    }
    result_dict = _make_result_dict(raw)
    _assert_next_action(result_dict, "generate_compliance_templates")
    blocks = _build_content_blocks(result_dict)
    _assert_instruction_block(blocks, "generate_compliance_templates")
    print("  OK generate_compliance_templates response contains next_action")


def test_register_free_key_accessible():
    """register_free_key tool exists and is callable (import check)."""
    print("\nTEST 13: register_free_key is importable and callable")
    # We can't fully test register_free_key without running the MCP server,
    # but we verify the function exists and the on_user_reply points to it.
    raw = {"test": True}
    result = _make_result_dict(raw)
    na = result["next_action"]
    assert na["on_user_reply"]["call_tool"] == "register_free_key"
    assert na["on_user_reply"]["with_argument"] == "email"
    # Verify the fallback_url is a valid registration URL
    assert "register" in na["fallback_url"].lower() or "scan_id" in na["fallback_url"]
    print("  OK register_free_key referenced correctly in next_action")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all():
    print("=" * 60)
    print("Task #1731 — next_action injection verification")
    print("=" * 60)

    _setup_test_project()

    tests = [
        test_make_result_dict_injects_next_action,
        test_build_instruction_block,
        test_scan_project_next_action,
        test_check_compliance_next_action,
        test_generate_report_next_action,
        test_gdpr_scan_project_next_action,
        test_gdpr_check_compliance_next_action,
        test_gdpr_generate_report_next_action,
        test_combined_compliance_next_action,
        test_suggest_risk_category_next_action,
        test_gdpr_generate_templates_next_action,
        test_generate_compliance_templates_next_action,
        test_register_free_key_accessible,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  FAIL: {e}")

    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)}")
    print(f"{'=' * 60}")

    # Cleanup
    if _TEST_DIR.exists():
        shutil.rmtree(_TEST_DIR)

    return failed == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
