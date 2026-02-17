#!/usr/bin/env python3
"""
Unit tests for the MCP EU AI Act Compliance Checker server
"""

import os
import sys
import json
from pathlib import Path

from server import MCPServer, EUAIActChecker, RISK_CATEGORIES


def test_server_initialization():
    """Test server initialization"""
    print("TEST 1: Server Initialization")
    server = MCPServer()
    assert server is not None
    assert len(server.tools) == 3
    assert "scan_project" in server.tools
    assert "check_compliance" in server.tools
    assert "generate_report" in server.tools
    print("  OK Server initialized correctly")


def test_list_tools():
    """Test tool listing"""
    print("\nTEST 2: List Tools")
    server = MCPServer()
    tools = server.list_tools()
    assert "tools" in tools
    assert len(tools["tools"]) == 3

    tool_names = [t["name"] for t in tools["tools"]]
    assert "scan_project" in tool_names
    assert "check_compliance" in tool_names
    assert "generate_report" in tool_names
    print("  OK All tools listed correctly")


def test_risk_categories():
    """Test risk categories"""
    print("\nTEST 3: Risk Categories")
    expected_categories = ["unacceptable", "high", "limited", "minimal"]

    for category in expected_categories:
        assert category in RISK_CATEGORIES
        assert "description" in RISK_CATEGORIES[category]
        assert "requirements" in RISK_CATEGORIES[category]

    print("  OK All risk categories defined correctly")


def test_scan_project():
    """Test project scanning"""
    print("\nTEST 4: Scan Project")

    test_dir = Path("/tmp/test-scan-project")
    test_dir.mkdir(exist_ok=True)

    openai_file = test_dir / "openai_code.py"
    openai_file.write_text("""
import openai
client = openai.ChatCompletion()
""")

    anthropic_file = test_dir / "anthropic_code.py"
    anthropic_file.write_text("""
from anthropic import Anthropic
client = Anthropic()
""")

    checker = EUAIActChecker(str(test_dir))
    results = checker.scan_project()

    assert results["files_scanned"] == 2
    assert len(results["ai_files"]) == 2
    assert "openai" in results["detected_models"]
    assert "anthropic" in results["detected_models"]

    print(f"  OK Scanned {results['files_scanned']} files")
    print(f"  OK Detected frameworks: {', '.join(results['detected_models'].keys())}")


def test_check_compliance():
    """Test compliance checking"""
    print("\nTEST 5: Check Compliance")

    test_dir = Path("/tmp/test-compliance")
    test_dir.mkdir(exist_ok=True)

    readme = test_dir / "README.md"
    readme.write_text("# Test Project\nThis project uses AI models.")

    py_file = test_dir / "main.py"
    py_file.write_text("import anthropic")

    checker = EUAIActChecker(str(test_dir))
    checker.scan_project()
    compliance = checker.check_compliance("limited")

    assert compliance["risk_category"] == "limited"
    assert "compliance_status" in compliance
    assert "compliance_score" in compliance
    assert compliance["compliance_percentage"] >= 0

    print(f"  OK Compliance checked for 'limited' risk")
    print(f"  OK Score: {compliance['compliance_score']} ({compliance['compliance_percentage']}%)")


def test_generate_report():
    """Test report generation"""
    print("\nTEST 6: Generate Report")

    test_dir = Path("/tmp/test-report")
    test_dir.mkdir(exist_ok=True)

    (test_dir / "README.md").write_text("# AI Project")
    (test_dir / "code.py").write_text("from anthropic import Anthropic")

    checker = EUAIActChecker(str(test_dir))
    scan_results = checker.scan_project()
    compliance_results = checker.check_compliance("limited")
    report = checker.generate_report(scan_results, compliance_results)

    assert "report_date" in report
    assert "project_path" in report
    assert "scan_summary" in report
    assert "compliance_summary" in report
    assert "detailed_findings" in report
    assert "recommendations" in report

    print("  OK Report generated successfully")
    print("  OK Report contains all required sections")


def test_mcp_server_handle_request():
    """Test MCP request handling"""
    print("\nTEST 7: MCP Server Handle Request")

    server = MCPServer()
    test_dir = Path("/tmp/test-mcp-request")
    test_dir.mkdir(exist_ok=True)
    (test_dir / "test.py").write_text("import openai")

    result = server.handle_request("scan_project", {"project_path": str(test_dir)})
    assert "tool" in result
    assert result["tool"] == "scan_project"
    assert "results" in result

    result = server.handle_request("check_compliance", {
        "project_path": str(test_dir),
        "risk_category": "minimal"
    })
    assert result["tool"] == "check_compliance"
    assert result["results"]["risk_category"] == "minimal"

    result = server.handle_request("generate_report", {
        "project_path": str(test_dir),
        "risk_category": "limited"
    })
    assert result["tool"] == "generate_report"
    assert "report_date" in result["results"]

    print("  OK All MCP requests handled correctly")


def test_invalid_tool():
    """Test invalid tool handling"""
    print("\nTEST 8: Invalid Tool Handling")

    server = MCPServer()
    result = server.handle_request("invalid_tool", {})

    assert "error" in result
    assert "Unknown tool" in result["error"]
    assert "available_tools" in result

    print("  OK Invalid tool handled correctly")


def test_invalid_risk_category():
    """Test invalid risk category handling"""
    print("\nTEST 9: Invalid Risk Category")

    test_dir = Path("/tmp/test-invalid-risk")
    test_dir.mkdir(exist_ok=True)

    checker = EUAIActChecker(str(test_dir))
    result = checker.check_compliance("invalid_category")

    assert "error" in result
    assert "Invalid risk category" in result["error"]

    print("  OK Invalid risk category handled correctly")


def test_nonexistent_project():
    """Test with non-existent project"""
    print("\nTEST 10: Nonexistent Project")

    checker = EUAIActChecker("/nonexistent/path/to/project")
    result = checker.scan_project()

    assert "error" in result
    assert "does not exist" in result["error"]

    print("  OK Nonexistent project handled correctly")


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("EU AI Act Compliance Checker - Unit Tests")
    print("=" * 60)

    tests = [
        test_server_initialization,
        test_list_tools,
        test_risk_categories,
        test_scan_project,
        test_check_compliance,
        test_generate_report,
        test_mcp_server_handle_request,
        test_invalid_tool,
        test_invalid_risk_category,
        test_nonexistent_project,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed == 0:
        print("ALL TESTS PASSED!")
        return 0
    else:
        print(f"{failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
