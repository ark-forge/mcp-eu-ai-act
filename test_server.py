#!/usr/bin/env python3
"""
Tests unitaires pour le serveur MCP EU AI Act Compliance Checker
"""

import os
import sys
import json
from pathlib import Path

# Import du serveur
from server import MCPServer, EUAIActChecker, RISK_CATEGORIES


def test_server_initialization():
    """Test de l'initialisation du serveur"""
    print("TEST 1: Server Initialization")
    server = MCPServer()
    assert server is not None
    assert len(server.tools) == 3
    assert "scan_project" in server.tools
    assert "check_compliance" in server.tools
    assert "generate_report" in server.tools
    print("  ✅ Server initialized correctly")


def test_list_tools():
    """Test de la liste des tools"""
    print("\nTEST 2: List Tools")
    server = MCPServer()
    tools = server.list_tools()
    assert "tools" in tools
    assert len(tools["tools"]) == 3

    tool_names = [t["name"] for t in tools["tools"]]
    assert "scan_project" in tool_names
    assert "check_compliance" in tool_names
    assert "generate_report" in tool_names
    print("  ✅ All tools listed correctly")


def test_risk_categories():
    """Test des catégories de risque"""
    print("\nTEST 3: Risk Categories")
    expected_categories = ["unacceptable", "high", "limited", "minimal"]

    for category in expected_categories:
        assert category in RISK_CATEGORIES
        assert "description" in RISK_CATEGORIES[category]
        assert "requirements" in RISK_CATEGORIES[category]

    print("  ✅ All risk categories defined correctly")


def test_scan_project():
    """Test du scan d'un projet"""
    print("\nTEST 4: Scan Project")

    # Créer un projet de test
    test_dir = Path("/tmp/test-scan-project")
    test_dir.mkdir(exist_ok=True)

    # Fichier avec code OpenAI
    openai_file = test_dir / "openai_code.py"
    openai_file.write_text("""
import openai
client = openai.ChatCompletion()
""")

    # Fichier avec code Anthropic
    anthropic_file = test_dir / "anthropic_code.py"
    anthropic_file.write_text("""
from anthropic import Anthropic
client = Anthropic()
""")

    # Scanner
    checker = EUAIActChecker(str(test_dir))
    results = checker.scan_project()

    assert results["files_scanned"] == 2
    assert len(results["ai_files"]) == 2
    assert "openai" in results["detected_models"]
    assert "anthropic" in results["detected_models"]

    print(f"  ✅ Scanned {results['files_scanned']} files")
    print(f"  ✅ Detected frameworks: {', '.join(results['detected_models'].keys())}")


def test_check_compliance():
    """Test de la vérification de conformité"""
    print("\nTEST 5: Check Compliance")

    test_dir = Path("/tmp/test-compliance")
    test_dir.mkdir(exist_ok=True)

    # Créer README
    readme = test_dir / "README.md"
    readme.write_text("# Test Project\nThis project uses AI models.")

    # Créer un fichier Python
    py_file = test_dir / "main.py"
    py_file.write_text("import anthropic")

    # Tester risque limité
    checker = EUAIActChecker(str(test_dir))
    checker.scan_project()
    compliance = checker.check_compliance("limited")

    assert compliance["risk_category"] == "limited"
    assert "compliance_status" in compliance
    assert "compliance_score" in compliance
    assert compliance["compliance_percentage"] >= 0

    print(f"  ✅ Compliance checked for 'limited' risk")
    print(f"  ✅ Score: {compliance['compliance_score']} ({compliance['compliance_percentage']}%)")


def test_generate_report():
    """Test de génération de rapport"""
    print("\nTEST 6: Generate Report")

    test_dir = Path("/tmp/test-report")
    test_dir.mkdir(exist_ok=True)

    # Créer des fichiers de test
    (test_dir / "README.md").write_text("# AI Project")
    (test_dir / "code.py").write_text("from anthropic import Anthropic")

    # Générer rapport
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

    print("  ✅ Report generated successfully")
    print(f"  ✅ Report contains all required sections")


def test_mcp_server_handle_request():
    """Test de gestion des requêtes MCP"""
    print("\nTEST 7: MCP Server Handle Request")

    server = MCPServer()
    test_dir = Path("/tmp/test-mcp-request")
    test_dir.mkdir(exist_ok=True)
    (test_dir / "test.py").write_text("import openai")

    # Test scan_project
    result = server.handle_request("scan_project", {"project_path": str(test_dir)})
    assert "tool" in result
    assert result["tool"] == "scan_project"
    assert "results" in result

    # Test check_compliance
    result = server.handle_request("check_compliance", {
        "project_path": str(test_dir),
        "risk_category": "minimal"
    })
    assert result["tool"] == "check_compliance"
    assert result["results"]["risk_category"] == "minimal"

    # Test generate_report
    result = server.handle_request("generate_report", {
        "project_path": str(test_dir),
        "risk_category": "limited"
    })
    assert result["tool"] == "generate_report"
    assert "report_date" in result["results"]

    print("  ✅ All MCP requests handled correctly")


def test_invalid_tool():
    """Test de gestion d'un tool invalide"""
    print("\nTEST 8: Invalid Tool Handling")

    server = MCPServer()
    result = server.handle_request("invalid_tool", {})

    assert "error" in result
    assert "Unknown tool" in result["error"]
    assert "available_tools" in result

    print("  ✅ Invalid tool handled correctly")


def test_invalid_risk_category():
    """Test de gestion d'une catégorie de risque invalide"""
    print("\nTEST 9: Invalid Risk Category")

    test_dir = Path("/tmp/test-invalid-risk")
    test_dir.mkdir(exist_ok=True)

    checker = EUAIActChecker(str(test_dir))
    result = checker.check_compliance("invalid_category")

    assert "error" in result
    assert "Invalid risk category" in result["error"]

    print("  ✅ Invalid risk category handled correctly")


def test_nonexistent_project():
    """Test avec un projet inexistant"""
    print("\nTEST 10: Nonexistent Project")

    checker = EUAIActChecker("/nonexistent/path/to/project")
    result = checker.scan_project()

    assert "error" in result
    assert "does not exist" in result["error"]

    print("  ✅ Nonexistent project handled correctly")


def run_all_tests():
    """Exécute tous les tests"""
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
            print(f"  ❌ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ❌ ERROR: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed == 0:
        print("✅ ALL TESTS PASSED!")
        return 0
    else:
        print(f"❌ {failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
