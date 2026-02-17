#!/usr/bin/env python3
"""Test JSON response format"""

import json
from server import MCPServer

def test_json_response_format():
    """Verify JSON response format is correct"""
    print("Testing JSON response format...")

    server = MCPServer()

    # Test 1: scan_project
    result = server.handle_request("scan_project", {
        "project_path": "/tmp/test-eu-ai-act"
    })

    print("\n1. scan_project response:")
    print(json.dumps(result, indent=2))
    assert "tool" in result
    assert "results" in result
    print("OK Valid JSON format")

    # Test 2: check_compliance
    result = server.handle_request("check_compliance", {
        "project_path": "/tmp/test-eu-ai-act",
        "risk_category": "limited"
    })

    print("\n2. check_compliance response:")
    print(json.dumps(result, indent=2))
    assert "tool" in result
    assert "results" in result
    print("OK Valid JSON format")

    # Test 3: generate_report
    result = server.handle_request("generate_report", {
        "project_path": "/tmp/test-eu-ai-act",
        "risk_category": "limited"
    })

    print("\n3. generate_report response:")
    print(f"Keys: {list(result.keys())}")
    print(f"Tool: {result.get('tool')}")
    print(f"Results keys: {list(result.get('results', {}).keys())}")
    assert "tool" in result
    assert "results" in result
    print("OK Valid JSON format")

    print("\nOK All JSON formats are compliant")

if __name__ == "__main__":
    test_json_response_format()
