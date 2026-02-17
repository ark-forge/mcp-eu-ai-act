#!/usr/bin/env python3
"""
Usage examples for the MCP EU AI Act Compliance Checker server
"""

from server import MCPServer
import json

def main():
    # Initialize the server
    server = MCPServer()

    print("=" * 60)
    print("EU AI Act Compliance Checker - Examples")
    print("=" * 60)

    # 1. List available tools
    print("\n1. LIST AVAILABLE TOOLS")
    print("-" * 60)
    tools = server.list_tools()
    for tool in tools["tools"]:
        print(f"\n  {tool['name']}")
        print(f"   {tool['description']}")

    # 2. Scan a project
    print("\n\n2. SCAN PROJECT")
    print("-" * 60)
    scan_result = server.handle_request("scan_project", {
        "project_path": "/tmp/test-eu-ai-act"
    })
    print(f"Files scanned: {scan_result['results']['files_scanned']}")
    print(f"AI files detected: {len(scan_result['results']['ai_files'])}")
    print(f"Frameworks: {', '.join(scan_result['results']['detected_models'].keys())}")

    # 3. Check compliance (limited risk)
    print("\n\n3. CHECK COMPLIANCE (Limited Risk)")
    print("-" * 60)
    compliance_result = server.handle_request("check_compliance", {
        "project_path": "/tmp/test-eu-ai-act",
        "risk_category": "limited"
    })
    print(f"Risk Category: {compliance_result['results']['risk_category']}")
    print(f"Compliance Score: {compliance_result['results']['compliance_score']}")
    print(f"Compliance: {compliance_result['results']['compliance_percentage']}%")
    print("\nCompliance Checks:")
    for check, passed in compliance_result['results']['compliance_status'].items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {check}")

    # 4. Check compliance (high risk)
    print("\n\n4. CHECK COMPLIANCE (High Risk)")
    print("-" * 60)
    high_risk_result = server.handle_request("check_compliance", {
        "project_path": "/tmp/test-eu-ai-act",
        "risk_category": "high"
    })
    print(f"Risk Category: {high_risk_result['results']['risk_category']}")
    print(f"Compliance Score: {high_risk_result['results']['compliance_score']}")
    print(f"Compliance: {high_risk_result['results']['compliance_percentage']}%")
    print("\nCompliance Checks:")
    for check, passed in high_risk_result['results']['compliance_status'].items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {check}")

    # 5. Generate a full report
    print("\n\n5. GENERATE FULL REPORT")
    print("-" * 60)
    report = server.handle_request("generate_report", {
        "project_path": "/tmp/test-eu-ai-act",
        "risk_category": "limited"
    })
    print(f"Report Date: {report['results']['report_date']}")
    print(f"Project: {report['results']['project_path']}")
    print("\nRecommendations:")
    for rec in report['results']['recommendations']:
        print(f"  {rec}")

    # Save the full report
    report_path = "/tmp/eu-ai-act-report.json"
    with open(report_path, 'w') as f:
        json.dump(report['results'], f, indent=2)
    print(f"\nFull report saved to: {report_path}")

    print("\n" + "=" * 60)
    print("Examples completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
