#!/usr/bin/env python3
"""
Exemples d'utilisation du serveur MCP EU AI Act Compliance Checker
"""

from server import MCPServer
import json

def main():
    # Initialiser le serveur
    server = MCPServer()

    print("=" * 60)
    print("EU AI Act Compliance Checker - Examples")
    print("=" * 60)

    # 1. Lister les tools disponibles
    print("\n1. LIST AVAILABLE TOOLS")
    print("-" * 60)
    tools = server.list_tools()
    for tool in tools["tools"]:
        print(f"\n📦 {tool['name']}")
        print(f"   {tool['description']}")

    # 2. Scanner un projet
    print("\n\n2. SCAN PROJECT")
    print("-" * 60)
    scan_result = server.handle_request("scan_project", {
        "project_path": "/tmp/test-eu-ai-act"
    })
    print(f"Files scanned: {scan_result['results']['files_scanned']}")
    print(f"AI files detected: {len(scan_result['results']['ai_files'])}")
    print(f"Frameworks: {', '.join(scan_result['results']['detected_models'].keys())}")

    # 3. Vérifier la conformité (risque limité)
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
        status = "✅" if passed else "❌"
        print(f"  {status} {check}")

    # 4. Vérifier la conformité (risque élevé)
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
        status = "✅" if passed else "❌"
        print(f"  {status} {check}")

    # 5. Générer un rapport complet
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

    # Sauvegarder le rapport complet
    report_path = "/tmp/eu-ai-act-report.json"
    with open(report_path, 'w') as f:
        json.dump(report['results'], f, indent=2)
    print(f"\n📄 Full report saved to: {report_path}")

    print("\n" + "=" * 60)
    print("Examples completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
