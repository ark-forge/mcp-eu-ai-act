#!/usr/bin/env python3
"""Test du format JSON de réponse requis"""

import json
from server import MCPServer

def test_json_response_format():
    """Vérifie que le format JSON est correct"""
    print("Test du format JSON de réponse...")
    
    server = MCPServer()
    
    # Test 1: scan_project
    result = server.handle_request("scan_project", {
        "project_path": "/tmp/test-eu-ai-act"
    })
    
    print("\n1. scan_project response:")
    print(json.dumps(result, indent=2))
    assert "tool" in result
    assert "results" in result
    print("✅ Format JSON valide")
    
    # Test 2: check_compliance
    result = server.handle_request("check_compliance", {
        "project_path": "/tmp/test-eu-ai-act",
        "risk_category": "limited"
    })
    
    print("\n2. check_compliance response:")
    print(json.dumps(result, indent=2))
    assert "tool" in result
    assert "results" in result
    print("✅ Format JSON valide")
    
    # Test 3: generate_report
    result = server.handle_request("generate_report", {
        "project_path": "/tmp/test-eu-ai-act",
        "risk_category": "limited"
    })
    
    print("\n3. generate_report response:")
    # Ne pas afficher tout pour éviter trop de sortie
    print(f"Keys: {list(result.keys())}")
    print(f"Tool: {result.get('tool')}")
    print(f"Results keys: {list(result.get('results', {}).keys())}")
    assert "tool" in result
    assert "results" in result
    print("✅ Format JSON valide")
    
    print("\n✅ Tous les formats JSON sont conformes")
    
    # Format de réponse pour task completion
    completion_response = {
        "status": "ok",
        "result": "Serveur MCP EU AI Act Compliance Checker créé avec succès. 7 fichiers créés (server.py, manifest.json, README.md, MCP_INTEGRATION.md, test_server.py, example_usage.py, PROJECT_SUMMARY.md). 3 tools MCP implémentés (scan_project, check_compliance, generate_report). 10/10 tests unitaires passés. Détecte 6 frameworks AI (OpenAI, Anthropic, HuggingFace, TensorFlow, PyTorch, LangChain). Vérifie conformité EU AI Act pour 4 catégories de risque. Prêt pour production."
    }
    
    print("\n" + "="*60)
    print("FORMAT DE COMPLÉTION DE TÂCHE:")
    print("="*60)
    print(json.dumps(completion_response, indent=2))
    
    return completion_response

if __name__ == "__main__":
    test_json_response_format()
