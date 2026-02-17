#!/usr/bin/env python3
"""
MCP Server: EU AI Act Compliance Checker
Scanne les projets pour détecter l'utilisation de modèles AI et vérifier la conformité EU AI Act
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

# Patterns pour détecter l'utilisation de modèles AI
AI_MODEL_PATTERNS = {
    "openai": [
        r"openai\.ChatCompletion",
        r"openai\.Completion",
        r"from openai import",
        r"import openai",
        r"gpt-3\.5",
        r"gpt-4",
        r"text-davinci",
    ],
    "anthropic": [
        r"from anthropic import",
        r"import anthropic",
        r"claude-",
        r"Anthropic\(\)",
        r"messages\.create",
    ],
    "huggingface": [
        r"from transformers import",
        r"AutoModel",
        r"AutoTokenizer",
        r"pipeline\(",
        r"huggingface_hub",
    ],
    "tensorflow": [
        r"import tensorflow",
        r"from tensorflow import",
        r"tf\.keras",
        r"\.h5$",  # model files
    ],
    "pytorch": [
        r"import torch",
        r"from torch import",
        r"nn\.Module",
        r"\.pt$",  # model files
        r"\.pth$",
    ],
    "langchain": [
        r"from langchain import",
        r"import langchain",
        r"LLMChain",
        r"ChatOpenAI",
    ],
}

# EU AI Act - Catégories de risque
RISK_CATEGORIES = {
    "unacceptable": {
        "description": "Systèmes interdits (manipulation, notation sociale, surveillance de masse)",
        "requirements": ["Système interdit - Ne pas déployer"],
    },
    "high": {
        "description": "Systèmes à haut risque (recrutement, crédit, application de la loi)",
        "requirements": [
            "Documentation technique complète",
            "Système de gestion des risques",
            "Qualité et gouvernance des données",
            "Transparence et information aux utilisateurs",
            "Surveillance humaine",
            "Robustesse, précision et cybersécurité",
            "Système de gestion de la qualité",
            "Enregistrement dans base de données UE",
        ],
    },
    "limited": {
        "description": "Systèmes à risque limité (chatbots, deepfakes)",
        "requirements": [
            "Obligations de transparence",
            "Information claire aux utilisateurs sur interaction avec AI",
            "Marquage du contenu généré par AI",
        ],
    },
    "minimal": {
        "description": "Systèmes à risque minimal (filtres spam, jeux vidéo)",
        "requirements": [
            "Aucune obligation spécifique",
            "Code de conduite volontaire encouragé",
        ],
    },
}


class EUAIActChecker:
    """Vérificateur de conformité EU AI Act"""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.detected_models = {}
        self.files_scanned = 0
        self.ai_files = []

    def scan_project(self) -> Dict[str, Any]:
        """Scanne le projet pour détecter l'utilisation de modèles AI"""
        print(f"Scanning project: {self.project_path}")

        if not self.project_path.exists():
            return {
                "error": f"Project path does not exist: {self.project_path}",
                "detected_models": {},
            }

        # Extensions de fichiers à scanner
        code_extensions = {".py", ".js", ".ts", ".java", ".go", ".rs", ".cpp", ".c"}

        for file_path in self.project_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in code_extensions:
                self._scan_file(file_path)

        return {
            "files_scanned": self.files_scanned,
            "ai_files": self.ai_files,
            "detected_models": self.detected_models,
        }

    def _scan_file(self, file_path: Path):
        """Scanne un fichier pour détecter des patterns AI"""
        self.files_scanned += 1
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            file_detections = []
            for framework, patterns in AI_MODEL_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        file_detections.append(framework)
                        if framework not in self.detected_models:
                            self.detected_models[framework] = []
                        self.detected_models[framework].append(str(file_path.relative_to(self.project_path)))
                        break  # Une seule détection par framework par fichier

            if file_detections:
                self.ai_files.append({
                    "file": str(file_path.relative_to(self.project_path)),
                    "frameworks": list(set(file_detections)),
                })

        except Exception as e:
            print(f"Error scanning {file_path}: {e}")

    def check_compliance(self, risk_category: str = "limited") -> Dict[str, Any]:
        """Vérifie la conformité EU AI Act pour une catégorie de risque donnée"""
        if risk_category not in RISK_CATEGORIES:
            return {
                "error": f"Invalid risk category: {risk_category}. Valid: {list(RISK_CATEGORIES.keys())}",
            }

        category_info = RISK_CATEGORIES[risk_category]
        requirements = category_info["requirements"]

        # Vérifier la présence de documentation
        compliance_checks = {
            "risk_category": risk_category,
            "description": category_info["description"],
            "requirements": requirements,
            "compliance_status": {},
        }

        # Vérifications basiques de conformité
        docs_path = self.project_path / "docs"
        readme_exists = (self.project_path / "README.md").exists()

        if risk_category == "high":
            compliance_checks["compliance_status"] = {
                "documentation_technique": self._check_technical_docs(),
                "gestion_risques": self._check_file_exists("RISK_MANAGEMENT.md"),
                "transparence": self._check_file_exists("TRANSPARENCY.md") or readme_exists,
                "gouvernance_donnees": self._check_file_exists("DATA_GOVERNANCE.md"),
                "surveillance_humaine": self._check_file_exists("HUMAN_OVERSIGHT.md"),
                "robustesse": self._check_file_exists("ROBUSTNESS.md"),
            }
        elif risk_category == "limited":
            compliance_checks["compliance_status"] = {
                "transparence": readme_exists or self._check_file_exists("TRANSPARENCY.md"),
                "information_utilisateurs": self._check_ai_disclosure(),
                "marquage_contenu": self._check_content_marking(),
            }
        elif risk_category == "minimal":
            compliance_checks["compliance_status"] = {
                "documentation_basique": readme_exists,
            }

        # Calculer le score de conformité
        total_checks = len(compliance_checks["compliance_status"])
        passed_checks = sum(1 for v in compliance_checks["compliance_status"].values() if v)
        compliance_checks["compliance_score"] = f"{passed_checks}/{total_checks}"
        compliance_checks["compliance_percentage"] = round((passed_checks / total_checks) * 100, 1) if total_checks > 0 else 0

        return compliance_checks

    def _check_technical_docs(self) -> bool:
        """Vérifie la présence de documentation technique"""
        docs = ["README.md", "ARCHITECTURE.md", "API.md", "docs/"]
        return any((self.project_path / doc).exists() for doc in docs)

    def _check_file_exists(self, filename: str) -> bool:
        """Vérifie si un fichier existe"""
        return (self.project_path / filename).exists() or (self.project_path / "docs" / filename).exists()

    def _check_ai_disclosure(self) -> bool:
        """Vérifie si le projet informe clairement de l'utilisation d'AI"""
        readme_path = self.project_path / "README.md"
        if readme_path.exists():
            content = readme_path.read_text(encoding="utf-8", errors="ignore").lower()
            ai_keywords = ["ai", "artificial intelligence", "intelligence artificielle", "machine learning", "deep learning", "gpt", "claude", "llm"]
            return any(keyword in content for keyword in ai_keywords)
        return False

    def _check_content_marking(self) -> bool:
        """Vérifie si le contenu généré est marqué"""
        # Chercher des marqueurs dans le code
        markers = [
            "generated by ai",
            "généré par ia",
            "ai-generated",
            "machine-generated",
        ]
        for file_path in self.project_path.rglob("*.py"):
            if file_path.is_file():
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
                    if any(marker in content for marker in markers):
                        return True
                except:
                    pass
        return False

    def generate_report(self, scan_results: Dict, compliance_results: Dict) -> Dict[str, Any]:
        """Génère un rapport de conformité complet"""
        report = {
            "report_date": datetime.now(timezone.utc).isoformat(),
            "project_path": str(self.project_path),
            "scan_summary": {
                "files_scanned": scan_results.get("files_scanned", 0),
                "ai_files_detected": len(scan_results.get("ai_files", [])),
                "frameworks_detected": list(scan_results.get("detected_models", {}).keys()),
            },
            "compliance_summary": {
                "risk_category": compliance_results.get("risk_category", "unknown"),
                "compliance_score": compliance_results.get("compliance_score", "0/0"),
                "compliance_percentage": compliance_results.get("compliance_percentage", 0),
            },
            "detailed_findings": {
                "detected_models": scan_results.get("detected_models", {}),
                "compliance_checks": compliance_results.get("compliance_status", {}),
                "requirements": compliance_results.get("requirements", []),
            },
            "recommendations": self._generate_recommendations(compliance_results),
        }

        return report

    def _generate_recommendations(self, compliance_results: Dict) -> List[str]:
        """Génère des recommandations basées sur les résultats de conformité"""
        recommendations = []
        compliance_status = compliance_results.get("compliance_status", {})

        for check, passed in compliance_status.items():
            if not passed:
                recommendations.append(f"❌ Créer documentation: {check.replace('_', ' ').title()}")

        if not recommendations:
            recommendations.append("✅ Toutes les vérifications basiques sont passées")

        risk_category = compliance_results.get("risk_category", "limited")
        if risk_category == "high":
            recommendations.append("⚠️ Système à haut risque - Enregistrement UE requis avant déploiement")
        elif risk_category == "limited":
            recommendations.append("ℹ️ Système à risque limité - Assurer transparence complète")

        return recommendations


# MCP Server Tools
def scan_project_tool(project_path: str) -> Dict[str, Any]:
    """
    Tool MCP: Scanne un projet pour détecter l'utilisation de modèles AI

    Args:
        project_path: Chemin vers le projet à scanner

    Returns:
        Résultats du scan avec fichiers détectés et frameworks utilisés
    """
    checker = EUAIActChecker(project_path)
    results = checker.scan_project()
    return {
        "tool": "scan_project",
        "results": results,
    }


def check_compliance_tool(project_path: str, risk_category: str = "limited") -> Dict[str, Any]:
    """
    Tool MCP: Vérifie la conformité EU AI Act

    Args:
        project_path: Chemin vers le projet
        risk_category: Catégorie de risque (unacceptable|high|limited|minimal)

    Returns:
        Résultats de la vérification de conformité
    """
    checker = EUAIActChecker(project_path)
    checker.scan_project()  # Scan d'abord
    compliance = checker.check_compliance(risk_category)
    return {
        "tool": "check_compliance",
        "results": compliance,
    }


def generate_report_tool(project_path: str, risk_category: str = "limited") -> Dict[str, Any]:
    """
    Tool MCP: Génère un rapport de conformité complet

    Args:
        project_path: Chemin vers le projet
        risk_category: Catégorie de risque (unacceptable|high|limited|minimal)

    Returns:
        Rapport de conformité complet au format JSON
    """
    checker = EUAIActChecker(project_path)
    scan_results = checker.scan_project()
    compliance_results = checker.check_compliance(risk_category)
    report = checker.generate_report(scan_results, compliance_results)
    return {
        "tool": "generate_report",
        "results": report,
    }


# MCP Server Interface
class MCPServer:
    """Serveur MCP pour EU AI Act Compliance Checker"""

    def __init__(self):
        self.tools = {
            "scan_project": scan_project_tool,
            "check_compliance": check_compliance_tool,
            "generate_report": generate_report_tool,
        }

    def handle_request(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Traite une requête MCP"""
        if tool_name not in self.tools:
            return {
                "error": f"Unknown tool: {tool_name}",
                "available_tools": list(self.tools.keys()),
            }

        try:
            result = self.tools[tool_name](**params)
            return result
        except Exception as e:
            return {
                "error": f"Error executing {tool_name}: {str(e)}",
            }

    def list_tools(self) -> Dict[str, Any]:
        """Liste les tools disponibles"""
        return {
            "tools": [
                {
                    "name": "scan_project",
                    "description": "Scanne un projet pour détecter l'utilisation de modèles AI",
                    "parameters": {
                        "project_path": "string (required) - Chemin vers le projet"
                    },
                },
                {
                    "name": "check_compliance",
                    "description": "Vérifie la conformité EU AI Act",
                    "parameters": {
                        "project_path": "string (required) - Chemin vers le projet",
                        "risk_category": "string (optional) - unacceptable|high|limited|minimal (default: limited)",
                    },
                },
                {
                    "name": "generate_report",
                    "description": "Génère un rapport de conformité complet",
                    "parameters": {
                        "project_path": "string (required) - Chemin vers le projet",
                        "risk_category": "string (optional) - unacceptable|high|limited|minimal (default: limited)",
                    },
                },
            ]
        }


def main():
    """Point d'entrée principal du serveur MCP"""
    server = MCPServer()

    # Exemple d'utilisation
    print("=== EU AI Act Compliance Checker - MCP Server ===")
    print("\nAvailable tools:")
    tools_info = server.list_tools()
    for tool in tools_info["tools"]:
        print(f"\n- {tool['name']}: {tool['description']}")

    # Test avec le projet actuel
    print("\n\n=== Testing with current project ===")
    project_path = "/opt/claude-ceo"

    # 1. Scan
    print("\n1. Scanning project...")
    scan_result = server.handle_request("scan_project", {"project_path": project_path})
    print(json.dumps(scan_result, indent=2))

    # 2. Check compliance
    print("\n2. Checking compliance (limited risk)...")
    compliance_result = server.handle_request("check_compliance", {
        "project_path": project_path,
        "risk_category": "limited"
    })
    print(json.dumps(compliance_result, indent=2))

    # 3. Generate report
    print("\n3. Generating full report...")
    report_result = server.handle_request("generate_report", {
        "project_path": project_path,
        "risk_category": "limited"
    })
    print(json.dumps(report_result, indent=2))


if __name__ == "__main__":
    main()
