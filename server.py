#!/usr/bin/env python3
"""
MCP Server: EU AI Act Compliance Checker
Scans projects to detect AI model usage and verify EU AI Act compliance
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

# Patterns for detecting AI model usage
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

# EU AI Act - Risk categories
RISK_CATEGORIES = {
    "unacceptable": {
        "description": "Prohibited systems (behavioral manipulation, social scoring, mass biometric surveillance)",
        "requirements": ["Prohibited system - Do not deploy"],
    },
    "high": {
        "description": "High-risk systems (recruitment, credit scoring, law enforcement)",
        "requirements": [
            "Complete technical documentation",
            "Risk management system",
            "Data quality and governance",
            "Transparency and user information",
            "Human oversight",
            "Robustness, accuracy and cybersecurity",
            "Quality management system",
            "Registration in EU database",
        ],
    },
    "limited": {
        "description": "Limited-risk systems (chatbots, deepfakes)",
        "requirements": [
            "Transparency obligations",
            "Clear user information about AI interaction",
            "AI-generated content marking",
        ],
    },
    "minimal": {
        "description": "Minimal-risk systems (spam filters, video games)",
        "requirements": [
            "No specific obligations",
            "Voluntary code of conduct encouraged",
        ],
    },
}


class EUAIActChecker:
    """EU AI Act compliance checker"""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.detected_models = {}
        self.files_scanned = 0
        self.ai_files = []

    def scan_project(self) -> Dict[str, Any]:
        """Scan the project to detect AI model usage"""
        print(f"Scanning project: {self.project_path}")

        if not self.project_path.exists():
            return {
                "error": f"Project path does not exist: {self.project_path}",
                "detected_models": {},
            }

        # File extensions to scan
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
        """Scan a file for AI patterns"""
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
                        break  # One detection per framework per file

            if file_detections:
                self.ai_files.append({
                    "file": str(file_path.relative_to(self.project_path)),
                    "frameworks": list(set(file_detections)),
                })

        except Exception as e:
            print(f"Error scanning {file_path}: {e}")

    def check_compliance(self, risk_category: str = "limited") -> Dict[str, Any]:
        """Check EU AI Act compliance for a given risk category"""
        if risk_category not in RISK_CATEGORIES:
            return {
                "error": f"Invalid risk category: {risk_category}. Valid: {list(RISK_CATEGORIES.keys())}",
            }

        category_info = RISK_CATEGORIES[risk_category]
        requirements = category_info["requirements"]

        compliance_checks = {
            "risk_category": risk_category,
            "description": category_info["description"],
            "requirements": requirements,
            "compliance_status": {},
        }

        # Basic compliance checks
        docs_path = self.project_path / "docs"
        readme_exists = (self.project_path / "README.md").exists()

        if risk_category == "high":
            compliance_checks["compliance_status"] = {
                "technical_documentation": self._check_technical_docs(),
                "risk_management": self._check_file_exists("RISK_MANAGEMENT.md"),
                "transparency": self._check_file_exists("TRANSPARENCY.md") or readme_exists,
                "data_governance": self._check_file_exists("DATA_GOVERNANCE.md"),
                "human_oversight": self._check_file_exists("HUMAN_OVERSIGHT.md"),
                "robustness": self._check_file_exists("ROBUSTNESS.md"),
            }
        elif risk_category == "limited":
            compliance_checks["compliance_status"] = {
                "transparency": readme_exists or self._check_file_exists("TRANSPARENCY.md"),
                "user_disclosure": self._check_ai_disclosure(),
                "content_marking": self._check_content_marking(),
            }
        elif risk_category == "minimal":
            compliance_checks["compliance_status"] = {
                "basic_documentation": readme_exists,
            }

        # Calculate compliance score
        total_checks = len(compliance_checks["compliance_status"])
        passed_checks = sum(1 for v in compliance_checks["compliance_status"].values() if v)
        compliance_checks["compliance_score"] = f"{passed_checks}/{total_checks}"
        compliance_checks["compliance_percentage"] = round((passed_checks / total_checks) * 100, 1) if total_checks > 0 else 0

        return compliance_checks

    def _check_technical_docs(self) -> bool:
        """Check for technical documentation"""
        docs = ["README.md", "ARCHITECTURE.md", "API.md", "docs/"]
        return any((self.project_path / doc).exists() for doc in docs)

    def _check_file_exists(self, filename: str) -> bool:
        """Check if a file exists"""
        return (self.project_path / filename).exists() or (self.project_path / "docs" / filename).exists()

    def _check_ai_disclosure(self) -> bool:
        """Check if the project clearly discloses AI usage"""
        readme_path = self.project_path / "README.md"
        if readme_path.exists():
            content = readme_path.read_text(encoding="utf-8", errors="ignore").lower()
            ai_keywords = ["ai", "artificial intelligence", "intelligence artificielle", "machine learning", "deep learning", "gpt", "claude", "llm"]
            return any(keyword in content for keyword in ai_keywords)
        return False

    def _check_content_marking(self) -> bool:
        """Check if generated content is properly marked"""
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
        """Generate a complete compliance report"""
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
        """Generate recommendations based on compliance results"""
        recommendations = []
        compliance_status = compliance_results.get("compliance_status", {})

        for check, passed in compliance_status.items():
            if not passed:
                recommendations.append(f"MISSING: Create documentation for: {check.replace('_', ' ').title()}")

        if not recommendations:
            recommendations.append("All basic checks passed")

        risk_category = compliance_results.get("risk_category", "limited")
        if risk_category == "high":
            recommendations.append("WARNING: High-risk system - EU database registration required before deployment")
        elif risk_category == "limited":
            recommendations.append("INFO: Limited-risk system - Ensure full transparency compliance")

        return recommendations


# MCP Server Tools
def scan_project_tool(project_path: str) -> Dict[str, Any]:
    """
    MCP Tool: Scan a project to detect AI model usage

    Args:
        project_path: Path to the project to scan

    Returns:
        Scan results with detected files and frameworks
    """
    checker = EUAIActChecker(project_path)
    results = checker.scan_project()
    return {
        "tool": "scan_project",
        "results": results,
    }


def check_compliance_tool(project_path: str, risk_category: str = "limited") -> Dict[str, Any]:
    """
    MCP Tool: Check EU AI Act compliance

    Args:
        project_path: Path to the project
        risk_category: Risk category (unacceptable|high|limited|minimal)

    Returns:
        Compliance verification results
    """
    checker = EUAIActChecker(project_path)
    checker.scan_project()
    compliance = checker.check_compliance(risk_category)
    return {
        "tool": "check_compliance",
        "results": compliance,
    }


def generate_report_tool(project_path: str, risk_category: str = "limited") -> Dict[str, Any]:
    """
    MCP Tool: Generate a complete compliance report

    Args:
        project_path: Path to the project
        risk_category: Risk category (unacceptable|high|limited|minimal)

    Returns:
        Complete compliance report in JSON format
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
    """MCP Server for EU AI Act Compliance Checker"""

    def __init__(self):
        self.tools = {
            "scan_project": scan_project_tool,
            "check_compliance": check_compliance_tool,
            "generate_report": generate_report_tool,
        }

    def handle_request(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an MCP request"""
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
        """List available tools"""
        return {
            "tools": [
                {
                    "name": "scan_project",
                    "description": "Scan a project to detect AI model usage",
                    "parameters": {
                        "project_path": "string (required) - Path to the project"
                    },
                },
                {
                    "name": "check_compliance",
                    "description": "Check EU AI Act compliance",
                    "parameters": {
                        "project_path": "string (required) - Path to the project",
                        "risk_category": "string (optional) - unacceptable|high|limited|minimal (default: limited)",
                    },
                },
                {
                    "name": "generate_report",
                    "description": "Generate a complete compliance report",
                    "parameters": {
                        "project_path": "string (required) - Path to the project",
                        "risk_category": "string (optional) - unacceptable|high|limited|minimal (default: limited)",
                    },
                },
            ]
        }


def main():
    """Main entry point for the MCP server - demo mode"""
    import sys
    server = MCPServer()
    project_path = sys.argv[1] if len(sys.argv) > 1 else "."

    tools_info = server.list_tools()
    sys.stdout.write("=== EU AI Act Compliance Checker - MCP Server ===\n")
    for tool in tools_info["tools"]:
        sys.stdout.write(f"\n- {tool['name']}: {tool['description']}\n")

    scan_result = server.handle_request("scan_project", {"project_path": project_path})
    sys.stdout.write(f"\nScan: {scan_result['results']['files_scanned']} files\n")

    compliance_result = server.handle_request("check_compliance", {
        "project_path": project_path, "risk_category": "limited"
    })
    sys.stdout.write(f"Compliance: {compliance_result['results']['compliance_score']}\n")

    report_result = server.handle_request("generate_report", {
        "project_path": project_path, "risk_category": "limited"
    })
    sys.stdout.write(json.dumps(report_result, indent=2) + "\n")


if __name__ == "__main__":
    main()
