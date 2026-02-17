#!/usr/bin/env python3
"""
Integration tests for the MCP EU AI Act server
Tests complete end-to-end user scenarios
"""

import unittest
import sys
import tempfile
import shutil
import json
from pathlib import Path

# Add parent directory to path for import
sys.path.insert(0, str(Path(__file__).parent.parent))

from server import MCPServer, EUAIActChecker


class TestEndToEndScenarios(unittest.TestCase):
    """Complete user scenario tests"""

    def setUp(self):
        """Create a test environment"""
        self.server = MCPServer()
        self.test_dir = tempfile.mkdtemp()
        self.project_path = Path(self.test_dir) / "test_project"
        self.project_path.mkdir()

    def tearDown(self):
        """Clean up"""
        shutil.rmtree(self.test_dir)

    def test_scenario_simple_chatbot(self):
        """
        Scenario: Simple chatbot using OpenAI
        - Limited risk
        - Must have transparency and user disclosure
        """
        (self.project_path / "chatbot.py").write_text("""
import openai

def chat(message):
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": message}]
    )
    return response.choices[0].message.content
""")

        (self.project_path / "README.md").write_text("""
# Simple Chatbot

This chatbot uses OpenAI GPT-4 to answer questions.
Users interact with an AI system.
""")

        # 1. Scan the project
        scan_result = self.server.handle_request("scan_project", {
            "project_path": str(self.project_path)
        })

        self.assertEqual(scan_result["tool"], "scan_project")
        self.assertIn("openai", scan_result["results"]["detected_models"])
        self.assertEqual(scan_result["results"]["files_scanned"], 1)

        # 2. Check compliance (limited risk)
        compliance_result = self.server.handle_request("check_compliance", {
            "project_path": str(self.project_path),
            "risk_category": "limited"
        })

        self.assertEqual(compliance_result["results"]["risk_category"], "limited")
        self.assertTrue(compliance_result["results"]["compliance_status"]["transparency"])
        self.assertTrue(compliance_result["results"]["compliance_status"]["user_disclosure"])

        # 3. Generate full report
        report_result = self.server.handle_request("generate_report", {
            "project_path": str(self.project_path),
            "risk_category": "limited"
        })

        self.assertIn("report_date", report_result["results"])
        self.assertEqual(report_result["results"]["scan_summary"]["frameworks_detected"], ["openai"])
        self.assertGreater(len(report_result["results"]["recommendations"]), 0)

    def test_scenario_high_risk_recruitment_ai(self):
        """
        Scenario: AI recruitment system (high risk)
        - Must have complete documentation, risk management, etc.
        """
        (self.project_path / "recruitment.py").write_text("""
from anthropic import Anthropic

def analyze_cv(cv_text):
    client = Anthropic()
    message = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1024,
        messages=[{
            "role": "user",
            "content": f"Analyze this CV and score the candidate: {cv_text}"
        }]
    )
    return message.content
""")

        (self.project_path / "README.md").write_text("""
# AI Recruitment System

Uses Claude AI to analyze CVs and score candidates.
""")

        report = self.server.handle_request("generate_report", {
            "project_path": str(self.project_path),
            "risk_category": "high"
        })

        self.assertIn("anthropic", report["results"]["scan_summary"]["frameworks_detected"])

        compliance_pct = report["results"]["compliance_summary"]["compliance_percentage"]
        self.assertLess(compliance_pct, 50)

        recommendations = report["results"]["recommendations"]
        self.assertTrue(any("documentation" in r.lower() for r in recommendations))
        self.assertTrue(any("high-risk" in r.lower() for r in recommendations))

    def test_scenario_multi_framework_project(self):
        """
        Scenario: Project using multiple AI frameworks
        - OpenAI, Anthropic, LangChain
        - All must be detected
        """
        (self.project_path / "openai_service.py").write_text("""
import openai
openai.ChatCompletion.create(model="gpt-4", messages=[])
""")

        (self.project_path / "anthropic_service.py").write_text("""
from anthropic import Anthropic
client = Anthropic()
""")

        (self.project_path / "langchain_agent.py").write_text("""
from langchain import LLMChain
from langchain.llms import ChatOpenAI
""")

        (self.project_path / "utils.py").write_text("""
def helper():
    pass
""")

        scan_result = self.server.handle_request("scan_project", {
            "project_path": str(self.project_path)
        })

        detected = scan_result["results"]["detected_models"]
        self.assertIn("openai", detected)
        self.assertIn("anthropic", detected)
        self.assertIn("langchain", detected)
        self.assertEqual(scan_result["results"]["files_scanned"], 4)
        self.assertEqual(len(scan_result["results"]["ai_files"]), 3)

    def test_scenario_compliant_limited_risk_project(self):
        """
        Scenario: Fully compliant limited risk project
        - Transparency: README with AI mention
        - User disclosure: Clear disclosure
        - Content marking: Generated code marked
        """
        (self.project_path / "app.py").write_text("""
import openai

# This code is generated by AI
def generate_text(prompt):
    return openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt
    )
""")

        (self.project_path / "README.md").write_text("""
# AI Content Generator

This application uses OpenAI GPT models to generate content.

## AI Disclosure
Users are informed that they are interacting with an AI system.
All generated content is clearly marked as AI-generated.
""")

        compliance_result = self.server.handle_request("check_compliance", {
            "project_path": str(self.project_path),
            "risk_category": "limited"
        })

        status = compliance_result["results"]["compliance_status"]
        self.assertTrue(status["transparency"])
        self.assertTrue(status["user_disclosure"])
        self.assertTrue(status["content_marking"])

        self.assertEqual(compliance_result["results"]["compliance_score"], "3/3")
        self.assertEqual(compliance_result["results"]["compliance_percentage"], 100.0)

    def test_scenario_minimal_risk_game(self):
        """
        Scenario: Video game with AI (minimal risk)
        - Almost no requirements
        """
        (self.project_path / "game_ai.py").write_text("""
import torch
import torch.nn as nn

class GameAI(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(10, 10)
""")

        (self.project_path / "README.md").write_text("# Game AI")

        compliance_result = self.server.handle_request("check_compliance", {
            "project_path": str(self.project_path),
            "risk_category": "minimal"
        })

        self.assertEqual(compliance_result["results"]["risk_category"], "minimal")
        self.assertTrue(compliance_result["results"]["compliance_status"]["basic_documentation"])
        self.assertEqual(compliance_result["results"]["compliance_percentage"], 100.0)

    def test_scenario_no_ai_detected(self):
        """
        Scenario: Project with no AI detected
        - Should still check compliance
        """
        (self.project_path / "utils.py").write_text("""
def add(a, b):
    return a + b
""")

        (self.project_path / "README.md").write_text("# Utilities")

        scan_result = self.server.handle_request("scan_project", {
            "project_path": str(self.project_path)
        })

        self.assertEqual(len(scan_result["results"]["detected_models"]), 0)
        self.assertEqual(len(scan_result["results"]["ai_files"]), 0)

        compliance_result = self.server.handle_request("check_compliance", {
            "project_path": str(self.project_path),
            "risk_category": "minimal"
        })

        self.assertEqual(compliance_result["results"]["risk_category"], "minimal")

    def test_scenario_nested_project_structure(self):
        """
        Scenario: Project with nested folder structure
        - AI code in subdirectories
        - Documentation in docs/
        """
        (self.project_path / "src").mkdir()
        (self.project_path / "src" / "ai").mkdir()
        (self.project_path / "docs").mkdir()

        (self.project_path / "src" / "ai" / "model.py").write_text("""
from transformers import AutoModel, AutoTokenizer

model = AutoModel.from_pretrained("bert-base-uncased")
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
""")

        (self.project_path / "docs" / "TRANSPARENCY.md").write_text("""
# Transparency Documentation
This system uses AI models from HuggingFace.
""")

        scan_result = self.server.handle_request("scan_project", {
            "project_path": str(self.project_path)
        })

        self.assertIn("huggingface", scan_result["results"]["detected_models"])
        self.assertIn("src/ai/model.py", scan_result["results"]["detected_models"]["huggingface"][0])

        compliance_result = self.server.handle_request("check_compliance", {
            "project_path": str(self.project_path),
            "risk_category": "limited"
        })

        self.assertTrue(compliance_result["results"]["compliance_status"]["transparency"])

    def test_scenario_full_workflow(self):
        """
        Scenario: Complete audit workflow
        1. List available tools
        2. Scan the project
        3. Check compliance for each risk category
        4. Generate final report
        """
        (self.project_path / "ai_app.py").write_text("""
import openai

def process():
    return openai.ChatCompletion.create(model="gpt-4", messages=[])
""")

        (self.project_path / "README.md").write_text("# AI Application using GPT-4")

        # 1. List tools
        tools = self.server.list_tools()
        self.assertEqual(len(tools["tools"]), 3)

        # 2. Scan
        scan = self.server.handle_request("scan_project", {
            "project_path": str(self.project_path)
        })
        self.assertIn("openai", scan["results"]["detected_models"])

        # 3. Check for each category
        for risk_category in ["minimal", "limited", "high"]:
            compliance = self.server.handle_request("check_compliance", {
                "project_path": str(self.project_path),
                "risk_category": risk_category
            })
            self.assertEqual(compliance["results"]["risk_category"], risk_category)
            self.assertIn("compliance_percentage", compliance["results"])

        # 4. Final report
        report = self.server.handle_request("generate_report", {
            "project_path": str(self.project_path),
            "risk_category": "limited"
        })

        self.assertIn("report_date", report["results"])
        self.assertIn("scan_summary", report["results"])
        self.assertIn("compliance_summary", report["results"])
        self.assertIn("detailed_findings", report["results"])
        self.assertIn("recommendations", report["results"])

    def test_scenario_unacceptable_risk_system(self):
        """
        Scenario: Social scoring system (unacceptable risk)
        - Should be prohibited
        """
        (self.project_path / "social_scoring.py").write_text("""
from anthropic import Anthropic

def score_citizen(data):
    client = Anthropic()
    return client.messages.create(
        model="claude-3-opus-20240229",
        messages=[{"role": "user", "content": f"Score citizen: {data}"}]
    )
""")

        report = self.server.handle_request("generate_report", {
            "project_path": str(self.project_path),
            "risk_category": "unacceptable"
        })

        self.assertIn("anthropic", report["results"]["scan_summary"]["frameworks_detected"])
        self.assertEqual(report["results"]["compliance_summary"]["compliance_score"], "0/0")

    def test_scenario_progressive_compliance(self):
        """
        Scenario: Progressive compliance improvement
        - First non-compliant, then adding documentation
        """
        # 1. Non-compliant project
        (self.project_path / "app.py").write_text("import openai")

        result1 = self.server.handle_request("check_compliance", {
            "project_path": str(self.project_path),
            "risk_category": "limited"
        })
        pct1 = result1["results"]["compliance_percentage"]

        # 2. Add README with AI mention
        (self.project_path / "README.md").write_text("# AI-powered app using GPT")

        result2 = self.server.handle_request("check_compliance", {
            "project_path": str(self.project_path),
            "risk_category": "limited"
        })
        pct2 = result2["results"]["compliance_percentage"]

        # 3. Add content marking
        (self.project_path / "app.py").write_text("""
import openai
# This content is generated by AI
def predict(): pass
""")

        result3 = self.server.handle_request("check_compliance", {
            "project_path": str(self.project_path),
            "risk_category": "limited"
        })
        pct3 = result3["results"]["compliance_percentage"]

        # Compliance should improve progressively
        self.assertGreater(pct2, pct1)
        self.assertGreater(pct3, pct2)
        self.assertEqual(pct3, 100.0)

    def test_scenario_real_world_project_scan(self):
        """
        Scenario: Scan the MCP EU AI Act server itself
        - Should detect Python code
        - Should be a real project
        """
        mcp_path = str(Path(__file__).parent.parent)
        scan_result = self.server.handle_request("scan_project", {
            "project_path": mcp_path
        })

        self.assertGreater(scan_result["results"]["files_scanned"], 0)


class TestErrorHandling(unittest.TestCase):
    """Error handling tests under real conditions"""

    def setUp(self):
        """Create a test environment"""
        self.server = MCPServer()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up"""
        shutil.rmtree(self.test_dir)

    def test_invalid_project_path(self):
        """Test with invalid project path"""
        result = self.server.handle_request("scan_project", {
            "project_path": "/this/path/does/not/exist"
        })

        self.assertIn("error", result["results"])

    def test_missing_parameters(self):
        """Test with missing parameters"""
        result = self.server.handle_request("scan_project", {})

        self.assertIn("error", result)

    def test_invalid_risk_category(self):
        """Test with invalid risk category"""
        project_path = Path(self.test_dir) / "test"
        project_path.mkdir()

        result = self.server.handle_request("check_compliance", {
            "project_path": str(project_path),
            "risk_category": "super_high"
        })

        self.assertIn("error", result["results"])

    def test_empty_params_dict(self):
        """Test with empty params dict for check_compliance"""
        result = self.server.handle_request("check_compliance", {})
        self.assertIn("error", result)

    def test_generate_report_nonexistent_path(self):
        """Test report generation with non-existent path"""
        result = self.server.handle_request("generate_report", {
            "project_path": "/nonexistent/path",
            "risk_category": "limited"
        })
        self.assertEqual(result["tool"], "generate_report")


class TestReportGeneration(unittest.TestCase):
    """Detailed report generation tests"""

    def setUp(self):
        """Create a test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.project_path = Path(self.test_dir) / "test_project"
        self.project_path.mkdir()

    def tearDown(self):
        """Clean up"""
        shutil.rmtree(self.test_dir)

    def test_report_structure_completeness(self):
        """Test complete report structure"""
        (self.project_path / "main.py").write_text("import openai")
        (self.project_path / "README.md").write_text("# Test AI")

        checker = EUAIActChecker(str(self.project_path))
        scan_results = checker.scan_project()
        compliance_results = checker.check_compliance("limited")
        report = checker.generate_report(scan_results, compliance_results)

        required_fields = [
            "report_date",
            "project_path",
            "scan_summary",
            "compliance_summary",
            "detailed_findings",
            "recommendations"
        ]

        for field in required_fields:
            self.assertIn(field, report)

        self.assertIn("files_scanned", report["scan_summary"])
        self.assertIn("ai_files_detected", report["scan_summary"])
        self.assertIn("frameworks_detected", report["scan_summary"])

        self.assertIn("risk_category", report["compliance_summary"])
        self.assertIn("compliance_score", report["compliance_summary"])
        self.assertIn("compliance_percentage", report["compliance_summary"])

        self.assertIn("detected_models", report["detailed_findings"])
        self.assertIn("compliance_checks", report["detailed_findings"])
        self.assertIn("requirements", report["detailed_findings"])

        self.assertIsInstance(report["recommendations"], list)
        self.assertGreater(len(report["recommendations"]), 0)

    def test_report_json_serializable(self):
        """Test that report is JSON serializable"""
        (self.project_path / "test.py").write_text("from anthropic import Anthropic")

        checker = EUAIActChecker(str(self.project_path))
        scan_results = checker.scan_project()
        compliance_results = checker.check_compliance("high")
        report = checker.generate_report(scan_results, compliance_results)

        json_str = json.dumps(report, indent=2)
        self.assertIsInstance(json_str, str)

        parsed = json.loads(json_str)
        self.assertEqual(parsed["project_path"], str(self.project_path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
