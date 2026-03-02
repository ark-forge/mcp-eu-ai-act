"""Scanner accuracy tests — framework detection, false positives."""

import os
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from server import EUAIActChecker


def _make_project(files: dict) -> str:
    """Create a temp project with given files. Returns path."""
    d = tempfile.mkdtemp()
    for name, content in files.items():
        path = Path(d) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return d


class TestFrameworkDetection:
    """Verify AI framework detection accuracy."""

    def test_detect_openai(self):
        proj = _make_project({"app.py": "import openai\nclient = openai.ChatCompletion.create()"})
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert "openai" in result["detected_models"]

    def test_detect_anthropic(self):
        proj = _make_project({"chat.py": "from anthropic import Anthropic\nclient = Anthropic()"})
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert "anthropic" in result["detected_models"]

    def test_detect_langchain(self):
        proj = _make_project({"chain.py": "from langchain import LLMChain\nfrom langchain.agents import initialize_agent"})
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert "langchain" in result["detected_models"]

    def test_detect_huggingface(self):
        proj = _make_project({"model.py": "from transformers import AutoModel"})
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert "huggingface" in result["detected_models"]

    def test_detect_tensorflow(self):
        proj = _make_project({"train.py": "import tensorflow as tf"})
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert "tensorflow" in result["detected_models"]

    def test_detect_pytorch(self):
        proj = _make_project({"train.py": "import torch\nmodel = torch.nn.Linear(10, 5)"})
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert "pytorch" in result["detected_models"]

    def test_detect_in_requirements(self):
        proj = _make_project({"requirements.txt": "openai>=1.0.0\nfastapi"})
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert "openai" in result["detected_models"]

    def test_no_false_positive_on_clean_project(self):
        proj = _make_project({
            "app.py": "from flask import Flask\napp = Flask(__name__)",
            "requirements.txt": "flask\nrequests\npydantic",
        })
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert result["detected_models"] == {}

    def test_empty_project(self):
        proj = _make_project({})
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert result["files_scanned"] == 0
        assert result["detected_models"] == {}

    def test_files_scanned_count(self):
        proj = _make_project({
            "a.py": "print('hello')",
            "b.py": "print('world')",
            "c.txt": "not python",
        })
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert result["files_scanned"] >= 2

    def test_skip_venv_directory(self):
        proj = _make_project({
            "app.py": "print('clean')",
            ".venv/lib/openai.py": "import openai",
        })
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert "openai" not in result["detected_models"]


class TestFollowImports:
    """Verify follow_imports propagation through Python import graph."""

    def test_direct_import_no_propagation_needed(self):
        """When AI import is direct, follow_imports adds no extra files."""
        proj = _make_project({"app.py": "import openai\nclient = openai.ChatCompletion.create()"})
        checker = EUAIActChecker(proj)
        result = checker.scan_project(follow_imports=True)
        assert result.get("follow_imports_applied") is True
        assert result["propagated_files"] == []

    def test_transitive_import_detected(self):
        """File importing from AI-flagged file should appear in propagated_files."""
        proj = _make_project({
            "core/ai_engine.py": "from openai import OpenAI\nclient = OpenAI()",
            "routes/analyze.py": "from core.ai_engine import run_analysis\n",
        })
        checker = EUAIActChecker(proj)
        result = checker.scan_project(follow_imports=True)
        assert result.get("follow_imports_applied") is True
        propagated_files = [p["file"] for p in result["propagated_files"]]
        assert any("analyze" in f for f in propagated_files), (
            f"routes/analyze.py should be propagated, got: {propagated_files}"
        )

    def test_propagated_file_in_detected_models(self):
        """Propagated files appear in detected_models so compliance checks cover them."""
        proj = _make_project({
            "ai_core.py": "from anthropic import Anthropic\n",
            "handler.py": "from ai_core import process\n",
        })
        checker = EUAIActChecker(proj)
        result = checker.scan_project(follow_imports=True)
        anthropic_files = result["detected_models"].get("anthropic", [])
        assert any("handler" in f for f in anthropic_files), (
            f"handler.py should be in detected_models['anthropic'], got: {anthropic_files}"
        )

    def test_non_ai_project_no_propagation(self):
        """No propagation when no AI frameworks are detected."""
        proj = _make_project({
            "utils.py": "import math\n",
            "app.py": "from utils import compute\n",
        })
        checker = EUAIActChecker(proj)
        result = checker.scan_project(follow_imports=True)
        assert result.get("follow_imports_applied") is True
        assert result["propagated_files"] == []

    def test_follow_imports_false_by_default(self):
        """follow_imports is False by default — no propagated_files key."""
        proj = _make_project({
            "core/ai_engine.py": "from openai import OpenAI\n",
            "routes/analyze.py": "from core.ai_engine import run_analysis\n",
        })
        checker = EUAIActChecker(proj)
        result = checker.scan_project()
        assert "follow_imports_applied" not in result
        assert "propagated_files" not in result


class TestCompliance:
    """Verify compliance check logic."""

    def test_compliance_high_risk(self):
        proj = _make_project({"app.py": "import openai"})
        checker = EUAIActChecker(proj)
        checker.scan_project()
        result = checker.check_compliance("high")
        assert "requirements" in result
        assert len(result["requirements"]) > 0

    def test_compliance_minimal_risk(self):
        proj = _make_project({"app.py": "import openai"})
        checker = EUAIActChecker(proj)
        checker.scan_project()
        result = checker.check_compliance("minimal")
        assert "requirements" in result

    def test_compliance_no_ai_detected(self):
        proj = _make_project({"app.py": "print('hello')"})
        checker = EUAIActChecker(proj)
        checker.scan_project()
        result = checker.check_compliance("limited")
        assert isinstance(result, dict)
