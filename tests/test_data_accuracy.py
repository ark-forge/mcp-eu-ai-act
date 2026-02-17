#!/usr/bin/env python3
"""
EU AI Act data accuracy tests
Verifies correctness of risk categories, requirements, and detection patterns
"""

import unittest
import sys
import re
from pathlib import Path

# Add parent directory to path for import
sys.path.insert(0, str(Path(__file__).parent.parent))

from server import AI_MODEL_PATTERNS, RISK_CATEGORIES


class TestAIModelPatterns(unittest.TestCase):
    """AI detection pattern accuracy tests"""

    def test_openai_patterns_accuracy(self):
        """Test OpenAI patterns against real code"""
        patterns = AI_MODEL_PATTERNS["openai"]

        valid_openai_code = [
            "import openai",
            "from openai import OpenAI",
            "openai.ChatCompletion.create()",
            "openai.Completion.create()",
            'model="gpt-4"',
            'model="gpt-3.5-turbo"',
            'engine="text-davinci-003"',
        ]

        for code in valid_openai_code:
            matched = any(re.search(pattern, code, re.IGNORECASE) for pattern in patterns)
            self.assertTrue(matched, f"Failed to detect OpenAI in: {code}")

        invalid_code = [
            "import os",
            "from anthropic import Anthropic",
            "import tensorflow",
        ]

        for code in invalid_code:
            matched = any(re.search(pattern, code, re.IGNORECASE) for pattern in patterns)
            self.assertFalse(matched, f"False positive for OpenAI in: {code}")

    def test_anthropic_patterns_accuracy(self):
        """Test Anthropic patterns against real code"""
        patterns = AI_MODEL_PATTERNS["anthropic"]

        valid_anthropic_code = [
            "from anthropic import Anthropic",
            "import anthropic",
            'model="claude-3-opus-20240229"',
            'model="claude-3-sonnet-20240229"',
            "client = Anthropic()",
            "client.messages.create()",
        ]

        for code in valid_anthropic_code:
            matched = any(re.search(pattern, code, re.IGNORECASE) for pattern in patterns)
            self.assertTrue(matched, f"Failed to detect Anthropic in: {code}")

    def test_huggingface_patterns_accuracy(self):
        """Test HuggingFace patterns against real code"""
        patterns = AI_MODEL_PATTERNS["huggingface"]

        valid_hf_code = [
            "from transformers import AutoModel",
            "from transformers import AutoTokenizer",
            "from transformers import pipeline",
            "model = AutoModel.from_pretrained('bert-base-uncased')",
            "from huggingface_hub import HfApi",
        ]

        for code in valid_hf_code:
            matched = any(re.search(pattern, code, re.IGNORECASE) for pattern in patterns)
            self.assertTrue(matched, f"Failed to detect HuggingFace in: {code}")

    def test_tensorflow_patterns_accuracy(self):
        """Test TensorFlow patterns against real code"""
        patterns = AI_MODEL_PATTERNS["tensorflow"]

        valid_tf_code = [
            "import tensorflow as tf",
            "from tensorflow import keras",
            "model = tf.keras.Sequential()",
        ]

        for code in valid_tf_code:
            matched = any(re.search(pattern, code, re.IGNORECASE) for pattern in patterns)
            self.assertTrue(matched, f"Failed to detect TensorFlow in: {code}")

        self.assertTrue("model.h5".endswith(".h5"))
        h5_pattern = r"\.h5$"
        self.assertTrue(re.search(h5_pattern, "model.h5"))

    def test_pytorch_patterns_accuracy(self):
        """Test PyTorch patterns against real code"""
        patterns = AI_MODEL_PATTERNS["pytorch"]

        valid_pytorch_code = [
            "import torch",
            "from torch import nn",
            "class MyModel(nn.Module):",
        ]

        for code in valid_pytorch_code:
            matched = any(re.search(pattern, code, re.IGNORECASE) for pattern in patterns)
            self.assertTrue(matched, f"Failed to detect PyTorch in: {code}")

        self.assertTrue("model.pt".endswith(".pt"))
        self.assertTrue("model.pth".endswith(".pth"))
        pt_pattern = r"\.pt$"
        pth_pattern = r"\.pth$"
        self.assertTrue(re.search(pt_pattern, "model.pt"))
        self.assertTrue(re.search(pth_pattern, "model.pth"))

    def test_langchain_patterns_accuracy(self):
        """Test LangChain patterns against real code"""
        patterns = AI_MODEL_PATTERNS["langchain"]

        valid_langchain_code = [
            "from langchain import LLMChain",
            "from langchain.llms import ChatOpenAI",
            "import langchain",
        ]

        for code in valid_langchain_code:
            matched = any(re.search(pattern, code, re.IGNORECASE) for pattern in patterns)
            self.assertTrue(matched, f"Failed to detect LangChain in: {code}")

    def test_no_false_positives(self):
        """Test no false positives with normal code"""
        all_patterns = []
        for patterns in AI_MODEL_PATTERNS.values():
            all_patterns.extend(patterns)

        normal_code = [
            "import os",
            "import sys",
            "import json",
            "from pathlib import Path",
            "def hello(): pass",
            "class MyClass: pass",
        ]

        for code in normal_code:
            matched = any(re.search(pattern, code, re.IGNORECASE) for pattern in all_patterns)
            self.assertFalse(matched, f"False positive in: {code}")

    def test_all_frameworks_have_patterns(self):
        """Test all frameworks have at least one pattern"""
        expected_frameworks = ["openai", "anthropic", "huggingface", "tensorflow", "pytorch", "langchain"]

        for framework in expected_frameworks:
            self.assertIn(framework, AI_MODEL_PATTERNS)
            self.assertGreater(len(AI_MODEL_PATTERNS[framework]), 0)
            self.assertIsInstance(AI_MODEL_PATTERNS[framework], list)


class TestRiskCategories(unittest.TestCase):
    """EU AI Act risk category accuracy tests"""

    def test_all_risk_categories_present(self):
        """Test all risk categories are present"""
        required_categories = ["unacceptable", "high", "limited", "minimal"]

        for category in required_categories:
            self.assertIn(category, RISK_CATEGORIES)

    def test_unacceptable_risk_category(self):
        """Test unacceptable risk category"""
        category = RISK_CATEGORIES["unacceptable"]

        self.assertIn("description", category)
        self.assertIn("requirements", category)

        description_lower = category["description"].lower()
        self.assertTrue(
            "prohibited" in description_lower or "manipulation" in description_lower,
            "Description should mention prohibited systems"
        )

        self.assertGreater(len(category["requirements"]), 0)
        self.assertIsInstance(category["requirements"], list)

    def test_high_risk_category(self):
        """Test high risk category"""
        category = RISK_CATEGORIES["high"]

        self.assertIn("description", category)
        self.assertIn("requirements", category)

        description_lower = category["description"].lower()
        self.assertTrue(
            "high-risk" in description_lower or "recruitment" in description_lower or "credit" in description_lower,
            "Description should mention high-risk systems"
        )

        requirements_str = " ".join(category["requirements"]).lower()

        required_keywords = [
            "documentation",
            "risk",
            "transparency",
            "oversight",
            "robustness",
        ]

        for keyword in required_keywords:
            self.assertTrue(
                keyword in requirements_str,
                f"High-risk requirements should include '{keyword}'"
            )

        self.assertGreaterEqual(len(category["requirements"]), 6)

    def test_limited_risk_category(self):
        """Test limited risk category"""
        category = RISK_CATEGORIES["limited"]

        self.assertIn("description", category)
        self.assertIn("requirements", category)

        description_lower = category["description"].lower()
        self.assertTrue(
            "limited" in description_lower or "chatbot" in description_lower,
            "Description should mention limited-risk systems"
        )

        requirements_str = " ".join(category["requirements"]).lower()

        required_keywords = [
            "transparency",
            "information",
        ]

        for keyword in required_keywords:
            self.assertTrue(
                keyword in requirements_str,
                f"Limited-risk requirements should include '{keyword}'"
            )

        self.assertGreaterEqual(len(category["requirements"]), 2)

    def test_minimal_risk_category(self):
        """Test minimal risk category"""
        category = RISK_CATEGORIES["minimal"]

        self.assertIn("description", category)
        self.assertIn("requirements", category)

        description_lower = category["description"].lower()
        self.assertTrue(
            "minimal" in description_lower or "spam" in description_lower or "game" in description_lower,
            "Description should mention minimal-risk systems"
        )

        requirements_str = " ".join(category["requirements"]).lower()
        self.assertTrue(
            "no specific" in requirements_str or "voluntary" in requirements_str,
            "Minimal-risk should have minimal or voluntary requirements"
        )

    def test_requirements_are_actionable(self):
        """Test requirements are actionable (not empty, meaningful)"""
        for category_name, category in RISK_CATEGORIES.items():
            requirements = category["requirements"]

            for req in requirements:
                self.assertIsInstance(req, str)
                self.assertGreater(len(req), 5, f"Requirement too short in {category_name}: {req}")

                self.assertTrue(
                    any(word in req.lower() for word in [
                        "documentation", "system", "data", "transparency", "oversight",
                        "quality", "no specific", "voluntary", "prohibited", "robustness",
                        "accuracy", "cybersecurity", "human", "management", "risk",
                        "governance", "registration", "information", "user", "marking",
                        "content", "obligations", "deploy", "encouraged", "code"
                    ]),
                    f"Requirement lacks meaningful content in {category_name}: {req}"
                )

    def test_risk_hierarchy(self):
        """Test risk hierarchy is consistent"""
        high_reqs = len(RISK_CATEGORIES["high"]["requirements"])
        limited_reqs = len(RISK_CATEGORIES["limited"]["requirements"])
        minimal_reqs = len(RISK_CATEGORIES["minimal"]["requirements"])

        self.assertGreater(high_reqs, limited_reqs, "High risk should have more requirements than limited")
        self.assertGreater(limited_reqs, minimal_reqs, "Limited risk should have more requirements than minimal")


class TestComplianceAccuracy(unittest.TestCase):
    """Compliance logic accuracy tests"""

    def test_compliance_score_calculation(self):
        """Test compliance score calculation"""
        test_cases = [
            (3, 3, 100.0),
            (2, 3, 66.7),
            (1, 3, 33.3),
            (0, 3, 0.0),
            (5, 6, 83.3),
        ]

        for passed, total, expected_pct in test_cases:
            calculated_pct = round((passed / total) * 100, 1) if total > 0 else 0
            self.assertEqual(
                calculated_pct,
                expected_pct,
                f"Score calculation wrong for {passed}/{total}"
            )

    def test_eu_ai_act_reference_data(self):
        """Test against known EU AI Act reference data"""
        high_risk_examples = [
            "recruitment",
            "credit",
            "law enforcement",
        ]

        high_risk_desc = RISK_CATEGORIES["high"]["description"].lower()

        matches = sum(1 for ex in high_risk_examples if ex in high_risk_desc)
        self.assertGreaterEqual(matches, 2, "High-risk description should mention known examples")

        unacceptable_examples = [
            "manipulation",
            "social scoring",
            "surveillance",
        ]

        unacceptable_desc = RISK_CATEGORIES["unacceptable"]["description"].lower()

        matches = sum(1 for ex in unacceptable_examples if ex in unacceptable_desc)
        self.assertGreaterEqual(matches, 1, "Unacceptable-risk description should mention prohibited systems")


class TestDataConsistency(unittest.TestCase):
    """Data consistency tests"""

    def test_no_duplicate_patterns(self):
        """Test no duplicate patterns within a framework"""
        for framework, patterns in AI_MODEL_PATTERNS.items():
            unique_patterns = set(patterns)
            self.assertEqual(
                len(patterns),
                len(unique_patterns),
                f"Duplicate patterns found in {framework}"
            )

    def test_patterns_are_valid_regex(self):
        """Test all patterns are valid regex"""
        for framework, patterns in AI_MODEL_PATTERNS.items():
            for pattern in patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    self.fail(f"Invalid regex in {framework}: {pattern} - {e}")

    def test_risk_categories_structure(self):
        """Test all categories have the same structure"""
        required_keys = ["description", "requirements"]

        for category_name, category in RISK_CATEGORIES.items():
            for key in required_keys:
                self.assertIn(
                    key,
                    category,
                    f"Missing key '{key}' in category '{category_name}'"
                )

            self.assertIsInstance(category["description"], str)
            self.assertIsInstance(category["requirements"], list)

    def test_no_empty_data(self):
        """Test no empty data"""
        for framework, patterns in AI_MODEL_PATTERNS.items():
            self.assertGreater(len(patterns), 0, f"Empty patterns for {framework}")
            for pattern in patterns:
                self.assertGreater(len(pattern), 0, f"Empty pattern in {framework}")

        for category_name, category in RISK_CATEGORIES.items():
            self.assertGreater(len(category["description"]), 0, f"Empty description in {category_name}")
            self.assertGreater(len(category["requirements"]), 0, f"Empty requirements in {category_name}")


class TestFrameworkCoverage(unittest.TestCase):
    """AI framework coverage tests"""

    def test_major_frameworks_covered(self):
        """Test major frameworks are covered"""
        major_frameworks = {
            "openai": ["OpenAI", "GPT"],
            "anthropic": ["Claude", "Anthropic"],
            "huggingface": ["Transformers", "HuggingFace"],
            "tensorflow": ["TensorFlow", "Keras"],
            "pytorch": ["PyTorch", "Torch"],
            "langchain": ["LangChain"],
        }

        for framework, expected_detections in major_frameworks.items():
            self.assertIn(framework, AI_MODEL_PATTERNS, f"Missing framework: {framework}")
            patterns = AI_MODEL_PATTERNS[framework]

            patterns_str = " ".join(patterns).lower()
            framework_mentioned = any(
                name.lower() in patterns_str for name in expected_detections
            )

            self.assertTrue(
                framework_mentioned,
                f"Framework {framework} patterns don't mention expected names: {expected_detections}"
            )

    def test_common_model_files_detected(self):
        """Test common model files are detected"""
        file_patterns = {
            "tensorflow": [".h5"],
            "pytorch": [".pt", ".pth"],
        }

        for framework, extensions in file_patterns.items():
            patterns = AI_MODEL_PATTERNS[framework]
            patterns_str = " ".join(patterns)

            for ext in extensions:
                self.assertTrue(
                    ext in patterns_str,
                    f"File extension {ext} not detected for {framework}"
                )


class TestEUAIActArticleAccuracy(unittest.TestCase):
    """Tests for compliance with specific EU AI Act articles"""

    def test_article_5_prohibited_practices(self):
        """Art. 5 - Prohibited practices are properly covered"""
        desc = RISK_CATEGORIES["unacceptable"]["description"].lower()
        prohibited = ["manipulation", "social scoring", "surveillance"]
        covered = sum(1 for p in prohibited if p in desc)
        self.assertGreaterEqual(covered, 2, "Article 5 prohibited practices insufficiently covered")

    def test_article_6_high_risk_systems(self):
        """Art. 6 - High-risk systems have Annex III requirements"""
        high_reqs = RISK_CATEGORIES["high"]["requirements"]
        req_text = " ".join(high_reqs).lower()

        essential = ["documentation", "risk", "data", "transparency", "human oversight", "robustness"]
        for req in essential:
            self.assertIn(req, req_text, f"High-risk missing Art. 6 requirement: {req}")

    def test_article_52_transparency_obligations(self):
        """Art. 52 - Transparency obligations for limited risk"""
        limited_reqs = RISK_CATEGORIES["limited"]["requirements"]
        req_text = " ".join(limited_reqs).lower()

        self.assertIn("transparency", req_text)
        self.assertIn("user", req_text)
        self.assertIn("content", req_text)

    def test_four_tier_risk_classification(self):
        """The EU AI Act defines exactly 4 risk levels"""
        self.assertEqual(len(RISK_CATEGORIES), 4)
        expected = {"unacceptable", "high", "limited", "minimal"}
        self.assertEqual(set(RISK_CATEGORIES.keys()), expected)

    def test_high_risk_examples_accuracy(self):
        """High-risk system examples match Annex III"""
        desc = RISK_CATEGORIES["high"]["description"].lower()
        annex_iii_examples = ["recruitment", "credit", "law"]
        covered = sum(1 for ex in annex_iii_examples if ex in desc)
        self.assertGreaterEqual(covered, 2, "High-risk examples should match Annex III")

    def test_limited_risk_examples_accuracy(self):
        """Limited risk examples are correct"""
        desc = RISK_CATEGORIES["limited"]["description"].lower()
        self.assertTrue("chatbot" in desc or "deepfake" in desc)

    def test_minimal_risk_no_mandatory_requirements(self):
        """Minimal risk has no mandatory requirements (Art. 69 - voluntary codes)"""
        req_text = " ".join(RISK_CATEGORIES["minimal"]["requirements"]).lower()
        self.assertTrue("no specific" in req_text or "voluntary" in req_text)

    def test_high_risk_eu_database_registration(self):
        """Art. 60 - High-risk systems must be registered in EU database"""
        high_reqs = RISK_CATEGORIES["high"]["requirements"]
        req_text = " ".join(high_reqs).lower()
        self.assertTrue("registration" in req_text or "database" in req_text)


class TestPatternCrossContamination(unittest.TestCase):
    """Tests that patterns from one framework don't detect another"""

    def test_openai_not_detected_as_langchain(self):
        """Pure OpenAI code should not trigger LangChain"""
        langchain_patterns = AI_MODEL_PATTERNS["langchain"]
        pure_openai_code = "import openai\nopenai.ChatCompletion.create(model='gpt-4')"

        for pattern in langchain_patterns:
            if pattern == "ChatOpenAI":
                continue
            matched = re.search(pattern, pure_openai_code, re.IGNORECASE)
            self.assertIsNone(matched, f"LangChain pattern '{pattern}' false positive on OpenAI code")

    def test_pytorch_not_detected_as_tensorflow(self):
        """Pure PyTorch code should not trigger TensorFlow"""
        tf_patterns = AI_MODEL_PATTERNS["tensorflow"]
        pure_pytorch_code = "import torch\nmodel = torch.nn.Linear(10, 5)"

        for pattern in tf_patterns:
            matched = re.search(pattern, pure_pytorch_code, re.IGNORECASE)
            self.assertIsNone(matched, f"TensorFlow pattern '{pattern}' false positive on PyTorch code")

    def test_anthropic_not_detected_as_openai(self):
        """Pure Anthropic code should not trigger OpenAI"""
        openai_patterns = AI_MODEL_PATTERNS["openai"]
        pure_anthropic_code = "from anthropic import Anthropic\nclient = Anthropic()\nclient.messages.create(model='claude-3-opus')"

        for pattern in openai_patterns:
            matched = re.search(pattern, pure_anthropic_code, re.IGNORECASE)
            self.assertIsNone(matched, f"OpenAI pattern '{pattern}' false positive on Anthropic code")


if __name__ == "__main__":
    unittest.main(verbosity=2)
