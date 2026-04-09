"""Tests for generate_compliance_roadmap MCP tool.

Tests the roadmap generation logic via EUAIActChecker + the create_server() tool
as exposed through direct calls to the server module.
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import EUAIActChecker, create_server, RiskCategory


def _unwrap_result(result):
    """Unwrap TextContent list to dict if needed."""
    if isinstance(result, list) and len(result) >= 2 and hasattr(result[0], "text"):
        return json.loads(result[0].text)
    return result


# ---------------------------------------------------------------------------
# Helper: invoke the tool via the MCP server instance
# ---------------------------------------------------------------------------

def _get_roadmap_tool():
    """Return the generate_compliance_roadmap function from the MCP server."""
    server = create_server()
    return server._tool_manager._tools["generate_compliance_roadmap"].fn


def _roadmap(project_path, risk_category="high", deadline="2026-08-02"):
    """Call generate_compliance_roadmap with positional args matching its signature."""
    tool = _get_roadmap_tool()
    return _unwrap_result(tool(
        project_path=str(project_path),
        risk_category=RiskCategory(risk_category),
        deadline=deadline,
    ))


# ---------------------------------------------------------------------------
# Helper: create a fully compliant high-risk project
# ---------------------------------------------------------------------------

def _make_compliant_project(path: Path) -> None:
    """Create all 6 required compliance documents for high-risk with sufficient content."""

    def write(filename, content):
        (path / filename).write_text(content, encoding="utf-8")

    write("RISK_MANAGEMENT.md", (
        "# Risk Management System\n\n"
        "## Risk Identification\n"
        "All risks are identified across the AI lifecycle.\n"
        "Risk assessment covers safety, fairness, and privacy.\n\n"
        "## Risk Mitigation\n"
        "Each identified risk has a documented mitigation strategy.\n"
        "Mitigation measures are tested before deployment.\n\n"
        "## Residual Risks\n"
        "Residual risks after mitigation are documented and accepted.\n\n"
        "## Testing & Validation\n"
        "All mitigation strategies undergo automated testing and manual review.\n"
        "Validation includes adversarial testing and bias assessment.\n\n"
        "## Review Schedule\n"
        "Risk management reviews are conducted quarterly.\n"
        "Annual full review of the AI lifecycle.\n\n"
        "## Lifecycle Considerations\n"
        "Risk management spans the entire AI lifecycle from design to decommission.\n"
    ))

    write("TECHNICAL_DOCUMENTATION.md", (
        "# Technical Documentation\n\n"
        "## General Description\n"
        "System name, version, provider, intended purpose, and foreseeable misuse.\n\n"
        "## Architecture\n"
        "AI models used, frameworks, system diagram.\n\n"
        "## Training Data\n"
        "Data sources, volume, preprocessing, known limitations.\n\n"
        "## Performance Metrics\n"
        "Accuracy, precision, recall on representative test sets.\n\n"
        "## Limitations\n"
        "Performance degrades for edge cases and out-of-distribution inputs.\n\n"
        "## Changes Log\n"
        "Version 1.0 — initial release with full documentation.\n"
    ))

    write("DATA_GOVERNANCE.md", (
        "# Data Governance\n\n"
        "## Data Sources\n"
        "Training data sourced from validated datasets.\n\n"
        "## Data Quality\n"
        "Completeness, accuracy, representativeness, and bias assessment documented.\n\n"
        "## Data Preprocessing\n"
        "Steps: deduplication, anonymization, class balancing.\n\n"
        "## Data Retention\n"
        "Retention period: 2 years. Deletion: automated on expiry.\n\n"
        "## GDPR Compliance\n"
        "DPIA completed. DPA with sub-processors. Privacy notice updated.\n"
    ))

    write("HUMAN_OVERSIGHT.md", (
        "# Human Oversight\n\n"
        "## Oversight Mechanism\n"
        "Human-in-the-loop for high-stakes decisions.\n\n"
        "## Responsible Persons\n"
        "AI Operator role defined with required qualifications.\n\n"
        "## Intervention Mechanisms\n"
        "Override: API kill switch. Stop: systemctl stop. Escalation: PagerDuty.\n\n"
        "## Monitoring\n"
        "Real-time monitoring via Grafana. All decisions logged to audit trail.\n\n"
        "## Training\n"
        "Operator training required before first use. Annual refresher.\n"
    ))

    write("ROBUSTNESS.md", (
        "# Robustness and Cybersecurity\n\n"
        "## Accuracy\n"
        "Accuracy 94.2% on representative test set. Precision 92.1%, Recall 95.3%.\n\n"
        "## Robustness Testing\n"
        "Adversarial inputs tested. Out-of-distribution data tested.\n"
        "Stress testing under high load completed.\n\n"
        "## Cybersecurity\n"
        "Input validation, output filtering, API authentication implemented.\n\n"
        "## Fallback Behavior\n"
        "On error: graceful degradation with human escalation.\n\n"
        "## Update & Maintenance\n"
        "Monthly security updates. Model retraining schedule documented.\n"
    ))

    write("TRANSPARENCY.md", (
        "# Transparency — EU AI Act Art. 13 & 52\n\n"
        "## System Description\n"
        "This AI system performs [purpose]. It uses [frameworks] to [function].\n"
        "Provider: [Organization]. Version: 1.0.\n\n"
        "## Capabilities and Limitations\n"
        "Capabilities: [what the system can do].\n"
        "Limitations: [known edge cases, failure modes, out-of-scope uses].\n\n"
        "## Human Oversight Instructions\n"
        "Deployers must ensure qualified human oversight per Art. 14.\n"
        "Override procedure: [description]. Escalation path: [description].\n\n"
        "## Performance Metrics\n"
        "Accuracy: [%] on [test set]. Precision: [%]. Recall: [%].\n"
        "Benchmark conditions: [description].\n\n"
        "## Maintenance Instructions\n"
        "Update schedule: monthly. Contact for support: contact@example.com.\n"
        "Retraining triggers: [description].\n\n"
        "## AI Disclosure\n"
        "This system uses artificial intelligence.\n"
        "AI models: [list models]. Disclosure provided before first user interaction.\n\n"
        "## User Notification\n"
        "Users are informed before interaction via UI notice and documentation.\n\n"
        "## AI-Generated Content Labeling\n"
        "Outputs labeled [AI-generated] in metadata and visible labels.\n\n"
        "## Contact\n"
        "Questions about this AI system: contact@example.com\n"
    ))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_past_deadline_returns_error(tmp_path):
    """A deadline in the past should return an error response."""
    result = _roadmap(tmp_path, deadline="2020-01-01")
    assert "error" in result, "Expected 'error' key for past deadline"


def test_empty_project_returns_steps(tmp_path):
    """An empty project with high risk should have non-empty steps."""
    result = _roadmap(tmp_path, risk_category="high")
    assert "steps" in result, "Expected 'steps' key in roadmap result"
    assert isinstance(result["steps"], list), "steps should be a list"
    assert len(result["steps"]) > 0, "Empty project should have compliance steps to take"


def test_steps_have_required_fields(tmp_path):
    """Each step must contain: step, week, article, action, effort_days."""
    result = _roadmap(tmp_path, risk_category="high")
    required_fields = {"step", "week", "article", "action", "effort_days"}
    for i, step in enumerate(result["steps"]):
        missing = required_fields - set(step.keys())
        assert not missing, f"Step {i+1} is missing fields: {missing}"


def test_compliance_pct_increases_per_step(tmp_path):
    """compliance_pct_after should be non-decreasing across steps."""
    result = _roadmap(tmp_path, risk_category="high")
    steps = result["steps"]
    if len(steps) < 2:
        pytest.skip("Need at least 2 steps to check monotonicity")
    for i in range(1, len(steps)):
        prev = steps[i - 1]["compliance_pct_after"]
        curr = steps[i]["compliance_pct_after"]
        assert curr >= prev, (
            f"Step {i+1} compliance_pct_after ({curr}) is lower than step {i} ({prev})"
        )


def test_fully_compliant_project_no_steps(tmp_path):
    """A project with all required docs fully populated should have no steps."""
    _make_compliant_project(tmp_path)
    result = _roadmap(tmp_path, risk_category="high")
    assert "steps" in result, "Expected 'steps' key in result"
    assert result["steps"] == [], (
        f"Expected no steps for fully compliant project, got {len(result['steps'])} step(s): "
        + str([s['check'] for s in result['steps']])
    )


def test_roadmap_has_days_remaining(tmp_path):
    """days_remaining should be a positive integer."""
    result = _roadmap(tmp_path, risk_category="high")
    assert "days_remaining" in result, "Expected 'days_remaining' key"
    assert isinstance(result["days_remaining"], int), "days_remaining should be int"
    assert result["days_remaining"] > 0, "days_remaining should be > 0 for a future deadline"


def test_art52_step_comes_first_for_limited(tmp_path):
    """For limited risk with no transparency doc, first step should address Art. 52."""
    result = _roadmap(tmp_path, risk_category="limited")
    steps = result["steps"]
    assert len(steps) > 0, "Expected at least one step for empty limited-risk project"
    first_step = steps[0]
    assert first_step["article"] == "Art. 52", (
        f"Expected first step to address Art. 52 (transparency), got {first_step['article']}"
    )


def test_total_effort_is_sum_of_steps(tmp_path):
    """total_effort_days must equal the sum of effort_days across all steps."""
    result = _roadmap(tmp_path, risk_category="high")
    steps = result["steps"]
    computed_total = sum(s["effort_days"] for s in steps)
    assert result["total_effort_days"] == computed_total, (
        f"total_effort_days ({result['total_effort_days']}) != sum of steps ({computed_total})"
    )
