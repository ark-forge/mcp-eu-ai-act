# EU AI Act Compliance Checker - MCP Server

![CI](https://github.com/ark-forge/mcp-eu-ai-act/workflows/QA%20-%20MCP%20EU%20AI%20Act/badge.svg)
![Version](https://img.shields.io/badge/version-1.1.0-blue)
![MCP](https://img.shields.io/badge/MCP-1.0-green)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)

> **The EU AI Act is now in force.** Non-compliant AI systems face fines up to 35M or 7% of global revenue.
> This MCP server scans your codebase, detects AI frameworks, classifies risk level, and tells you exactly what's missing.

**3 commands. 2 minutes. Know where you stand.**

```bash
git clone https://github.com/ark-forge/mcp-eu-ai-act.git
cd mcp-eu-ai-act
python3 example_usage.py
```

Learn more: [arkforge.fr/mcp-eu-ai-act](https://arkforge.fr/mcp-eu-ai-act.html)

---

## What It Does

| Step | Action | Output |
|------|--------|--------|
| 1 | **Scan** your project | Detects OpenAI, Anthropic, HuggingFace, TensorFlow, PyTorch, LangChain |
| 2 | **Classify** risk level | Unacceptable / High / Limited / Minimal (per EU AI Act) |
| 3 | **Check** compliance | Pass/Fail on each regulatory requirement |
| 4 | **Report** findings | JSON report with actionable recommendations |

## Installation

### Via Smithery (Recommended)

```bash
smithery install @arkforge/mcp-eu-ai-act
```

[Smithery](https://smithery.ai) is the official MCP server registry.

### Manual Installation

```bash
git clone https://github.com/ark-forge/mcp-eu-ai-act.git
cd mcp-eu-ai-act
python3 server.py
```

No dependencies required. Pure Python 3.8+.

## Quick Start

```python
from server import MCPServer

server = MCPServer()

# Scan a project for AI frameworks
scan = server.handle_request("scan_project", {"project_path": "/your/project"})

# Check compliance (limited risk by default)
check = server.handle_request("check_compliance", {
    "project_path": "/your/project",
    "risk_category": "high"  # or "limited", "minimal", "unacceptable"
})

# Generate a full compliance report
report = server.handle_request("generate_report", {"project_path": "/your/project"})
```

See [`examples/`](./examples/) for complete runnable examples.

## MCP Tools

### `scan_project`

Scans a project to detect AI model usage.

```json
// Input
{ "project_path": "/path/to/project" }

// Output
{
  "files_scanned": 150,
  "ai_files": [{"file": "src/main.py", "frameworks": ["openai", "langchain"]}],
  "detected_models": {"openai": ["src/main.py"], "langchain": ["src/main.py"]}
}
```

### `check_compliance`

Verifies EU AI Act compliance for a given risk category.

```json
// Input
{ "project_path": "/path/to/project", "risk_category": "limited" }

// Output
{
  "risk_category": "limited",
  "compliance_status": {"transparency": true, "user_information": true, "content_labeling": false},
  "compliance_score": "2/3",
  "compliance_percentage": 66.7
}
```

### `generate_report`

Generates a complete compliance report with recommendations.

```json
// Input
{ "project_path": "/path/to/project", "risk_category": "high" }

// Output
{
  "report_date": "2026-02-09T10:30:00",
  "scan_summary": {"files_scanned": 150, "ai_files_detected": 5},
  "compliance_summary": {"risk_category": "high", "compliance_percentage": 50.0},
  "recommendations": ["Missing: Risk management system", "Missing: Human oversight documentation"]
}
```

## EU AI Act - Risk Categories

| Category | Examples | Key Requirements | Max Fine |
|----------|----------|-----------------|----------|
| **Unacceptable** | Social scoring, mass biometric surveillance | **Prohibited** | 35M / 7% revenue |
| **High** | Recruitment, credit scoring, law enforcement | Full documentation, risk management, human oversight | 15M / 3% revenue |
| **Limited** | Chatbots, recommendation systems, content generation | Transparency, user information, content labeling | 7.5M / 1.5% revenue |
| **Minimal** | Spam filters, video games | No specific obligations | - |

## Detected Frameworks

- **OpenAI** - GPT-3.5, GPT-4, OpenAI API
- **Anthropic** - Claude, Anthropic API
- **HuggingFace** - Transformers, pipelines, models
- **TensorFlow** - Keras, .h5 models
- **PyTorch** - .pt, .pth models
- **LangChain** - LLM chains, agents

## MCP Integration

Works with any MCP-compatible client:
- Claude Code
- VS Code with MCP extension
- CI/CD pipelines (GitHub Actions, GitLab CI)
- Custom integrations via JSON protocol

## Official Resources

- [EU AI Act - Official text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52021PC0206)
- [European Commission - AI](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [Compliance guide](https://artificialintelligenceact.eu/)

## Roadmap

- [ ] Integration with EU compliance databases
- [ ] Multi-language support (FR, EN, DE, ES)
- [ ] PDF report export
- [ ] CI/CD native integration (GitHub Actions, GitLab CI)
- [ ] Automatic compliance documentation generation

## License

MIT License - See [LICENSE](./LICENSE) for details.

---

Built by [ArkForge](https://arkforge.fr) | [Documentation](https://arkforge.fr/mcp-eu-ai-act.html)
