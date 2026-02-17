# EU AI Act Compliance Checker - MCP Server

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![MCP](https://img.shields.io/badge/MCP-1.0-green)
![License](https://img.shields.io/badge/license-MIT-green)
![CI/CD](https://github.com/ark-forge/mcp-eu-ai-act/actions/workflows/qa-mcp-eu-ai-act.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)

**Automated EU AI Act compliance verification for AI projects** - MCP Server to automatically check compliance with European Union AI Act regulations.

## Keywords
`EU AI Act` · `compliance checker` · `MCP server` · `AI regulation` · `risk assessment` · `artificial intelligence` · `legal compliance` · `transparency` · `Model Context Protocol` · `automated audit` · `GDPR` · `AI governance`

## Features

- **Automatic detection** of AI models (OpenAI, Anthropic, HuggingFace, TensorFlow, PyTorch, LangChain)
- **Risk categorization** according to EU AI Act (unacceptable, high, limited, minimal)
- **Compliance verification** with regulatory requirements
- **Detailed JSON reports** generation
- **Actionable recommendations** to achieve compliance
- **GDPR alignment** checking
- **MCP protocol integration** for seamless workflow

## EU AI Act - Risk Categories

### Unacceptable Risk (Prohibited)
- Behavioral manipulation
- Social scoring by governments
- Mass biometric surveillance

### High Risk
- Recruitment systems
- Credit scoring systems
- Law enforcement
- Critical infrastructure management

**Requirements**: Complete technical documentation, risk management, human oversight, EU registration

### Limited Risk
- Chatbots
- Recommendation systems
- Content generation

**Requirements**: Transparency, user information, AI content labeling

### Minimal Risk
- Anti-spam filters
- Video games
- Non-critical applications

**Requirements**: No specific obligations

## Installation

### Via Smithery (Recommended)

```bash
smithery install @arkforge/mcp-eu-ai-act
```

[Smithery](https://smithery.ai) is the official MCP server registry. Installing via Smithery ensures you get the latest stable version with automatic updates.

### Manual Installation

```bash
git clone https://github.com/ark-forge/mcp-eu-ai-act.git
cd mcp-eu-ai-act
chmod +x server.py
```

## Usage

### 1. Command Line

```bash
python3 server.py
```

### 2. As Python Module

```python
from server import MCPServer

# Initialize the server
server = MCPServer()

# Scan a project
scan_result = server.handle_request("scan_project", {
    "project_path": "/path/to/project"
})

# Check compliance
compliance_result = server.handle_request("check_compliance", {
    "project_path": "/path/to/project",
    "risk_category": "limited"  # or "high", "minimal", "unacceptable"
})

# Generate a complete report
report = server.handle_request("generate_report", {
    "project_path": "/path/to/project",
    "risk_category": "high"
})
```

## MCP Tools

### scan_project

Scans a project to detect AI model usage.

**Parameters**:
- `project_path` (string, required): Path to the project

**Returns**:
```json
{
  "files_scanned": 150,
  "ai_files": [
    {
      "file": "src/main.py",
      "frameworks": ["openai", "langchain"]
    }
  ],
  "detected_models": {
    "openai": ["src/main.py", "src/api.py"],
    "langchain": ["src/main.py"]
  }
}
```

### check_compliance

Verifies EU AI Act compliance.

**Parameters**:
- `project_path` (string, required): Path to the project
- `risk_category` (string, optional): Risk category (`unacceptable`, `high`, `limited`, `minimal`) - default: `limited`

**Returns**:
```json
{
  "risk_category": "limited",
  "description": "Limited risk systems (chatbots, deepfakes)",
  "requirements": [
    "Transparency obligations",
    "Clear user information about AI interaction"
  ],
  "compliance_status": {
    "transparency": true,
    "user_information": true,
    "content_labeling": false
  },
  "compliance_score": "2/3",
  "compliance_percentage": 66.7
}
```

### generate_report

Generates a complete compliance report.

**Parameters**:
- `project_path` (string, required): Path to the project
- `risk_category` (string, optional): Risk category - default: `limited`

**Returns**:
```json
{
  "report_date": "2026-02-09T10:30:00",
  "project_path": "/path/to/project",
  "scan_summary": {
    "files_scanned": 150,
    "ai_files_detected": 5,
    "frameworks_detected": ["openai", "langchain"]
  },
  "compliance_summary": {
    "risk_category": "limited",
    "compliance_score": "2/3",
    "compliance_percentage": 66.7
  },
  "detailed_findings": {
    "detected_models": {},
    "compliance_checks": {},
    "requirements": []
  },
  "recommendations": [
    "Missing documentation: Content Labeling",
    "Limited risk system - Ensure complete transparency"
  ]
}
```

## Detected Frameworks

The server automatically detects the following AI frameworks:

- **OpenAI**: GPT-3.5, GPT-4, OpenAI API
- **Anthropic**: Claude, Anthropic API
- **HuggingFace**: Transformers, pipelines, models
- **TensorFlow**: Keras, .h5 models
- **PyTorch**: .pt, .pth models
- **LangChain**: LLM chains, agents

## Compliance Checks

### For high-risk systems
- Technical documentation
- Risk management system
- Transparency and user information
- Data governance
- Human oversight
- Robustness and cybersecurity

### For limited-risk systems
- Transparency (README, docs)
- Information about AI usage
- Generated content labeling

### For minimal-risk systems
- Basic documentation

## Regulatory Requirements

This server verifies compliance with:
- **EU AI Act** (EU Regulation 2024/1689)
- **GDPR** (data protection)
- **Algorithmic transparency**
- **Documentation obligations**

## Example Report

```bash
$ python3 server.py

=== EU AI Act Compliance Checker - MCP Server ===

Available tools:
- scan_project: Scans a project to detect AI model usage
- check_compliance: Verifies EU AI Act compliance
- generate_report: Generates a complete compliance report

=== Testing with current project ===

1. Scanning project...
Files scanned: 150
AI files detected: 5
Frameworks: openai, anthropic

2. Checking compliance (limited risk)...
Compliance score: 2/3 (66.7%)
Status: Partial compliance

3. Generating full report...
Report generated successfully
```

## MCP Integration

This server is compatible with the Model Context Protocol and can be integrated into:
- Claude Code
- VS Code with MCP extension
- CI/CD tools
- Deployment pipelines

## EU AI Act Documentation

Official resources:
- [EU AI Act - Official text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52021PC0206)
- [European Commission - AI Act](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [Compliance guide](https://artificialintelligenceact.eu/)

## Contribution

This server is developed by ArkForge as part of the autonomous CEO system.

## License

MIT License - See LICENSE for details

## Roadmap

- [ ] Integration with EU compliance databases
- [ ] Multi-language support (FR, EN, DE, ES)
- [ ] Automatic compliance documentation generation
- [ ] Automatic risk scoring
- [ ] PDF report export
- [ ] CI/CD integration (GitHub Actions, GitLab CI)

---

**Version**: 1.0.0
**Date**: 2026-02-09
**Maintained by**: ArkForge CEO System
