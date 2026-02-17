# MCP Integration - EU AI Act Compliance Checker

## MCP Configuration

To integrate this server into an MCP-compatible system (Claude Code, VS Code, etc.), follow the steps below.

## 1. Claude Code Configuration

### MCP Configuration File

Create or modify the `~/.claude/mcp.json` file:

```json
{
  "mcpServers": {
    "eu-ai-act-compliance": {
      "command": "python3",
      "args": [
        "/path/to/mcp-eu-ai-act/server.py"
      ],
      "env": {},
      "metadata": {
        "name": "EU AI Act Compliance Checker",
        "description": "Verify EU AI Act compliance for AI projects",
        "version": "1.0.0",
        "author": "ArkForge"
      }
    }
  }
}
```

## 2. VS Code Configuration

### MCP Extension for VS Code

1. Install the MCP extension for VS Code
2. Add the configuration in `.vscode/mcp-servers.json`:

```json
{
  "servers": {
    "eu-ai-act-compliance": {
      "type": "python",
      "path": "/path/to/mcp-eu-ai-act/server.py",
      "enabled": true
    }
  }
}
```

## 3. Usage in Claude Code

Once configured, the MCP server will be available in Claude Code via commands:

### Scan a Project

```
@eu-ai-act-compliance scan_project /path/to/project
```

### Check Compliance

```
@eu-ai-act-compliance check_compliance /path/to/project --risk=limited
```

### Generate a Report

```
@eu-ai-act-compliance generate_report /path/to/project --risk=high
```

## 4. Programmatic Integration

### Python

```python
from server import MCPServer

server = MCPServer()

# Scan a project
result = server.handle_request("scan_project", {
    "project_path": "/path/to/project"
})

# Check compliance
result = server.handle_request("check_compliance", {
    "project_path": "/path/to/project",
    "risk_category": "high"
})

# Generate a report
result = server.handle_request("generate_report", {
    "project_path": "/path/to/project",
    "risk_category": "limited"
})
```

### REST API (via wrapper)

If you want to expose the MCP server via a REST API, create a Flask/FastAPI wrapper:

```python
from flask import Flask, request, jsonify
from server import MCPServer

app = Flask(__name__)
server = MCPServer()

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    result = server.handle_request("scan_project", data)
    return jsonify(result)

@app.route('/api/compliance', methods=['POST'])
def compliance():
    data = request.json
    result = server.handle_request("check_compliance", data)
    return jsonify(result)

@app.route('/api/report', methods=['POST'])
def report():
    data = request.json
    result = server.handle_request("generate_report", data)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

## 5. CI/CD Integration

### GitHub Actions

Create `.github/workflows/eu-ai-act-compliance.yml`:

```yaml
name: EU AI Act Compliance Check

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  compliance:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'

    - name: Install MCP Server
      run: |
        git clone https://github.com/ark-forge/mcp-eu-ai-act.git
        cd mcp-eu-ai-act
        pip install -r requirements.txt

    - name: Run Compliance Check
      run: |
        python3 mcp-eu-ai-act/server.py << EOF
        from server import MCPServer
        import json
        import sys

        server = MCPServer()
        result = server.handle_request("generate_report", {
            "project_path": ".",
            "risk_category": "high"
        })

        compliance_pct = result['results']['compliance_summary']['compliance_percentage']

        print(json.dumps(result, indent=2))

        if compliance_pct < 80:
            print(f"Compliance below threshold: {compliance_pct}%")
            sys.exit(1)
        else:
            print(f"Compliance OK: {compliance_pct}%")
            sys.exit(0)
        EOF
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
stages:
  - compliance

eu-ai-act-check:
  stage: compliance
  image: python:3.9
  script:
    - git clone https://github.com/ark-forge/mcp-eu-ai-act.git
    - cd mcp-eu-ai-act && pip install -r requirements.txt
    - python3 -c "
      from server import MCPServer;
      import sys;
      server = MCPServer();
      result = server.handle_request('check_compliance', {'project_path': '.', 'risk_category': 'high'});
      pct = result['results']['compliance_percentage'];
      print(f'Compliance: {pct}%');
      sys.exit(0 if pct >= 80 else 1)"
  only:
    - main
    - develop
```

## 6. Environment Variables

The server can be configured with environment variables:

```bash
# Log level
export MCP_LOG_LEVEL=INFO

# Minimum compliance threshold
export MCP_COMPLIANCE_THRESHOLD=80

# Default risk category
export MCP_DEFAULT_RISK_CATEGORY=limited
```

## 7. Monitoring and Logging

The server generates logs that can be captured:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/eu-ai-act-mcp.log'),
        logging.StreamHandler()
    ]
)
```

## 8. Integration Tests

Run tests before deployment:

```bash
# Unit tests
python3 test_server.py

# Integration tests
python3 example_usage.py

# Complete test with real project
python3 server.py
```

## 9. Dependencies

### Minimum Requirements

- Python 3.7+
- No external dependencies (uses only stdlib)

### Optional for Advanced Features

```txt
# For REST API
flask>=2.0.0
fastapi>=0.95.0
uvicorn>=0.20.0

# For PDF report generation
reportlab>=3.6.0

# For advanced analysis
pyyaml>=6.0
```

## 10. Security

### Best Practices

- The server is read-only (does not modify files)
- No arbitrary code execution
- File path validation
- Robust error handling
- No vulnerable external dependencies

### Limitations

- The server only scans and analyzes
- It does not collect external data
- It does not communicate over the network
- All processing is local

## Support

For any questions or issues:
- Issues: GitHub repository
- Email: support@arkforge.fr
- Documentation: README.md in the repository

---

**Version**: 1.0.0
**Last updated**: 2026-02-09
**Maintained by**: ArkForge
