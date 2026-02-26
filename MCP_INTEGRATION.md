# MCP Integration — EU AI Act Compliance Scanner

## 1. Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "eu-ai-act": {
      "command": "python3",
      "args": ["/absolute/path/to/mcp-eu-ai-act/server.py"]
    }
  }
}
```

Replace `/absolute/path/to/` with the actual installation directory (must be absolute).

## 2. Claude Code

```bash
claude mcp add eu-ai-act python3 /absolute/path/to/mcp-eu-ai-act/server.py
```

## 3. VS Code / Cursor

Add to `.vscode/mcp.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "eu-ai-act": {
      "command": "python3",
      "args": ["/absolute/path/to/mcp-eu-ai-act/server.py"]
    }
  }
}
```

## 4. HTTP Mode

For remote access, CI/CD, or non-MCP clients:

```bash
pip install uvicorn
python3 server.py --http
# Listening on 0.0.0.0:8089
```

## 5. REST API

A separate HTTP API (`paywall_api.py`) provides rate-limited REST endpoints:

```bash
python3 paywall_api.py
# Listening on 0.0.0.0:8091
```

### Scan via REST

```bash
# Free tier (10 scans/day per IP, no auth)
curl -X POST https://mcp.arkforge.fr/mcp/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"project_path": "/path/to/your/project"}'

# Pro tier (unlimited, API key required)
curl -X POST https://mcp.arkforge.fr/mcp/api/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_pro_key" \
  -d '{"project_path": "/path/to/your/project"}'
```

### REST Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/v1/status` | None | Service status + rate limit info |
| `GET` | `/api/usage` | None | Free-tier usage for your IP |
| `POST` | `/api/v1/scan` | Free/Pro | Scan for AI frameworks |
| `POST` | `/api/v1/check-compliance` | Free/Pro | Check EU AI Act compliance |
| `POST` | `/api/v1/generate-report` | Free/Pro | Full compliance report |
| `POST` | `/api/v1/scan-repo` | Internal | Scan a GitHub repo (Trust Layer integration) |

## 6. CI/CD Integration

### GitHub Actions

Use the REST API to add compliance checks to your pipeline:

```yaml
name: EU AI Act Compliance

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: EU AI Act Compliance Scan
      run: |
        RESULT=$(curl -sf -X POST https://mcp.arkforge.fr/mcp/api/v1/generate-report \
          -H "Content-Type: application/json" \
          -d "{\"project_path\": \"$GITHUB_WORKSPACE\", \"risk_category\": \"high\"}")

        echo "$RESULT" | python3 -m json.tool

        SCORE=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['results']['compliance_summary']['compliance_percentage'])")
        echo "Compliance score: ${SCORE}%"

        if [ "$(echo "$SCORE < 80" | bc)" -eq 1 ]; then
          echo "::error::Compliance below 80% threshold"
          exit 1
        fi
```

### GitLab CI

```yaml
eu-ai-act-check:
  stage: test
  image: python:3.12
  script:
    - |
      RESULT=$(curl -sf -X POST https://mcp.arkforge.fr/mcp/api/v1/check-compliance \
        -H "Content-Type: application/json" \
        -d '{"project_path": ".", "risk_category": "high"}')
      echo "$RESULT" | python3 -m json.tool
      PCT=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['results']['compliance_percentage'])")
      echo "Compliance: ${PCT}%"
      [ "$(echo "$PCT >= 80" | bc)" -eq 1 ] || exit 1
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

## 7. Dependencies

**Required:**
- Python 3.10+
- `mcp` library (for STDIO mode)

**For REST API:**
- `fastapi`
- `uvicorn`
- `stripe` (for Pro tier billing)

Install all:
```bash
pip install -r requirements.txt
```

## 8. Security

- Read-only: the server never modifies scanned files
- Path validation: blocks system directories (`/etc`, `/proc`, `/sys`, etc.)
- Payload size limit: 1 MB max on REST endpoints
- No arbitrary code execution
- All processing is local (MCP mode) or on the server (REST mode)

## Support

- Issues: [github.com/ark-forge/mcp-eu-ai-act/issues](https://github.com/ark-forge/mcp-eu-ai-act/issues)
- Email: contact@arkforge.fr

---

**Version**: 1.2.0
**Maintained by**: ArkForge
