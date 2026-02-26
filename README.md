# EU AI Act Compliance Scanner — MCP Server

Static analysis tool that scans codebases for AI framework usage and checks compliance against EU AI Act requirements.

## Quick Start

```bash
git clone https://github.com/ark-forge/mcp-eu-ai-act.git
cd mcp-eu-ai-act
pip install mcp
python3 server.py
```

Runs on Python 3.10+.

### Full install

```bash
git clone https://github.com/ark-forge/mcp-eu-ai-act.git
cd mcp-eu-ai-act
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 server.py
```

### Run tests

```bash
pip install pytest
pytest tests/ -v
```

## Usage Examples

Once connected via MCP (see integration below), call tools by name.

### Scan a project for AI frameworks

**Tool**: `scan_project` — **Input**: `{"project_path": "/path/to/your/app"}`

```json
{
  "files_scanned": 42,
  "ai_files": [
    {"file": "src/chat.py", "frameworks": ["openai"]},
    {"file": "requirements.txt", "frameworks": ["openai"], "source": "config"}
  ],
  "detected_models": {"openai": ["src/chat.py", "requirements.txt"]}
}
```

### Check compliance for a high-risk system

**Tool**: `check_compliance` — **Input**: `{"project_path": "/path/to/your/app", "risk_category": "high"}`

```json
{
  "risk_category": "high",
  "compliance_status": {
    "technical_documentation": true,
    "risk_management": false,
    "transparency": true,
    "data_governance": false,
    "human_oversight": false,
    "robustness": false
  },
  "compliance_score": "2/6",
  "compliance_percentage": 33.3
}
```

## MCP Integration

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "eu-ai-act": {
      "command": "python3",
      "args": ["/path/to/mcp-eu-ai-act/server.py"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add eu-ai-act python3 /path/to/mcp-eu-ai-act/server.py
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "eu-ai-act": {
      "command": "python3",
      "args": ["/path/to/mcp-eu-ai-act/server.py"]
    }
  }
}
```

### HTTP mode (for CI/CD or remote clients)

```bash
pip install uvicorn
python3 server.py --http
# Listening on 0.0.0.0:8089
```

## Tools

### `scan_project`

Detects AI framework usage in source code and config/manifest files. Scans `.py`, `.js`, `.ts`, `.java`, `.go`, `.rs`, `.cpp`, `.c` plus dependency files (`requirements.txt`, `package.json`, `pyproject.toml`, etc.).

**Parameters:** `project_path` (string, required) — absolute path to scan.

### `check_compliance`

Checks EU AI Act compliance for a given risk category. Verifies required documentation files exist (`RISK_MANAGEMENT.md`, `TRANSPARENCY.md`, etc.) and checks for AI disclosure patterns.

**Parameters:** `project_path` (string, required), `risk_category` (string, default: `limited` — one of `unacceptable`, `high`, `limited`, `minimal`).

### `generate_report`

Runs scan + compliance check, returns a combined report with actionable recommendations per failing check. Each recommendation includes the relevant EU article, steps, and effort estimate.

**Parameters:** `project_path` (string, required), `risk_category` (string, default: `limited`).

### `suggest_risk_category`

Suggests a risk category from a plain-text description of your AI system. Matches against EU AI Act criteria (Art. 5, Annex III, Art. 52).

**Parameters:** `system_description` (string, required) — what your AI system does.

### `generate_compliance_templates`

Returns starter markdown templates for each required compliance document. Save them in `docs/` and fill in the bracketed sections.

**Parameters:** `risk_category` (string, default: `high`). For `high` risk: Risk Management, Technical Documentation, Data Governance, Human Oversight, Robustness, Transparency.

### GDPR Tools

Also includes `gdpr_scan_project`, `gdpr_check_compliance`, `gdpr_generate_report`, and `gdpr_generate_templates` for GDPR personal data processing compliance.

## REST API

A separate HTTP API (`paywall_api.py`) provides rate-limited REST endpoints for CI/CD and external clients.

```bash
python3 paywall_api.py
# Listening on 0.0.0.0:8091
```

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/v1/status` | None | Service status + your rate limit |
| `GET` | `/api/usage` | None | Current free-tier usage for your IP |
| `POST` | `/api/v1/scan` | Free/Pro | Scan a project for AI frameworks |
| `POST` | `/api/v1/check-compliance` | Free/Pro | Check EU AI Act compliance |
| `POST` | `/api/v1/generate-report` | Free/Pro | Full compliance report |
| `POST` | `/api/v1/scan-repo` | Internal | Scan a GitHub repo (Trust Layer integration) |

**Free tier**: 10 scans/day per IP, no sign-up required.
**Pro tier**: Unlimited scans, `X-API-Key` header. 29 EUR/month via [mcp.arkforge.fr/fr/pricing.html](https://mcp.arkforge.fr/fr/pricing.html).

### Example: scan via REST

```bash
curl -X POST https://mcp.arkforge.fr/mcp/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"project_path": "/path/to/your/project"}'
```

## Configuration

For the REST API (Stripe payments, email notifications), create a `settings.env`:

```env
STRIPE_LIVE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
TRUST_LAYER_INTERNAL_SECRET=<random-64-char-hex>
SMTP_HOST=ssl0.ovh.net
IMAP_USER=contact@example.com
IMAP_PASSWORD=...
```

Set `SETTINGS_ENV_PATH` to the file location (defaults to `/opt/claude-ceo/config/settings.env`).

## Supported Frameworks (16)

| Framework | Detection covers |
|-----------|-----------------|
| OpenAI | GPT-3.5, GPT-4, GPT-4o, o1, o3, embeddings |
| Anthropic | Claude (Opus, Sonnet, Haiku) |
| Google Gemini | Gemini Pro, Ultra, 1.5, 2, 3, Flash |
| Vertex AI | Google Cloud AI Platform |
| Mistral | Mistral Large/Medium/Small, Mixtral, Codestral, Magistral |
| Cohere | Command-R, Command-R+, embeddings |
| HuggingFace | Transformers, Diffusers, Accelerate, SmolAgents |
| TensorFlow | Keras, .h5 model files |
| PyTorch | .pt/.pth model files, nn.Module |
| LangChain | Core, Community, OpenAI, Anthropic integrations |
| AWS Bedrock | Bedrock Runtime, Agent Runtime |
| Azure OpenAI | Azure AI OpenAI Service |
| Ollama | Local model inference |
| LlamaIndex | VectorStoreIndex, SimpleDirectoryReader |
| Replicate | Cloud model inference |
| Groq | Fast inference API |

Detection works on both source code imports and dependency declarations in config files.

## EU AI Act Risk Categories

| Category | Examples | Key obligations |
|----------|----------|----------------|
| Unacceptable | Social scoring, mass biometric surveillance | Prohibited |
| High | Recruitment, credit scoring, law enforcement | Documentation, risk management, human oversight |
| Limited | Chatbots, content generation | Transparency, user disclosure, content marking |
| Minimal | Spam filters, video games | None |

## Rate Limiting

Free tier: 10 scans/day per IP. Pro API keys (`X-API-Key` header or `Authorization: Bearer`) bypass limits.

## Limitations

- Static analysis only — detects imports and patterns, not runtime behavior
- Cannot determine risk category automatically from code alone (use `suggest_risk_category` with a description)
- Compliance checks verify documentation exists, not its content quality
- File scanning limited to 5,000 files and 1 MB per file
- Certain system paths are blocked from scanning for security

## ArkForge ecosystem

This scanner is the first service sold autonomously through the ArkForge Trust Layer — a certifying proxy that turns API calls into verifiable, paid, tamper-proof transactions.

```
Agent Client  →  Trust Layer  →  EU AI Act Scanner
   pays            certifies         delivers
```

| Component | Description | Repo |
|-----------|-------------|------|
| **Trust Layer** | Certifying proxy — billing, proof chain, verification | [ark-forge/trust-layer](https://github.com/ark-forge/trust-layer) |
| **MCP EU AI Act** | Compliance scanner (this repo) | [ark-forge/mcp-eu-ai-act](https://github.com/ark-forge/mcp-eu-ai-act) |
| **Proof Spec** | Open specification + test vectors for the proof format | [ark-forge/proof-spec](https://github.com/ark-forge/proof-spec) |
| **Agent Client** | Autonomous buyer — proof-of-concept of a non-human customer | [ark-forge/arkforge-agent-client](https://github.com/ark-forge/arkforge-agent-client) |


## License

MIT
