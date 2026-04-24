# EU AI Act Compliance Toolkit — MCP Server

[![GitHub Stars](https://img.shields.io/github/stars/ark-forge/mcp-eu-ai-act?style=flat&label=⭐%20Star%20this%20repo)](https://github.com/ark-forge/mcp-eu-ai-act/stargazers)
[![PyPI version](https://badge.fury.io/py/eu-ai-act-scanner.svg)](https://pypi.org/project/eu-ai-act-scanner/)
[![Works with Claude](https://img.shields.io/badge/Works%20with-Claude-blueviolet)](https://claude.ai)
[![Works with Cursor](https://img.shields.io/badge/Works%20with-Cursor-blue)](https://cursor.com)

If this tool helps your compliance work, a ⭐ on GitHub helps others discover it.

One call. Zero config. Full EU AI Act + GDPR compliance report in under 10 seconds.

Detects 16 AI frameworks in your codebase, maps each to binding legal articles, returns pass/fail with fix instructions. Free tier, no API key needed.

**August 2, 2026 enforcement deadline. Fines up to 35M EUR or 7% global turnover.**

> **Need audit-grade proof?** Certify every scan with [ArkForge Trust Layer](https://arkforge.tech/trust?utm_source=github_readme) — tamper-proof, timestamped compliance evidence. 500 free proofs/month.

## What's New in v2

| Feature | Description |
|---------|-------------|
| `generate_compliance_roadmap` | Week-by-week action plan to reach compliance before your deadline |
| `generate_annex4_package` | Auditor-ready ZIP with all 8 Annex IV sections populated from your code |
| `certify_compliance_report` | Cryptographic proof via Trust Layer (EU AI Act Art. 12) |
| Content scoring | `check_compliance` now scores document *content* (0-100), not just existence |
| Article mapping | Every finding mapped to specific EU AI Act article |

## Quick Start

### CLI (scan any project in 10 seconds)

```bash
pip install eu-ai-act-scanner
cd your-project/
eu-ai-act-scanner
```

Or specify a path directly: `eu-ai-act-scanner /path/to/your/project`

### MCP Server (from source)

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

## MCP Integration

### Install from PyPI (recommended)

```bash
pip install eu-ai-act-scanner
```

### Claude Code

```bash
claude mcp add eu-ai-act -- eu-ai-act-mcp
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "eu-ai-act": {
      "command": "eu-ai-act-mcp"
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "eu-ai-act": {
      "command": "eu-ai-act-mcp"
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

## Tools Reference

### 1. `scan_project`

Detects AI framework usage in source code and config/manifest files. Supports 16 frameworks across Python, JS, TS, Go, Java, and Rust.

**Key parameters:** `project_path` (string, required)

**Example output:**
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

---

### 2. `check_compliance`

Scores document *content* quality (0-100) and maps each finding to a specific EU AI Act article. Score ≥40 = pass. Fully backward compatible with v1.

**Key parameters:** `project_path` (string, required), `risk_category` (string, default: `limited`)

**Example output (v2):**
```json
{
  "risk_category": "high",
  "compliance_score": "4/6",
  "compliance_percentage": 66.7,
  "content_scores": {
    "RISK_MANAGEMENT.md": 82,
    "TRANSPARENCY.md": 45,
    "DATA_GOVERNANCE.md": 12
  },
  "article_map": {
    "art_9": {"status": "pass", "score": 82},
    "art_10": {"status": "fail", "score": 12},
    "art_13": {"status": "pass", "score": 45}
  }
}
```

---

### 3. `generate_compliance_roadmap` — NEW in v2

Deadline-aware, week-by-week action plan to reach EU AI Act compliance before August 2, 2026. Sequences quick wins first using a criticality × 1/effort algorithm.

**Key parameters:** `project_path` (string, required), `risk_category` (string), `target_date` (string, ISO format, default: `2026-08-02`)

**Example output:**
```json
{
  "weeks_remaining": 16,
  "phases": [
    {
      "week": 1,
      "action": "Add TRANSPARENCY.md with user disclosure statement",
      "article": "Art. 13",
      "effort_days": 1,
      "priority": "critical"
    },
    {
      "week": 2,
      "action": "Draft risk management procedure covering Art. 9 requirements",
      "article": "Art. 9",
      "effort_days": 3,
      "priority": "high"
    }
  ],
  "estimated_completion_week": 8
}
```

---

### 4. `generate_report`

Runs scan + compliance check, returns a combined report with two-level output: executive summary for DPO/legal and technical breakdown for developers. Article-by-article citations included.

**Key parameters:** `project_path` (string, required), `risk_category` (string, default: `limited`)

**Example output:**
```json
{
  "executive_summary": {
    "compliance_percentage": 67,
    "deadline": "2026-08-02",
    "days_remaining": 117,
    "gap_count": 3,
    "verdict": "Action required — 3 gaps must be addressed before deadline"
  },
  "technical_breakdown": {
    "art_9": {"status": "fail", "missing": ["hazard identification section", "residual risk log"]},
    "art_13": {"status": "pass", "score": 78}
  },
  "recommendations": [
    {"article": "Art. 9", "action": "Add hazard identification section to RISK_MANAGEMENT.md", "effort": "2 days"}
  ]
}
```

---

### 5. `suggest_risk_category`

Classifies your AI system into an EU AI Act risk category from a plain-text description. Matches against Art. 5 (prohibited), Annex III (high-risk), Art. 52 (limited), and minimal.

**Key parameters:** `system_description` (string, required)

**Example output:**
```json
{
  "suggested_category": "high",
  "confidence": "high",
  "matched_criteria": ["Annex III, Category 4 — AI in employment decisions"],
  "obligations_summary": "Technical documentation, risk management, human oversight, data governance, transparency"
}
```

---

### 6. `generate_compliance_templates`

Returns starter markdown templates for each required compliance document. Save them in `docs/` and fill in the bracketed sections.

**Key parameters:** `risk_category` (string, default: `high`)

For `high` risk: Risk Management (Art. 9), Technical Documentation (Art. 11), Data Governance (Art. 10), Human Oversight (Art. 14), Robustness (Art. 15), Transparency (Art. 13).

---

### 7. `generate_annex4_package` — NEW in v2

Generates an auditor-ready ZIP with all 8 Annex IV sections populated from your actual project files. Optionally certifies with Trust Layer for cryptographic proof.

**Key parameters:** `project_path` (string, required), `sign_with_trust_layer` (bool, default: `false`), `trust_layer_key` (string, optional)

**Example output:**
```json
{
  "package_path": "/tmp/annex4_myproject_20260407.zip",
  "sha256": "a3f8c2d1...",
  "sections_populated": 8,
  "sections_missing_data": ["section_6_accuracy_metrics"],
  "proof_id": "prf_01j9z8x7w6v5u4t3s2r1",
  "verification_url": "https://trust.arkforge.tech/verify/prf_01j9z8x7w6v5u4t3s2r1"
}
```

---

### 8. `certify_compliance_report` — NEW in v2

Certifies any compliance report with ArkForge Trust Layer. Returns a tamper-proof `proof_id` and public verification URL for your auditor (EU AI Act Art. 12 audit trail).

**Key parameters:** `report_data` (string, JSON-serialized report), `trust_layer_key` (string, required)

**Example output:**
```json
{
  "proof_id": "prf_01j9z8x7w6v5u4t3s2r1",
  "timestamp": "2026-04-07T14:32:00Z",
  "sha256": "a3f8c2d1e4b5...",
  "verification_url": "https://trust.arkforge.tech/verify/prf_01j9z8x7w6v5u4t3s2r1",
  "article": "EU AI Act Art. 12"
}
```

---

### 9. `gdpr_scan_project`

Scans for personal data processing patterns: PII fields, tracking pixels, geolocation, file uploads, cookie patterns. Maps to GDPR Art. 22/35 requirements.

**Key parameters:** `project_path` (string, required)

---

### 10. `combined_compliance_report`

Runs GDPR + EU AI Act scans simultaneously and identifies dual-compliance hotspots — files where both regulations apply at once.

**Key parameters:** `project_path` (string, required), `risk_category` (string, default: `limited`)

**Example output:**
```json
{
  "hotspots": [
    {
      "file": "src/hiring_model.py",
      "eu_ai_act_risk": "high",
      "gdpr_risk": "high",
      "overlap_patterns": ["AI+PII", "AI+automated_decision"],
      "combined_articles": ["EU AI Act Art. 14", "GDPR Art. 22"],
      "priority": "critical"
    }
  ],
  "key_insight": "2 files require simultaneous GDPR + EU AI Act remediation"
}
```

---

## Certify Your Compliance (EU AI Act Art. 12)

The only MCP that generates cryptographically certified compliance evidence.

```python
# Step 1: Generate Annex IV package and certify it
generate_annex4_package(
    project_path="/path/to/project",
    sign_with_trust_layer=True,
    trust_layer_key="your_trust_layer_key"
)
# → Returns proof_id + public verification URL for your auditor

# Step 2: Or certify any compliance report directly
certify_compliance_report(
    report_data='{"compliance_percentage": 87, "risk_category": "high"}',
    trust_layer_key="your_trust_layer_key"
)
```

Free Trust Layer account: 500 certified proofs/month → [arkforge.tech](https://arkforge.tech/trust?utm_source=github_readme&utm_medium=referral)

## Pricing

| Plan | Price | Includes |
|------|-------|---------|
| Free | €0 | 5 scans/day · scan_project + suggest_risk_category |
| Pro | €29/month | Unlimited scans · all 10 tools · compliance roadmap · Annex IV package |
| Certified | €99/month | Everything in Pro + Trust Layer certification on every report |

[Get your API key →](https://arkforge.tech/en/mcp-eu-ai-act.html?utm_source=github_readme&utm_medium=referral)

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
| `POST` | `/api/v1/scan-repo` | Free (rate-limited) | Scan a GitHub repo by URL |
| `POST` | `/api/checkout` | None | Stripe checkout session |
| `POST` | `/api/webhook` | Stripe sig | Stripe webhook handler |

**Free tier**: 5 scans/day per IP, no sign-up required.
**Pro tier**: Unlimited scans, `X-API-Key` header. 29 EUR/month via [arkforge.tech/en/mcp-eu-ai-act.html](https://arkforge.tech/en/mcp-eu-ai-act.html?utm_source=pypi).

### Example: scan via REST

```bash
curl -X POST https://arkforge.tech/mcp/api/v1/scan \
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

## Limitations

- Static analysis only — detects imports and patterns, not runtime behavior
- Cannot determine risk category automatically from code alone (use `suggest_risk_category` with a description)
- `check_compliance` scores content quality — documents with boilerplate/placeholder text will score low
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
| **MCP EU AI Act** | Compliance toolkit (this repo) | [ark-forge/mcp-eu-ai-act](https://github.com/ark-forge/mcp-eu-ai-act) |
| **Proof Spec** | Open specification + test vectors for the proof format | [ark-forge/proof-spec](https://github.com/ark-forge/proof-spec) |
| **Agent Client** | Autonomous buyer — proof-of-concept of a non-human customer | [ark-forge/arkforge-agent-client](https://github.com/ark-forge/arkforge-agent-client) |

## Community

- **Questions / integration help** → [GitHub Discussions Q&A](https://github.com/ark-forge/mcp-eu-ai-act/discussions/8)
- **Bug reports** → [Open an issue](https://github.com/ark-forge/mcp-eu-ai-act/issues)
- **Feature requests** → [Open an issue](https://github.com/ark-forge/mcp-eu-ai-act/issues) or join the discussion
- **Share your experience** → [Tell us what compliance gaps you found](https://github.com/ark-forge/mcp-eu-ai-act/discussions/3)

## Roadmap

- **v3**: GPAI obligations module (Art. 51-55, Code of Practice July 2025)  
- **v3**: GitHub Action for CI/CD compliance gates  
- **v3**: Runtime agentic compliance enforcement (Art. 14)

---

**Found this useful?** A ⭐ on GitHub helps other compliance teams discover the toolkit. Takes 2 seconds and helps a lot.

## License

MIT
