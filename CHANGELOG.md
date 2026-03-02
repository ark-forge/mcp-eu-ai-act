# Changelog

All notable changes to the EU AI Act Compliance Scanner MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-03-02

### Added
- `combined_compliance_report` MCP tool: detects GDPR + EU AI Act dual-compliance hotspots in a single scan
  - File-level correlation: identifies files where both regulations apply simultaneously
  - Overlap detection for 5 patterns: AI+PII, AI+automated tracking, AI+geolocation, AI+file uploads, AI+cookie tracking
  - Combined requirements per file, citing specific articles (GDPR Art. 22/35, EU AI Act Art. 11/13/14)
  - Priority scoring (critical/high/medium/low) based on risk category and data sensitivity
  - Key insight summary for quick triage
- 27 new tests for `combined_compliance_report` (418 total)

## [1.2.0] - 2026-02-26

### Added
- REST API payload size limit (1 MB) to prevent abuse
- 25 new tests: 11 security tests (path traversal, injection) + 14 scanner accuracy tests
- Startup logging for configuration status (Stripe, secrets)
- `requirements.txt` with pinned dependencies
- 10 additional AI framework detections: Gemini, Mistral, Cohere, Bedrock, Azure OpenAI, Ollama, LlamaIndex, Vertex AI, Replicate, Groq (total: 16)
- `suggest_risk_category` and `generate_compliance_templates` MCP tools
- GDPR compliance tools (`gdpr_scan_project`, `gdpr_check_compliance`, `gdpr_generate_report`, `gdpr_generate_templates`)

### Fixed
- Bare `except:` replaced with `except OSError:` in filesystem operations
- Internal API secret no longer hardcoded — reads from `TRUST_LAYER_INTERNAL_SECRET` env var
- `/api/v1/status` no longer returns 302 redirect (nginx routing fix)

### Security
- Path traversal protection verified via test suite
- Payload size enforcement on all REST endpoints

## [1.1.0] - 2026-02-17

### Changed
- Translated entire codebase from French to English (code, docs, tests)
- Standardized all repository URLs to `github.com/ark-forge/mcp-eu-ai-act`
- Replaced deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)`
- Removed internal report files not relevant to public distribution
- Compliance status keys renamed for consistency:
  - `transparence` -> `transparency`
  - `information_utilisateurs` -> `user_disclosure`
  - `marquage_contenu` -> `content_marking`
  - `documentation_technique` -> `technical_documentation`
  - `gestion_risques` -> `risk_management`
  - `gouvernance_donnees` -> `data_governance`
  - `surveillance_humaine` -> `human_oversight`
  - `documentation_basique` -> `basic_documentation`

### Added
- CHANGELOG.md
- TERMS_OF_USE.md
- Clean install test script
- Pre-publication quality gate validation

## [1.0.0] - 2026-02-09

### Added
- Initial release of the EU AI Act Compliance Checker MCP Server
- 3 MCP tools: `scan_project`, `check_compliance`, `generate_report`
- Detection of 6 AI frameworks: OpenAI, Anthropic, HuggingFace, TensorFlow, PyTorch, LangChain
- 4-tier risk categorization: unacceptable, high, limited, minimal
- Compliance verification against EU AI Act requirements
- JSON report generation with actionable recommendations
- 92 tests with 85%+ coverage
- CI/CD pipeline with GitHub Actions
- Smithery deployment configuration
- Docker support
