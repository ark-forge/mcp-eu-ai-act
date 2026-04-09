# Changelog

All notable changes to the EU AI Act Compliance Scanner MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-07

### Added
- `generate_compliance_roadmap`: deadline-aware, week-by-week EU AI Act action plan — sequences quick wins first using criticality × 1/effort algorithm
- `generate_annex4_package`: auditor-ready ZIP with all 8 Annex IV sections populated from actual project files; optional Trust Layer certification
- `certify_compliance_report`: cryptographic certification via Trust Layer (EU AI Act Art. 12 audit trail); returns proof_id + public verification URL
- `data/eu_ai_act_articles.json`: structured knowledge base of 15 entries (Art. 5, 6, 9-15, 17, 25, 50, 52, Annex III, Annex IV) with requirements, checklists, content_keywords, and required_sections
- `executive_summary` field in `generate_report` output: DPO/legal-facing summary with deadline countdown and gap count
- `technical_breakdown` field in `generate_report` output: developer-facing article-by-article breakdown
- Stripe checkout and webhook endpoints in api_wrapper (`POST /api/checkout`, `POST /api/webhook`)
- 6 new documentation files in `docs/` (ARTICLES_REFERENCE, COMPLIANCE_ROADMAP_GUIDE, ANNEX4_FORMAT, TRUST_LAYER_INTEGRATION, MIGRATION_v1_to_v2, STRIPE_SETUP)

### Changed
- `check_compliance`: now scores document *content* quality (0-100) instead of checking file existence. Score ≥40 = pass. Fully backward compatible — all v1 fields preserved
- `check_compliance` v2 output adds `content_scores` (dict: filename → 0-100) and `article_map` (dict: article_id → {status, score})
- `check_compliance` now validates project path security (path traversal fix)
- CI coverage gate raised from 70% to 80%
- Pricing: new Free/Pro/Certified tiers (€0/€29/€99 per month) specific to EU AI Act MCP

### Infrastructure
- `scripts/deploy_mcp_eu_ai_act.sh`: production deploy script with 4 gates, staged rollout, OVH deploy, rollback, PyPI publish, Telegram notification
- `scripts/smoke_test_mcp_prod.py`: post-deploy smoke test verifying v2 fields present
- `scripts/update_changelog.py`: automated changelog generation from git log

### Tests
- 481 tests total (up from 418)
- New test files: test_articles_db.py (18), test_check_compliance_v2.py (10), test_backward_compat.py (8), test_compliance_roadmap.py (8), test_annex4_package.py (7), test_certify_report.py (5), + 9 new Stripe tests in test_paywall.py

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

## [2.0.4] — 2026-04-07

### Security
- remove files leaking internal infra paths (issue #10)
- fix X-Forwarded-For spoofing + bind 127.0.0.1 (pentest 2026-03-17)
- hook pre-commit détection secrets
- replace safety with pip-audit in security-scan job

### Added
- plan-gated access on paid MCP tools
- migrate MCP endpoint to mcp.arkforge.tech
- EU AI Act MCP v2.0.0 — compliance roadmap + Annex IV package + Trust Layer certification
- add Trust Layer CTA near top of README for GitHub visitors
- contextual Trust Layer CTA in Python server output
- add Trust Layer CTA to all scan/compliance outputs
- contextual upgrade CTA + SSE transport guidance

### Fixed
- correct payload fields + check compliance_percentage (v2)
- OVH_ENABLED=false — MCP runs on local server only
- correct port 8103→8200 + canary check field compliance_percentage
- repair failing test + OAuth PKCE flow for claude.ai web
- migrate all public emails arkforge.fr → arkforge.tech
- vault path + mcp_webhook_secret key in api_wrapper
- read config from vault instead of env vars + fix test mocks
- replace dead arkforge.fr/fr/pricing with arkforge.tech/en/pricing
- enable json_response mode to fix 406 for non-SSE clients
- add marketplace_api.py entry point — stop systemd crash loop
- allow mcp.arkforge.fr host header — fix 421 Misdirected Request
- remove orphaned test_marketplace_api.py after marketplace_api.py removal
- update Trust Layer CTA URL from arkforge.fr to arkforge.tech, README API URL to trust.arkforge.tech
- supprimer référence résiduelle INTERNAL_SECRET dans __main__
- /api/v1/scan-repo public + TOCTOU-safe scan cleanup

### Documentation
- add CONTRIBUTING.md + remove internal files from root

### Internal
- rename package eu-ai-act-scanner + bump to v2.0.0
- add eu_ai_act_articles.json knowledge base (force-add, excluded from .gitignore)
- add glama.json for Glama MCP directory listing
- migrate GitHub Actions to Node.js 22 runtime
- make PyPI publish failure visible — remove silent continue-on-error

---

## [2.0.7] — 2026-04-09

### Added
- add utm_source=mcp_cta&utm_medium=tool_output to all pricing URLs

### Fixed
- swap TextContent block order — text summary last for single-block MCP clients
- replace invisible metadata CTAs with LLM-surfaceable next_steps + summary
- add _add_banner() to 3 tools missing pricing CTA

---

## [2.0.6] — 2026-04-08

_(no user-facing changes)_

---

## [2.0.5] — 2026-04-08

### Added
- add upgrade_url CTA field in free-tier scan responses

---
