# Changelog

All notable changes to the EU AI Act Compliance Checker MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
