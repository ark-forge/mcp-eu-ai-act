# CI/CD Pipeline - MCP EU AI Act

> GitHub Actions pipeline to ensure quality and security for the MCP EU AI Act

---

## Overview

The CI/CD pipeline `.github/workflows/qa-mcp-eu-ai-act.yml` runs automatically on:
- **Push** to `main` or `develop`
- **Pull requests** to `main` or `develop`
- **Manual trigger** via workflow_dispatch

---

## Pipeline Jobs

### 1. Test (Matrix Python 3.9, 3.10, 3.11)

**Estimated duration**: 2-3 minutes per Python version

**Actions**:
- Checkout code
- Install dependencies (pytest, pytest-cov)
- Run tests with coverage
- **Fail if coverage < 70%** (blocking)
- Upload coverage report to Codecov
- Archive HTML report (30 days retention)

**Quality thresholds**:
```yaml
--cov-fail-under=70  # Minimum 70% coverage
```

**Expected output**:
```
tests/test_server.py::test_list_tools PASSED                    [ 10%]
tests/test_integration.py::test_scan_project PASSED             [ 20%]
...
---------- coverage: platform linux, python 3.11 -----------
Name                    Stmts   Miss  Cover   Missing
-----------------------------------------------------
server.py                 245     35    85%   123-145, 230-240
-----------------------------------------------------
TOTAL                     245     35    85%
```

---

### 2. Quality Gates

**Estimated duration**: 1-2 minutes

**Blocking checks**:
- Tests exist (`tests/test_*.py`)
- Pytest configuration present (pytest.ini, pyproject.toml, or setup.cfg)
- Coverage >= 70%

**Non-blocking checks (warnings)**:
- Security markers (`@pytest.mark.security`)
- Code smells (TODO/FIXME/HACK in source code)

**Example output**:
```
Found 3 test files
Pytest configuration found
Found 2 code smells (TODO/FIXME/HACK)
  server.py:125: # TODO: Add caching
  server.py:240: # FIXME: Optimize regex
Coverage: 85.3%
```

---

### 3. Integration Tests

**Estimated duration**: 30-60 seconds

**Actions**:
- Run tests marked `@pytest.mark.integration`
- Test MCP server in standalone mode (10s timeout)

**Example**:
```bash
pytest tests/ -v -m "integration" --tb=short
timeout 10s python3 server.py
Server ran successfully (timeout expected)
```

---

### 4. Security Scan

**Estimated duration**: 1-2 minutes

**Tools**:
- **Bandit**: Python security linter (detects common vulnerabilities)
- **Safety**: Dependency check for known CVEs

**Example output**:
```
Run started: 2026-02-10 14:30:00
Test results:
  No issues identified. (Medium: 0, Low: 0)
Code scanned: server.py, tests/test_server.py
Total lines of code: 850
Total lines skipped (#nosec): 0
```

**Reports generated**:
- `bandit-report.json` (archived 30 days)

---

### 5. Build Status Summary

**Estimated duration**: 5 seconds

**Final summary**:
```
===================================
  MCP EU AI Act - Build Summary
===================================

Tests: success
Quality Gates: success
Integration: success
Security: success

Build PASSED
```

---

## README Badges

### CI/CD Badge
```markdown
![CI/CD](https://github.com/ark-forge/mcp-eu-ai-act/actions/workflows/qa-mcp-eu-ai-act.yml/badge.svg)
```

**Possible states**:
- **passing** (green) - All jobs successful
- **failing** (red) - At least one job failed
- **pending** (yellow) - Pipeline running

### Coverage Badge
```markdown
![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)
```

**Colors by percentage**:
- `< 50%` - red
- `50-70%` - yellow
- `70-80%` - green
- `>= 80%` - brightgreen

---

## Publishing Workflow

### Step 1: Local Development
```bash
# Run tests locally BEFORE pushing
pytest tests/ -v --cov=. --cov-report=term-missing --cov-fail-under=70
```

### Step 2: Push to GitHub
```bash
git add .github/workflows/qa-mcp-eu-ai-act.yml
git add tests/
git commit -m "Add CI/CD pipeline with 70% coverage enforcement"
git push origin main
```

### Step 3: Pipeline Runs Automatically
- GitHub Actions triggers the workflow
- Jobs run in parallel (tests on 3 Python versions)
- Results visible in the "Actions" tab of the repository

### Step 4: Verify Results
- **All jobs pass** - Ready for Smithery publication
- **A job fails** - Fix required before merge

---

## Local Configuration (Development)

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run Tests with Coverage
```bash
# Complete tests
pytest tests/ -v --cov=. --cov-report=term-missing

# Unit tests only
pytest tests/ -v -m unit

# Integration tests only
pytest tests/ -v -m integration

# Generate HTML report
pytest tests/ --cov=. --cov-report=html
open htmlcov/index.html
```

### Check Coverage Threshold
```bash
pytest tests/ --cov=. --cov-fail-under=70
echo $?  # 0 = success, 1 = coverage too low
```

---

## Quality Metrics

| Metric | Threshold | Current | Status |
|----------|-------|--------|--------|
| **Global Coverage** | >= 70% | 85% | PASS |
| **Passing Tests** | 100% | 66/66 | PASS |
| **Python Versions** | 3.9, 3.10, 3.11 | 3.9-3.11 | PASS |
| **Vulnerabilities** | 0 critical/high | 0 | PASS |
| **Code Smells** | Warning only | 2 | WARNING |

---

## Security Standards

### Bandit - Applied Rules
- **Minimum level**: Medium (`-ll` flag)
- **Scope**: All source code (excluding tests/)
- **Output**: JSON + console

### Safety - Dependency Verification
- Scan `requirements.txt`
- Alert on known CVEs
- Non-blocking (warning)

---

## Pre-Publication Checklist

Before publishing to GitHub/Smithery, verify:

- [ ] CI/CD pipeline passes on `main`
- [ ] Coverage >= 70% (ideally >= 80%)
- [ ] All tests pass on Python 3.9, 3.10, 3.11
- [ ] No critical vulnerabilities (Bandit)
- [ ] README badges up to date
- [ ] Complete README documentation
- [ ] LICENSE present (MIT)

---

## Smithery Integration

The CI/CD pipeline will be automatically triggered on:
1. Push to `main` (release)
2. Version tag (e.g., `v1.0.0`)
3. Pull request (verification before merge)

Smithery can display the CI/CD badge on its listing page, reassuring users about the package quality.

---

## References

- **GitHub Actions Documentation**: https://docs.github.com/en/actions
- **pytest Documentation**: https://docs.pytest.org/
- **Codecov Integration**: https://about.codecov.io/

---

**Date**: 2026-02-10
**Version**: 1.0
**Maintained by**: Worker Fondations (ArkForge CEO System)
