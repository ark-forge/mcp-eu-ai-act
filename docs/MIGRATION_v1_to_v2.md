# Migration Guide: MCP v1 to v2

How to update integrations built on the v1 `check_compliance` output for the v2 format.

## What Changed in `check_compliance` Output

### New Fields Added (v2)

Two new top-level fields are present in all `check_compliance` responses:

**`content_scores`** — a dictionary mapping compliance document filenames to their content quality score (0–100):

```json
"content_scores": {
  "RISK_MANAGEMENT.md": 72,
  "TECHNICAL_DOCUMENTATION.md": 45,
  "DATA_GOVERNANCE.md": 0,
  "HUMAN_OVERSIGHT.md": 88,
  "ROBUSTNESS.md": 33,
  "TRANSPARENCY.md": 61
}
```

**`article_map`** — a dictionary mapping EU AI Act article IDs to their compliance status for this project:

```json
"article_map": {
  "9":  {"status": "pass",    "score": 72, "check": "risk_management"},
  "10": {"status": "fail",    "score": 0,  "check": "data_governance"},
  "11": {"status": "partial", "score": 45, "check": "technical_documentation"},
  "14": {"status": "pass",    "score": 88, "check": "human_oversight"},
  "15": {"status": "partial", "score": 33, "check": "robustness"},
  "13": {"status": "pass",    "score": 61, "check": "transparency"}
}
```

### Backward Compatibility Guarantee

**All v1 fields are still present and unchanged.** No existing integration will break.

The following v1 fields are preserved exactly as before:

| v1 Field | Still Present in v2 |
|----------|-------------------|
| `risk_category` | Yes |
| `description` | Yes |
| `requirements` | Yes |
| `compliance_status` | Yes (dictionary of booleans) |
| `compliance_score` | Yes (e.g. `"4/6"`) |
| `compliance_percentage` | Yes (e.g. `66.7`) |

You can upgrade to v2 by simply ignoring the new fields until you are ready to use them.

## The New 0-100 Content Scoring System

### v1: Existence Check

In v1, compliance checks were binary: a document either existed (pass) or did not exist (fail). An empty `RISK_MANAGEMENT.md` would pass the same as a thoroughly completed one.

### v2: Content Quality Score

In v2, documents are scored 0–100 based on actual content quality:

| Score Range | Status | Meaning |
|-------------|--------|---------|
| 0 | `fail` | File does not exist |
| 1–4 | `fail` | File exists but is essentially empty (<50 chars) |
| 5–39 | `partial` | File exists with some content but missing required sections or keywords |
| 40–100 | `pass` | File contains enough of the required sections and keywords to be considered compliant |

**The pass threshold is 40/100.** A document needs to contain at least a meaningful subset of the required sections and keywords defined in the articles database to pass.

Scoring breakdown:
- Up to 60 points from required sections (e.g. "Risk Identification", "Risk Mitigation", "Testing & Validation")
- Up to 30 points from content keywords (e.g. "risk", "mitigation", "lifecycle")
- Up to 10 points for substantial length (>500 characters)

This is a strict improvement over v1: you can no longer achieve compliance by creating empty placeholder files.

## New Tools Available in v2

| Tool | Description |
|------|-------------|
| `generate_compliance_roadmap` | Produces a prioritized, week-by-week action plan to reach full compliance before a deadline |
| `generate_annex4_package` | Builds an Annex IV-structured ZIP evidence package (auditor-ready) |
| `certify_compliance_report` | Certifies any compliance report via ArkForge Trust Layer (Art. 12 audit trail) |

These tools are additive — no existing tools were removed or renamed.

## Updated Pricing Plans

| Plan | Price | Scans/Day | New v2 Tools | Trust Layer |
|------|-------|-----------|--------------|-------------|
| **Free** | €0/month | 10/day | Yes (all) | No |
| **Pro** | €29/month | Unlimited | Yes (all) | No |
| **Certified** | €99/month | Unlimited | Yes (all) | Yes (included Trust Layer key) |

The Certified plan bundles an ArkForge Trust Layer API key so compliance reports and Annex IV packages can be certified without a separate subscription.

Free and Pro plan users can still use `certify_compliance_report` and `generate_annex4_package(sign_with_trust_layer=True)` — they just need to provide a separately obtained Trust Layer key.
