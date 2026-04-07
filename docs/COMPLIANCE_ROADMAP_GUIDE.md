# Compliance Roadmap Guide

How to read and act on the output of `generate_compliance_roadmap`.

## What the Tool Does

`generate_compliance_roadmap` scans your project, identifies every failing compliance check, and returns a prioritized, week-by-week action plan to reach full EU AI Act compliance before your deadline.

It is the highest-value tool in the MCP: instead of a static list of gaps, it produces a sequenced project plan you can hand directly to an engineering or legal team.

## Response Fields Explained

### Top-Level Fields

| Field | Type | Meaning |
|-------|------|---------|
| `project_path` | string | The scanned project directory |
| `risk_category` | string | The risk category used for the assessment (`high`, `limited`, `minimal`) |
| `deadline` | string | The target compliance date (ISO format, default `2026-08-02`) |
| `days_remaining` | int | Calendar days from today until the deadline |
| `initial_compliance_pct` | float | Compliance percentage before any actions (based on current project state) |
| `final_compliance_pct` | float | Projected compliance percentage after completing all steps |
| `total_effort_days` | int | Sum of effort estimates across all steps |
| `feasible` | bool | `true` when `total_effort_days <= days_remaining` — your team can realistically finish before the deadline |
| `steps` | list | Ordered list of action items (see below) |
| `summary` | string | One-sentence human-readable summary |

### Per-Step Fields (`steps[]`)

| Field | Type | Meaning |
|-------|------|---------|
| `step` | int | Sequential step number (1 = first action to take) |
| `week` | int | Which calendar week this action should start (relative to today) |
| `article` | string | The EU AI Act article this step addresses (e.g. `Art. 52`) |
| `check` | string | Internal check key (e.g. `transparency`, `risk_management`) |
| `action` | string | Concrete task description — what you need to create or fix |
| `effort_days` | int | Estimated working days to complete this step |
| `doc_filename` | string or null | The compliance document to create (e.g. `RISK_MANAGEMENT.md`) |
| `compliance_pct_after` | float | Your compliance percentage after completing this step |
| `urgency` | string | `critical` (<30 days), `high` (<60 days), or `normal` |

## How Priority Is Calculated

Each action is scored by a combination of **legal criticality** and **effort**:

```
priority_score = criticality × (1 / effort_days)
```

Higher criticality = more important under the EU AI Act (Art. 52 transparency scores 10/10; basic documentation scores 5/10). Lower effort = quicker win.

This produces a "quick wins first" ordering: legally critical actions that take 1–2 days are always scheduled before legally important but expensive (10-day) actions.

## Why Art. 52 Transparency Always Comes First

For **limited-risk** systems, Art. 52 (user disclosure) is the primary obligation. Transparency is scored at criticality=10 with effort_days=2. No other check has a higher criticality-to-effort ratio. This means: if your system interacts with users and has no transparency disclosure, the roadmap will always place this as Step 1.

For **high-risk** systems, Art. 9 (risk management) reaches criticality=9 with effort=10 days, while Art. 52 still appears first because its 2-day effort makes it an immediate quick win before the heavier documentation work begins.

## What "Feasible" Means

`feasible: true` means that, working at the estimated pace, your team can complete all actions before the deadline.

`feasible: false` is a warning signal — you have more work than calendar time. In this case:
1. Focus on the first 3–4 steps (highest criticality)
2. Extend your deadline parameter or allocate additional developers
3. Use partial credit: documents with sections already filled in receive a reduced effort estimate

## Example Output with Annotation

```json
{
  "project_path": "/projects/my-chatbot",
  "risk_category": "limited",
  "deadline": "2026-08-02",
  "days_remaining": 118,           // plenty of time
  "initial_compliance_pct": 33.3,  // currently 1/3 checks passing
  "final_compliance_pct": 100.0,   // all 3 checks will pass after roadmap
  "total_effort_days": 4,          // 4 working days total
  "feasible": true,                // 4 << 118

  "steps": [
    {
      "step": 1,
      "week": 1,
      "article": "Art. 52",        // highest criticality + lowest effort
      "check": "transparency",
      "action": "Create TRANSPARENCY.md with AI disclosure notice",
      "effort_days": 2,
      "doc_filename": "TRANSPARENCY.md",
      "compliance_pct_after": 66.7, // after this step, 2/3 checks pass
      "urgency": "normal"
    },
    {
      "step": 2,
      "week": 1,
      "article": "Art. 52",
      "check": "user_disclosure",
      "action": "Add AI disclosure to README.md",
      "effort_days": 1,
      "doc_filename": "README.md",
      "compliance_pct_after": 100.0,
      "urgency": "normal"
    }
  ]
}
```

## How to Turn the Roadmap into a Project Plan

1. **Export the steps**: Copy the `steps` array into your project management tool (Jira, Linear, GitHub Issues).
2. **Assign by week**: The `week` field maps directly to sprint planning — Week 1 tasks go into your next sprint.
3. **Use the templates**: For each `doc_filename`, run `generate_compliance_templates` to get the starter document. Save it to `docs/` in your repo.
4. **Track progress**: Re-run `generate_compliance_roadmap` after completing each step. The `action` field will update to show `"Complete X — currently Y% done"` for partially filled documents.
5. **Verify completion**: When `steps == []`, your system has reached `final_compliance_pct = 100%` and you are ready for an audit.
6. **Certify**: Run `generate_annex4_package` to bundle all evidence, then `certify_compliance_report` to obtain a Trust Layer proof for the auditor.
