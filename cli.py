#!/usr/bin/env python3
"""
CLI interface for the EU AI Act Compliance Scanner.

Usage:
    eu-ai-act-scanner /path/to/project
    eu-ai-act-scanner /path/to/project --risk high
    eu-ai-act-scanner /path/to/project --pro
"""

import sys
import json
import argparse

from server import EUAIActChecker, RISK_CATEGORIES, ACTIONABLE_GUIDANCE

PRICING_URL = "https://mcp.arkforge.fr/fr/pricing.html?utm_source=cli"

PRO_FEATURES = [
    "Detailed per-article risk scores with remediation priorities",
    "Full actionable recommendations with step-by-step guidance",
    "PDF/JSON export for auditors and legal teams",
    "CI/CD integration via REST API (block deploys on non-compliance)",
    "Unlimited scans + scan history dashboard",
    "Email alerts when compliance status changes",
]

UPSELL_BLOCK = f"""
================================================================================
  UPGRADE TO PRO — Unlock full compliance intelligence
================================================================================

  Your scan is complete. With Pro, you also get:

    * Detailed per-article risk scores with remediation priorities
    * Full actionable recommendations with step-by-step guidance
    * PDF/JSON export for auditors and legal teams
    * CI/CD integration — block deploys on non-compliance
    * Unlimited scans + scan history dashboard

  29 EUR/month — Start now:
  {PRICING_URL}

  Questions? contact@arkforge.fr
================================================================================
"""


def _print_scan_results(scan: dict) -> None:
    files = scan.get("files_scanned", 0)
    models = scan.get("detected_models", {})
    print(f"\n  Files scanned: {files}")
    if models:
        print(f"  AI frameworks detected: {len(models)}")
        for fw, locations in models.items():
            print(f"    - {fw} (in {len(locations)} file{'s' if len(locations) > 1 else ''})")
    else:
        print("  AI frameworks detected: 0")


def _print_compliance_results(compliance: dict) -> None:
    score = compliance.get("compliance_score", "0/0")
    pct = compliance.get("compliance_percentage", 0)
    risk = compliance.get("risk_category", "unknown")
    print(f"\n  Risk category: {risk}")
    print(f"  Compliance score: {score} ({pct}%)")
    status = compliance.get("compliance_status", {})
    if status:
        print("  Checks:")
        for check, passed in status.items():
            icon = "PASS" if passed else "FAIL"
            print(f"    [{icon}] {check.replace('_', ' ').title()}")


def _print_pro_preview(compliance: dict) -> None:
    """Show a truncated preview of premium recommendations to entice upgrade."""
    status = compliance.get("compliance_status", {})
    risk = compliance.get("risk_category", "limited")
    failing = [check for check, passed in status.items() if not passed]

    print("\n  ── Pro Preview: Detailed Recommendations ──────────────────────")
    if not failing:
        print("  All checks passed! Pro gives you per-article risk scores,")
        print("  continuous monitoring, and export for auditors.")
    else:
        # Show first recommendation in full, truncate the rest
        shown = 0
        for check in failing:
            guidance = ACTIONABLE_GUIDANCE.get(check, {})
            if shown == 0:
                # Full first recommendation
                print(f"\n  [{check.replace('_', ' ').title()}] — {guidance.get('eu_article', '')}")
                print(f"    What: {guidance.get('what', 'N/A')}")
                print(f"    Why:  {guidance.get('why', 'N/A')}")
                steps = guidance.get("how", [])
                if steps:
                    print("    How:")
                    for step in steps:
                        print(f"      - {step}")
                print(f"    Effort: {guidance.get('effort', 'N/A')}")
            else:
                # Truncated
                what = guidance.get("what", "N/A")
                article = guidance.get("eu_article", "")
                truncated = what[:60] + "..." if len(what) > 60 else what
                print(f"\n  [{check.replace('_', ' ').title()}] — {article}")
                print(f"    {truncated}")
                print(f"    *** Full guidance available with Pro ***")
            shown += 1

    # Per-article risk scores preview
    print("\n  ── Pro Preview: Per-Article Risk Scores ───────────────────────")
    articles_preview = {
        "high": [
            ("Art. 9  Risk Management", "██████████ "),
            ("Art. 10 Data Governance", "████████░░ "),
            ("Art. 11 Technical Docs", "██████░░░░ "),
            ("Art. 14 Human Oversight", "████░░░░░░ "),
            ("Art. 15 Robustness", "██░░░░░░░░ "),
        ],
        "limited": [
            ("Art. 52  Transparency", "████████░░ "),
            ("Art. 52(1) User Disclosure", "██████░░░░ "),
            ("Art. 52(3) Content Marking", "████░░░░░░ "),
        ],
    }
    bars = articles_preview.get(risk, articles_preview["limited"])
    for article, bar in bars[:2]:
        print(f"    {article}  {bar}")
    if len(bars) > 2:
        print(f"    ... +{len(bars) - 2} more articles")
        print("    *** Full risk scores available with Pro ***")

    print(f"\n  Get the complete analysis: {PRICING_URL}")
    print("  ───────────────────────────────────────────────────────────────")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eu-ai-act-scanner",
        description="EU AI Act Compliance Scanner — Scan your project for AI framework usage and check regulatory compliance.",
    )
    parser.add_argument("project_path", help="Path to the project to scan")
    parser.add_argument(
        "--risk",
        choices=list(RISK_CATEGORIES.keys()),
        default="limited",
        help="EU AI Act risk category (default: limited)",
    )
    parser.add_argument(
        "--pro",
        action="store_true",
        help="Show a preview of Pro recommendations (detailed guidance, per-article risk scores)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON results",
    )

    args = parser.parse_args(argv)

    checker = EUAIActChecker(args.project_path)
    scan = checker.scan_project()

    if scan.get("error"):
        print(f"Error: {scan['error']}", file=sys.stderr)
        return 1

    compliance = checker.check_compliance(args.risk)

    if args.json:
        output = {
            "scan": scan,
            "compliance": compliance,
            "upgrade": {
                "pricing_url": PRICING_URL,
                "pro_features": PRO_FEATURES,
            },
        }
        print(json.dumps(output, indent=2))
        return 0

    # Human-readable output
    print("=" * 72)
    print("  EU AI Act Compliance Scanner")
    print("=" * 72)

    _print_scan_results(scan)
    _print_compliance_results(compliance)

    if args.pro:
        _print_pro_preview(compliance)

    # Always show upsell block
    print(UPSELL_BLOCK)

    return 0


if __name__ == "__main__":
    sys.exit(main())
