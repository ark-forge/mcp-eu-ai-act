#!/usr/bin/env python3
"""
CLI interface for the EU AI Act Compliance Scanner.

Usage:
    eu-ai-act-scanner                        # scan current directory
    eu-ai-act-scanner /path/to/project
    eu-ai-act-scanner . --risk high
    eu-ai-act-scanner . --pro
"""

import sys
import json
import argparse
import threading
import urllib.request
import urllib.error
from pathlib import Path

from server import EUAIActChecker, RISK_CATEGORIES, ACTIONABLE_GUIDANCE


def _resolve_version() -> str:
    pyproject = Path(__file__).parent / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib
        except ModuleNotFoundError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ModuleNotFoundError:
                tomllib = None
        if tomllib is not None:
            with open(pyproject, "rb") as f:
                v = tomllib.load(f).get("project", {}).get("version")
            if v:
                return v
    try:
        from importlib.metadata import version
        return version("eu-ai-act-scanner")
    except Exception:
        return "dev"


__version__ = _resolve_version()

PRICING_URL = "https://arkforge.tech/en/pricing.html?utm_source=cli"
CHECKOUT_URL = "https://arkforge.tech/en/scanner-pro.html?utm_source=cli&utm_medium=upgrade"
REGISTER_API = "https://mcp.arkforge.tech/api/register"

PRO_FEATURES = [
    "Detailed per-article risk scores with remediation priorities",
    "Full actionable recommendations with step-by-step guidance",
    "PDF/JSON export for auditors and legal teams",
    "CI/CD integration via REST API (block deploys on non-compliance)",
    "Unlimited scans + scan history dashboard",
    "Email alerts when compliance status changes",
]

UPSELL_BLOCK = f"""
  ── Pro: unlimited scans + CI/CD API + step-by-step remediation ──
  29 EUR/month — start 14-day free trial → {CHECKOUT_URL}
"""


def _mcp_bridge(failing_count: int) -> str:
    if failing_count > 0:
        return f"""
  ── {failing_count} check{'s' if failing_count > 1 else ''} failed — get step-by-step fix instructions ────────
  Claude Code:  claude mcp add eu-ai-act -- eu-ai-act-mcp
  Claude Desktop / Cursor: add to config:
    {{"command": "eu-ai-act-mcp"}}
  MCP gives you: fix instructions, compliance roadmap, template
  generation, GDPR scan, Annex IV package, and certification.
"""
    return """
  ── Extend with MCP server (Claude / Cursor / VS Code) ────────
  Claude Code:  claude mcp add eu-ai-act -- eu-ai-act-mcp
  Claude Desktop / Cursor: add to config:
    {"command": "eu-ai-act-mcp"}
  MCP adds: compliance roadmap, template generation, GDPR scan,
  Annex IV package, and Trust Layer certification.
"""


def _register_cli_user(email: str) -> dict | None:
    """Register email via MCP API. Returns key info or None."""
    try:
        payload = json.dumps({"email": email, "source": "cli"}).encode()
        req = urllib.request.Request(
            REGISTER_API,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except Exception:
        return None


def _ping_usage(scan: dict, compliance: dict) -> None:
    """Non-blocking anonymous usage ping. No PII. Fail-silent."""
    def _do():
        try:
            payload = json.dumps({
                "source": "cli_telemetry",
                "v": __version__,
                "fw": len(scan.get("detected_models", {})),
                "files": scan.get("files_scanned", 0),
                "risk": compliance.get("risk_category", "unknown"),
                "pct": compliance.get("compliance_percentage", 0),
            }).encode()
            req = urllib.request.Request(
                REGISTER_API.replace("/register", "/cli-ping"),
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass
    threading.Thread(target=_do, daemon=True).start()


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
        if files == 0:
            print("\n  No source files found. Make sure you point to your project root:")
            print("    eu-ai-act-scanner /path/to/your/project")
        else:
            print("\n  No AI frameworks detected in this project.")
            print("  Supported: openai, anthropic, langchain, huggingface, tensorflow,")
            print("  pytorch, gemini, cohere, bedrock, azure_openai, ollama, and more.")


SHORT_HINTS = {
    "technical_documentation": "Create docs/TECHNICAL_DOCUMENTATION.md — Art. 11",
    "risk_management": "Create docs/RISK_MANAGEMENT.md — Art. 9",
    "transparency": "Add AI disclosure to README.md — Art. 52",
    "user_disclosure": "Add 'AI Disclosure' section to README.md — Art. 52(1)",
    "content_marking": "Label AI-generated outputs — Art. 52(3)",
    "data_governance": "Create docs/DATA_GOVERNANCE.md — Art. 10",
    "human_oversight": "Create docs/HUMAN_OVERSIGHT.md — Art. 14",
    "robustness": "Create docs/ROBUSTNESS.md — Art. 15",
    "basic_documentation": "Create a README.md with project description — Art. 52",
}


def _print_compliance_results(compliance: dict) -> None:
    score = compliance.get("compliance_score", "0/0")
    pct = compliance.get("compliance_percentage", 0)
    risk = compliance.get("risk_category", "unknown")
    print(f"\n  Risk category: {risk}")
    print(f"  Compliance score: {score} ({pct}%)")
    status = compliance.get("compliance_status", {})
    failing = []
    if status:
        print("  Checks:")
        for check, passed in status.items():
            icon = "PASS" if passed else "FAIL"
            hint = ""
            if not passed:
                failing.append(check)
                hint_text = SHORT_HINTS.get(check)
                if hint_text:
                    hint = f"  → {hint_text}"
            print(f"    [{icon}] {check.replace('_', ' ').title()}{hint}")

    if failing:
        print(f"\n  Quick fix: run with --pro for step-by-step remediation guidance.")


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

    print(f"\n  Start 14-day free trial → {CHECKOUT_URL}")
    print("  ───────────────────────────────────────────────────────────────")


def _log_cli_invocation(args: argparse.Namespace, scan: dict, compliance: dict | None = None) -> None:
    """Append a local telemetry entry for CLI usage (activation tracking)."""
    try:
        from datetime import datetime, timezone
        log_path = Path(__file__).parent / "data" / "tool_calls.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": "cli_scan",
            "source": "cli",
            "version": __version__,
            "risk": args.risk,
            "pro_flag": args.pro,
            "json_flag": args.json,
            "register_flag": bool(getattr(args, "register", None)),
            "frameworks_found": len(scan.get("detected_models", {})),
            "frameworks": list(scan.get("detected_models", {}).keys()),
            "files_scanned": scan.get("files_scanned", 0),
        }
        if compliance:
            status = compliance.get("compliance_status", {})
            entry["compliance_pct"] = compliance.get("compliance_percentage", 0)
            entry["risk_category"] = compliance.get("risk_category", "unknown")
            entry["checks_pass"] = sum(1 for v in status.values() if v)
            entry["checks_fail"] = sum(1 for v in status.values() if not v)
        with open(log_path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eu-ai-act-scanner",
        description="EU AI Act Compliance Scanner — Scan your project for AI framework usage and check regulatory compliance.",
    )
    parser.add_argument(
        "project_path",
        nargs="?",
        default=".",
        help="Path to the project to scan (default: current directory)",
    )
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
    parser.add_argument(
        "--register",
        metavar="EMAIL",
        help="Register for a free API key (unlocks scan history + CI/CD integration)",
    )
    parser.add_argument(
        "--no-telemetry",
        action="store_true",
        help="Disable anonymous usage statistics",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "scan":
        argv = argv[1:] or ["."]

    args = parser.parse_args(argv)

    checker = EUAIActChecker(args.project_path)
    scan = checker.scan_project()

    if scan.get("error"):
        print(f"Error: {scan['error']}", file=sys.stderr)
        return 1

    compliance = checker.check_compliance(args.risk)

    _log_cli_invocation(args, scan, compliance)

    if not args.no_telemetry:
        _ping_usage(scan, compliance)

    if args.json:
        output = {
            "scan": scan,
            "compliance": compliance,
            "upgrade": {
                "pricing_url": PRICING_URL,
                "checkout_url": CHECKOUT_URL,
                "pro_features": PRO_FEATURES,
            },
        }
        if args.register:
            result = _register_cli_user(args.register)
            if result and result.get("key"):
                output["registration"] = {
                    "api_key": result["key"],
                    "plan": result.get("plan", "free"),
                }
            else:
                output["registration"] = {"error": "Registration failed. Try again or visit " + CHECKOUT_URL}
        print(json.dumps(output, indent=2))
        return 0

    # Human-readable output
    print("=" * 72)
    print("  EU AI Act Compliance Scanner")
    print("=" * 72)

    _print_scan_results(scan)
    _print_compliance_results(compliance)

    if args.register:
        result = _register_cli_user(args.register)
        if result and result.get("key"):
            print(f"\n  Registered! API key: {result['key']}")
            print(f"    Plan: {result.get('plan', 'free')} (10 scans/day)")
            print(f"    Use in CI/CD: X-Api-Key: {result['key']}")
            print(f"    Upgrade to Pro → {CHECKOUT_URL}")
        else:
            print(f"\n  Registration failed. Sign up at: {CHECKOUT_URL}")

    if args.pro:
        _print_pro_preview(compliance)

    failing_count = sum(
        1 for v in compliance.get("compliance_status", {}).values() if not v
    )
    print(_mcp_bridge(failing_count))
    print(UPSELL_BLOCK)

    if not args.register:
        print(f"  Free API key (scan history + CI/CD): eu-ai-act-scanner . --register you@email.com")

    return 0


if __name__ == "__main__":
    sys.exit(main())
