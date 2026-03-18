#!/usr/bin/env python3
"""
EU AI Act Compliance Scanner — Apify Actor (Pay-per-event)
Deploy to Apify marketplace for automated, paid compliance scanning.

Pricing model: pay-per-event via Actor.charge()
  - Each compliance scan: charge "compliance-scan" event (0.05 USD default)
  - Each file analyzed: charge "file-analyzed" event (optional, for large repos)

Deploy:
  apify push  (requires apify login first)

ACTIONNAIRE SETUP:
  1. Create account at https://console.apify.com
  2. Run: apify login
  3. Configure pricing in Apify console (pay-per-event pricing model)
  4. Run: apify push (from this directory)
  5. Store API token: vault.set('apify.token', 'TOKEN')
"""

import asyncio
import sys
import json
import subprocess
import tempfile
from pathlib import Path

# Apify SDK 3.3.0 — pay-per-event supported
from apify import Actor


async def run_compliance_scan(repo_url: str, risk_category: str = "limited") -> dict:
    """Run the EU AI Act compliance scanner on a GitHub repo."""
    # Clone repo to temp dir
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            ["git", "clone", "--depth=1", repo_url, tmpdir],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode != 0:
            return {"error": f"Git clone failed: {result.stderr[:200]}"}

        # Import and run the compliance checker
        sys.path.insert(0, str(Path(__file__).parent))
        try:
            from server import EUAIActChecker
            checker = EUAIActChecker(risk_category=risk_category)
            scan_result = checker.analyze_project(tmpdir)
            return scan_result
        except Exception as e:
            return {"error": f"Scan failed: {str(e)[:200]}"}


async def main():
    async with Actor:
        # Get input
        actor_input = await Actor.get_input() or {}
        repo_url = actor_input.get("repo_url", "")
        risk_category = actor_input.get("risk_category", "limited")
        include_files = actor_input.get("include_files", False)

        if not repo_url:
            Actor.log.error("No repo_url provided in input")
            await Actor.fail(status_message="Missing required input: repo_url")
            return

        Actor.log.info(f"Scanning: {repo_url} (category: {risk_category})")

        # Charge for the compliance scan (pay-per-event)
        charge_result = await Actor.charge(event_name="compliance-scan", count=1)
        Actor.log.info(f"Charged for compliance-scan: {charge_result}")

        # Run scan
        scan_result = await run_compliance_scan(repo_url, risk_category)

        if "error" in scan_result:
            await Actor.fail(status_message=scan_result["error"])
            return

        # Optionally charge per file if large repo
        files_scanned = scan_result.get("files_scanned", 0)
        if include_files and files_scanned > 50:
            extra_events = (files_scanned - 50) // 10
            if extra_events > 0:
                await Actor.charge(event_name="file-analyzed", count=extra_events)

        # Push output
        await Actor.push_data({
            "repo_url": repo_url,
            "risk_category": risk_category,
            "risk_score": scan_result.get("risk_score", 0),
            "compliance_score": scan_result.get("compliance_score", "unknown"),
            "frameworks_detected": scan_result.get("frameworks_detected", []),
            "files_scanned": files_scanned,
            "recommendations": scan_result.get("recommendations", []),
        })

        await Actor.set_status_message(
            f"Scan complete: score={scan_result.get('compliance_score', 'N/A')}"
        )


if __name__ == "__main__":
    asyncio.run(main())
