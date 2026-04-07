#!/usr/bin/env python3
"""
smoke_test_mcp_prod.py — Smoke tests for the deployed MCP EU AI Act API.

Runs against the local api_wrapper service (default: http://127.0.0.1:8200).

Tests:
  1. GET /health              → 200, JSON with `status` field
  2. POST /scan               → 200, has `scan.detected_models` or `scan.ai_files` key
  3. POST /scan (v2 check)    → response contains `compliance.compliance_percentage` field

Exit 0 if all tests pass, exit 1 on any failure.

Usage:
    python3 scripts/smoke_test_mcp_prod.py [--base-url http://127.0.0.1:8200]
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

PASS = "PASS"
FAIL = "FAIL"

SCAN_PAYLOAD = json.dumps({
    "text": "import openai\nclient = openai.OpenAI()",
    "risk_category": "limited",
    "context": "chatbot for customer support",
}).encode("utf-8")


def http_get(url: str, timeout: int = 10):
    """Return (status_code, body_dict_or_none)."""
    try:
        req = urllib.request.urlopen(url, timeout=timeout)
        body = json.loads(req.read().decode("utf-8"))
        return req.status, body
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = None
        return e.code, body
    except Exception as exc:
        return None, str(exc)


def http_post(url: str, payload: bytes, timeout: int = 15):
    """Return (status_code, body_dict_or_none)."""
    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = json.loads(resp.read().decode("utf-8"))
        return resp.status, body
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = None
        return e.code, body
    except Exception as exc:
        return None, str(exc)


def run_tests(base_url: str) -> bool:
    base_url = base_url.rstrip("/")
    results = []
    all_passed = True

    # ------------------------------------------------------------------
    # Test 1: GET /health → 200, JSON with `status` field
    # ------------------------------------------------------------------
    print(f"\n[Test 1] GET {base_url}/health")
    code, body = http_get(f"{base_url}/health")
    if code == 200 and isinstance(body, dict) and "status" in body:
        print(f"  {PASS} — HTTP {code}, status={body.get('status')!r}")
        results.append(True)
    else:
        print(f"  {FAIL} — HTTP {code}, body={body!r}")
        print("  Expected: HTTP 200 with JSON containing 'status' field")
        results.append(False)
        all_passed = False

    # ------------------------------------------------------------------
    # Test 2: POST /scan → 200, has scan.detected_models or scan.ai_files
    # ------------------------------------------------------------------
    print(f"\n[Test 2] POST {base_url}/scan (scan.detected_models or scan.ai_files)")
    code, body = http_post(f"{base_url}/scan", SCAN_PAYLOAD)
    scan_obj = body.get("scan", {}) if isinstance(body, dict) else {}
    if code == 200 and isinstance(body, dict) and \
            ("detected_models" in scan_obj or "ai_files" in scan_obj):
        found_key = "detected_models" if "detected_models" in scan_obj else "ai_files"
        print(f"  {PASS} — HTTP {code}, scan.{found_key!r} present")
        results.append(True)
    else:
        print(f"  {FAIL} — HTTP {code}, body keys={list(body.keys()) if isinstance(body, dict) else body!r}")
        print("  Expected: HTTP 200 with scan.detected_models or scan.ai_files key")
        results.append(False)
        all_passed = False

    # ------------------------------------------------------------------
    # Test 3: POST /scan → compliance.compliance_percentage present (v2)
    # ------------------------------------------------------------------
    print(f"\n[Test 3] POST {base_url}/scan (compliance.compliance_percentage — v2 check)")
    compliance_obj = body.get("compliance", {}) if isinstance(body, dict) else {}
    if code == 200 and isinstance(body, dict) and "compliance_percentage" in compliance_obj:
        pct = compliance_obj["compliance_percentage"]
        print(f"  {PASS} — HTTP {code}, compliance_percentage={pct!r} (v2 confirmed)")
        results.append(True)
    else:
        keys = list(body.keys()) if isinstance(body, dict) else body
        print(f"  {FAIL} — HTTP {code}, compliance_percentage NOT found. Keys: {keys!r}")
        print("  Expected: v2 response with compliance.compliance_percentage field")
        results.append(False)
        all_passed = False

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    passed = sum(results)
    total = len(results)
    print(f"\n{'='*50}")
    print(f"  Smoke tests: {passed}/{total} passed")
    if all_passed:
        print("  Result: ALL PASS")
    else:
        print("  Result: FAILED")
    print(f"{'='*50}\n")

    return all_passed


def main():
    parser = argparse.ArgumentParser(description="Smoke tests for MCP EU AI Act API")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8200",
        help="Base URL of the api_wrapper service (default: http://127.0.0.1:8103)",
    )
    args = parser.parse_args()

    print(f"MCP EU AI Act — Smoke Test")
    print(f"Target: {args.base_url}")

    success = run_tests(args.base_url)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
