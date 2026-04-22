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


def run_mcp_protocol_tests(mcp_url: str, expected_tools: int = 16) -> bool:
    """Test the MCP protocol endpoint (streamable HTTP on port 8090)."""
    mcp_url = mcp_url.rstrip("/")
    all_passed = True

    print(f"\n[MCP Test 1] Initialize session at {mcp_url}")
    init_payload = json.dumps({
        "jsonrpc": "2.0", "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "smoke-test", "version": "1.0"}},
        "id": 1
    }).encode("utf-8")
    req = urllib.request.Request(mcp_url, data=init_payload,
                                headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        session_id = resp.headers.get("Mcp-Session-Id", "")
        body = json.loads(resp.read().decode("utf-8"))
        server_name = body.get("result", {}).get("serverInfo", {}).get("name", "?")
        if session_id and "result" in body:
            print(f"  {PASS} — session={session_id[:12]}…, server={server_name}")
        else:
            print(f"  {FAIL} — no session or no result")
            all_passed = False
    except Exception as exc:
        print(f"  {FAIL} — {exc}")
        return False

    print(f"\n[MCP Test 2] ListTools (expect {expected_tools} tools)")
    list_payload = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 2}).encode("utf-8")
    req2 = urllib.request.Request(mcp_url, data=list_payload,
                                 headers={"Content-Type": "application/json", "Accept": "application/json",
                                          "Mcp-Session-Id": session_id})
    try:
        resp2 = urllib.request.urlopen(req2, timeout=10)
        body2 = json.loads(resp2.read().decode("utf-8"))
        tools = body2.get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]
        if len(tools) >= expected_tools:
            print(f"  {PASS} — {len(tools)} tools returned")
        else:
            print(f"  {FAIL} — {len(tools)} tools (expected {expected_tools}+)")
            print(f"  Tools: {tool_names}")
            all_passed = False
    except Exception as exc:
        print(f"  {FAIL} — {exc}")
        all_passed = False

    print(f"\n[MCP Test 3] tools/call scan_project")
    call_payload = json.dumps({
        "jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": "scan_project", "arguments": {"project_path": "."}},
        "id": 3
    }).encode("utf-8")
    req3 = urllib.request.Request(mcp_url, data=call_payload,
                                 headers={"Content-Type": "application/json", "Accept": "application/json",
                                          "Mcp-Session-Id": session_id})
    try:
        resp3 = urllib.request.urlopen(req3, timeout=30)
        body3 = json.loads(resp3.read().decode("utf-8"))
        content = body3.get("result", {}).get("content", [])
        if content and any(c.get("type") == "text" for c in content):
            text_len = sum(len(c.get("text", "")) for c in content if c.get("type") == "text")
            print(f"  {PASS} — scan returned {text_len} chars")
        else:
            print(f"  {FAIL} — no text content in response")
            all_passed = False
    except Exception as exc:
        print(f"  {FAIL} — {exc}")
        all_passed = False

    return all_passed


def main():
    parser = argparse.ArgumentParser(description="Smoke tests for MCP EU AI Act API")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8200",
        help="Base URL of the REST api_wrapper service (default: http://127.0.0.1:8200)",
    )
    parser.add_argument(
        "--mcp-url",
        default="http://127.0.0.1:8090/mcp",
        help="URL of the MCP protocol endpoint (default: http://127.0.0.1:8090/mcp)",
    )
    parser.add_argument(
        "--skip-rest", action="store_true",
        help="Skip REST API tests (port 8200)",
    )
    parser.add_argument(
        "--skip-mcp", action="store_true",
        help="Skip MCP protocol tests (port 8090)",
    )
    args = parser.parse_args()

    print("MCP EU AI Act — Smoke Test")
    all_ok = True

    if not args.skip_rest:
        print(f"\n=== REST API ({args.base_url}) ===")
        if not run_tests(args.base_url):
            all_ok = False

    if not args.skip_mcp:
        print(f"\n=== MCP Protocol ({args.mcp_url}) ===")
        if not run_mcp_protocol_tests(args.mcp_url):
            all_ok = False

    print(f"\n{'='*50}")
    print(f"  Overall: {'ALL PASS' if all_ok else 'FAILED'}")
    print(f"{'='*50}\n")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
