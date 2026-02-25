#!/usr/bin/env python3
"""
MCP EU AI Act - REST API
FastAPI server providing:
- Free tier: 10 scans/day per IP
- Pro tier: via ArkForge Trust Layer (https://trust.arkforge.fr)
- Scan, compliance check, and report endpoints

Payment, API keys, webhooks, and email are handled by the Trust Layer.
This service is a pure scanner with rate-limited free access.
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# --- Config ---
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

RATE_LIMITS_FILE = DATA_DIR / "rate_limits.json"
SCAN_HISTORY_FILE = DATA_DIR / "scan_history.json"

FREE_TIER_LIMIT = 10  # scans per day per IP

logger = logging.getLogger("eu-ai-act-api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

# --- Data persistence helpers ---

def _load_json(path: Path, default=None):
    if default is None:
        default = {}
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return default

def _save_json(path: Path, data):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str))
    tmp.rename(path)


# --- Rate limiting ---

def check_rate_limit(ip: str) -> tuple[bool, int]:
    """Check if IP is within free tier limit. Returns (allowed, remaining)."""
    limits = _load_json(RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Clean old entries
    limits = {k: v for k, v in limits.items() if v.get("date") == today}

    entry = limits.get(ip, {"date": today, "count": 0})
    if entry.get("date") != today:
        entry = {"date": today, "count": 0}

    remaining = max(0, FREE_TIER_LIMIT - entry["count"])
    allowed = remaining > 0

    if allowed:
        entry["count"] += 1
        entry["date"] = today
        limits[ip] = entry
        _save_json(RATE_LIMITS_FILE, limits)
        remaining -= 1

    return allowed, remaining

def get_rate_limit_usage(ip: str) -> dict:
    limits = _load_json(RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entry = limits.get(ip, {"date": today, "count": 0})
    if entry.get("date") != today:
        return {"used": 0, "limit": FREE_TIER_LIMIT, "remaining": FREE_TIER_LIMIT}
    used = entry.get("count", 0)
    return {"used": used, "limit": FREE_TIER_LIMIT, "remaining": max(0, FREE_TIER_LIMIT - used)}


# --- Scan history ---

def record_scan(ip: str, scan_type: str, result_summary: dict):
    history = _load_json(SCAN_HISTORY_FILE, [])
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "scan_type": scan_type,
        "frameworks_detected": result_summary.get("frameworks_detected", []),
        "files_scanned": result_summary.get("files_scanned", 0),
    })
    # Keep last 1000 entries
    if len(history) > 1000:
        history = history[-1000:]
    _save_json(SCAN_HISTORY_FILE, history)


# --- Import scanner from server.py ---

from server import EUAIActChecker, _validate_project_path


# --- FastAPI app ---

app = FastAPI(
    title="MCP EU AI Act - Compliance Scanner API",
    description="EU AI Act Compliance Scanner. Free: 10 scans/day. Paid: via ArkForge Trust Layer.",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


FREE_TIER_BANNER = f"Free tier: {FREE_TIER_LIMIT}/day — Paid scans via Trust Layer → https://trust.arkforge.fr"


def _check_free_tier(ip: str):
    """Check rate limit for free tier. Raises 429 if exceeded."""
    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        raise HTTPException(429, {
            "error": "Free tier limit reached (10/day)",
            "upgrade": "https://trust.arkforge.fr",
            "reset": "Tomorrow 00:00 UTC",
        })


# --- Usage endpoint ---

@app.get("/api/usage")
async def api_usage(request: Request):
    """Return current free-tier usage for the requesting IP."""
    ip = get_client_ip(request)
    usage = get_rate_limit_usage(ip)
    now_dt = datetime.now(timezone.utc)
    midnight = (now_dt + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return {
        "plan": "free",
        "daily_limit": FREE_TIER_LIMIT,
        "used": usage["used"],
        "remaining": usage["remaining"],
        "resets_in_seconds": int((midnight - now_dt).total_seconds()),
        "upgrade": FREE_TIER_BANNER,
    }


# --- REST API Endpoints ---

@app.get("/api/v1/status")
async def api_status(request: Request):
    ip = get_client_ip(request)
    usage = get_rate_limit_usage(ip)
    return {
        "service": "MCP EU AI Act Compliance Checker",
        "version": "1.1.0",
        "your_plan": "free",
        "rate_limit": usage,
        "paid_scans": "https://trust.arkforge.fr",
    }


@app.post("/api/v1/scan")
async def api_scan(request: Request):
    """Scan a project for AI framework usage. Free tier: 10/day."""
    body = await request.json()
    project_path = body.get("project_path", "")
    if not project_path:
        raise HTTPException(400, "project_path is required")

    ip = get_client_ip(request)
    _check_free_tier(ip)

    is_safe, error_msg = _validate_project_path(project_path)
    if not is_safe:
        raise HTTPException(403, error_msg)

    checker = EUAIActChecker(project_path)
    result = checker.scan_project()

    summary = {
        "frameworks_detected": list(result.get("detected_models", {}).keys()),
        "files_scanned": result.get("files_scanned", 0),
    }
    record_scan(ip, "scan", summary)

    usage = get_rate_limit_usage(ip)
    return {
        "plan": "free",
        "rate_limit": usage,
        "banner": FREE_TIER_BANNER,
        **result,
    }


@app.post("/api/v1/check-compliance")
async def api_check_compliance(request: Request):
    """Check EU AI Act compliance. Free tier: 10/day."""
    body = await request.json()
    project_path = body.get("project_path", "")
    risk_category = body.get("risk_category", "limited")
    if not project_path:
        raise HTTPException(400, "project_path is required")

    ip = get_client_ip(request)
    _check_free_tier(ip)

    is_safe, error_msg = _validate_project_path(project_path)
    if not is_safe:
        raise HTTPException(403, error_msg)

    checker = EUAIActChecker(project_path)
    checker.scan_project()
    result = checker.check_compliance(risk_category)

    record_scan(ip, "compliance", {"frameworks_detected": [], "files_scanned": 0})

    return {
        "plan": "free",
        "rate_limit": get_rate_limit_usage(ip),
        "banner": FREE_TIER_BANNER,
        **result,
    }


@app.post("/api/v1/report")
async def api_report(request: Request):
    """Generate full compliance report. Free tier: 10/day."""
    body = await request.json()
    project_path = body.get("project_path", "")
    risk_category = body.get("risk_category", "limited")
    if not project_path:
        raise HTTPException(400, "project_path is required")

    ip = get_client_ip(request)
    _check_free_tier(ip)

    is_safe, error_msg = _validate_project_path(project_path)
    if not is_safe:
        raise HTTPException(403, error_msg)

    checker = EUAIActChecker(project_path)
    scan_results = checker.scan_project()
    compliance_results = checker.check_compliance(risk_category)
    report = checker.generate_report(scan_results, compliance_results)

    record_scan(ip, "report", {
        "frameworks_detected": list(scan_results.get("detected_models", {}).keys()),
        "files_scanned": scan_results.get("files_scanned", 0),
    })

    return {
        "plan": "free",
        "rate_limit": get_rate_limit_usage(ip),
        "banner": FREE_TIER_BANNER,
        **report,
    }


# --- Trust Layer internal endpoint ---

INTERNAL_SECRET = os.environ.get("TRUST_LAYER_INTERNAL_SECRET", "tl_internal_9f4e2a")

@app.post("/api/v1/scan-repo")
async def scan_repo(request: Request):
    """Scan a GitHub repo — called by Trust Layer (no payment here, billing handled upstream).
    Protected by internal secret header."""
    if request.headers.get("X-Internal-Secret") != INTERNAL_SECRET:
        raise HTTPException(403, "Forbidden")

    body = await request.json()
    repo_url = body.get("repo_url", "")
    if not repo_url:
        raise HTTPException(400, "repo_url is required")
    if not repo_url.startswith("https://"):
        raise HTTPException(400, "repo_url must be an HTTPS URL")

    import tempfile, subprocess, shutil
    clone_dir = tempfile.mkdtemp(prefix="scan_")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, clone_dir],
            check=True, capture_output=True, text=True, timeout=60,
        )
        checker = EUAIActChecker(clone_dir)
        scan_result = checker.scan_project()
        compliance = checker.check_compliance("limited")
        report = checker.generate_report(scan_result, compliance)
        scan_result["report"] = report
    except subprocess.CalledProcessError as e:
        raise HTTPException(400, f"Cannot clone repo: {e.stderr[:200]}")
    except subprocess.TimeoutExpired:
        raise HTTPException(408, "Git clone timed out (60s limit)")
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)

    ip = get_client_ip(request)
    record_scan(ip, "trust_layer_scan", {
        "frameworks_detected": list(scan_result.get("detected_models", {}).keys()),
        "files_scanned": scan_result.get("files_scanned", 0),
    })

    return {"scan_result": {"plan": "trust_layer", "repo_url": repo_url, **scan_result}}


# --- Info endpoints ---

@app.get("/api/pricing")
async def pricing():
    return {
        "plans": {
            "free": {
                "price": "0",
                "scans_per_day": FREE_TIER_LIMIT,
                "features": [
                    "10 scans/day",
                    "Full compliance reports",
                    "16 AI frameworks detected",
                    "MCP protocol access",
                ],
            },
            "paid": {
                "price": "0.50 EUR/scan",
                "description": "Pay-per-scan via ArkForge Trust Layer",
                "features": [
                    "Unlimited scans",
                    "Cryptographic proof per transaction",
                    "OpenTimestamps (Bitcoin anchoring)",
                    "Any HTTPS API via proxy",
                ],
                "setup": "https://trust.arkforge.fr/v1/keys/setup",
            },
        },
        "contact": "contact@arkforge.fr",
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "mcp-eu-ai-act", "version": "1.1.0", "timestamp": datetime.now(timezone.utc).isoformat()}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8091, log_level="info")
