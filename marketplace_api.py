#!/usr/bin/env python3
"""
EU AI Act Compliance Scanner — Marketplace REST API
Standalone FastAPI service for marketplace listing (RapidAPI, etc.)

Endpoints:
  POST /v1/scan  — scan a GitHub repo URL or inline source code
  GET  /v1/scan/{scan_id} — retrieve a previous scan result

Rate limiting: 5 requests/day without API key, unlimited with valid key.
Port: 8200
"""

import os
import sys
import json
import uuid
import shutil
import logging
import tempfile
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Add parent for scanner imports
sys.path.insert(0, str(Path(__file__).parent))
from server import EUAIActChecker, _validate_project_path

# --- Config ---
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

SCANS_DIR = DATA_DIR / "marketplace_scans"
SCANS_DIR.mkdir(exist_ok=True)
JOBS_DIR = DATA_DIR / "marketplace_jobs"
JOBS_DIR.mkdir(exist_ok=True)
RATE_LIMITS_FILE = DATA_DIR / "marketplace_rate_limits.json"
API_KEYS_FILE = DATA_DIR / "api_keys.json"

FREE_TIER_LIMIT = 5
GIT_CLONE_TIMEOUT = 60
MAX_SOURCE_BYTES = 500_000  # 500 KB max inline source
MAX_JOBS = 200  # Max stored async job files

logger = logging.getLogger("euaiact-marketplace-api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

# --- Pydantic models ---

class ScanRequest(BaseModel):
    url: Optional[str] = Field(None, description="GitHub repo URL to scan (HTTPS)")
    code_source: Optional[str] = Field(None, description="Inline source code to scan")
    risk_category: str = Field("limited", description="Risk category: unacceptable, high, limited, minimal")

class ScanResponse(BaseModel):
    scan_id: str
    timestamp: str
    risk_score: float
    risk_category: str
    frameworks_detected: list[str]
    files_scanned: int
    compliance_score: str
    recommendations: list[dict]
    source: str

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None

# --- Persistence ---

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

def _save_scan_result(scan_id: str, result: dict):
    scan_file = SCANS_DIR / f"{scan_id}.json"
    _save_json(scan_file, result)
    # Cleanup: keep max 500 scan files (TOCTOU-safe: stat may fail if concurrent cleanup)
    files_with_mtime = []
    for f in SCANS_DIR.glob("*.json"):
        try:
            files_with_mtime.append((f.stat().st_mtime, f))
        except OSError:
            pass
    files_with_mtime.sort()
    scan_files = [f for _, f in files_with_mtime]
    if len(scan_files) > 500:
        for old in scan_files[:len(scan_files) - 500]:
            old.unlink(missing_ok=True)

def _load_scan_result(scan_id: str) -> Optional[dict]:
    scan_file = SCANS_DIR / f"{scan_id}.json"
    if scan_file.exists():
        try:
            return json.loads(scan_file.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None

# --- Async job management ---

def _create_job(job_id: str, request_body: dict) -> dict:
    job = {
        "job_id": job_id,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "result": None,
        "error": None,
        "request": request_body,
    }
    _save_json(JOBS_DIR / f"{job_id}.json", job)
    # Cleanup old jobs (TOCTOU-safe)
    files_with_mtime = []
    for f in JOBS_DIR.glob("*.json"):
        try:
            files_with_mtime.append((f.stat().st_mtime, f))
        except OSError:
            pass
    files_with_mtime.sort()
    job_files = [f for _, f in files_with_mtime]
    if len(job_files) > MAX_JOBS:
        for old in job_files[:len(job_files) - MAX_JOBS]:
            old.unlink(missing_ok=True)
    return job

def _update_job(job_id: str, **kwargs):
    job_file = JOBS_DIR / f"{job_id}.json"
    if not job_file.exists():
        return
    try:
        job = json.loads(job_file.read_text())
        job.update(kwargs)
        _save_json(job_file, job)
    except (json.JSONDecodeError, OSError):
        pass

def _load_job(job_id: str) -> Optional[dict]:
    job_file = JOBS_DIR / f"{job_id}.json"
    if job_file.exists():
        try:
            return json.loads(job_file.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None

def _run_scan_job(job_id: str, url: Optional[str], code_source: Optional[str], risk_category: str):
    """Background worker: runs the scan and updates job state."""
    _update_job(job_id, status="running")
    tmp_dir = None
    try:
        if url:
            tmp_dir = _clone_repo_blocking(url)
            source_label = url
        else:
            tmp_dir = _write_source_to_temp(code_source)
            source_label = "inline_code"
        result = _run_scan(tmp_dir, risk_category)
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        full_result = {"scan_id": scan_id, "timestamp": timestamp, "source": source_label, **result}
        _save_scan_result(scan_id, full_result)
        _update_job(
            job_id,
            status="done",
            completed_at=datetime.now(timezone.utc).isoformat(),
            result=full_result,
        )
    except HTTPException as e:
        _update_job(
            job_id,
            status="error",
            completed_at=datetime.now(timezone.utc).isoformat(),
            error=str(e.detail),
        )
    except Exception as e:
        _update_job(
            job_id,
            status="error",
            completed_at=datetime.now(timezone.utc).isoformat(),
            error=str(e),
        )
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

# --- Rate limiting ---

def _check_rate_limit(ip: str) -> tuple[bool, int]:
    limits = _load_json(RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
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

def _get_usage(ip: str) -> dict:
    limits = _load_json(RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entry = limits.get(ip, {"date": today, "count": 0})
    if entry.get("date") != today:
        return {"used": 0, "limit": FREE_TIER_LIMIT, "remaining": FREE_TIER_LIMIT}
    used = entry.get("count", 0)
    return {"used": used, "limit": FREE_TIER_LIMIT, "remaining": max(0, FREE_TIER_LIMIT - used)}

# --- API key validation ---

def _validate_api_key(key: Optional[str]) -> bool:
    if not key:
        return False
    keys = _load_json(API_KEYS_FILE, {})
    entry = keys.get(key)
    if entry and entry.get("active"):
        plan = entry.get("plan", entry.get("tier", ""))
        return plan in ("pro", "paid_scan", "marketplace")
    return False

def _extract_api_key(request: Request) -> Optional[str]:
    key = request.headers.get("x-api-key")
    if key:
        return key
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None

# --- Scanner helpers ---

def _clone_repo(url: str, timeout: int = GIT_CLONE_TIMEOUT) -> str:
    if not url.startswith("https://"):
        raise HTTPException(400, "URL must start with https://")
    clone_dir = tempfile.mkdtemp(prefix="euaiact_scan_")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, clone_dir],
            check=True, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.CalledProcessError as e:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise HTTPException(400, f"Cannot clone repo: {e.stderr[:200]}")
    except subprocess.TimeoutExpired:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise HTTPException(408, f"Git clone timed out ({timeout}s limit)")
    return clone_dir

# Async variant: longer timeout (300s) for background jobs
def _clone_repo_blocking(url: str) -> str:
    return _clone_repo(url, timeout=300)

def _write_source_to_temp(code_source: str) -> str:
    tmp_dir = tempfile.mkdtemp(prefix="euaiact_src_")
    (Path(tmp_dir) / "source_code.py").write_text(code_source)
    return tmp_dir

def _run_scan(project_path: str, risk_category: str) -> dict:
    checker = EUAIActChecker(project_path)
    scan_result = checker.scan_project()
    if scan_result.get("error"):
        raise HTTPException(403, scan_result["error"])
    compliance = checker.check_compliance(risk_category)
    report = checker.generate_report(scan_result, compliance)
    frameworks = list(scan_result.get("detected_models", {}).keys())
    compliance_pct = compliance.get("compliance_percentage", 0)
    # risk_score: 0 (fully compliant) to 100 (no compliance)
    risk_score = round(100.0 - compliance_pct, 1)
    recommendations = report.get("recommendations", [])
    # Filter to only actionable (FAIL / ACTION_REQUIRED)
    actionable = [r for r in recommendations if r.get("status") in ("FAIL", "ACTION_REQUIRED")]
    return {
        "risk_score": risk_score,
        "risk_category": risk_category,
        "frameworks_detected": frameworks,
        "files_scanned": scan_result.get("files_scanned", 0),
        "compliance_score": compliance.get("compliance_score", "0/0"),
        "compliance_percentage": compliance_pct,
        "recommendations": actionable,
        "detailed_findings": report.get("detailed_findings", {}),
    }

# --- FastAPI app ---

app = FastAPI(
    title="EU AI Act Compliance Scanner API",
    description=(
        "Scan GitHub repos or source code for EU AI Act compliance. "
        "Detects 16+ AI frameworks, checks compliance, provides actionable recommendations. "
        "Free: 5 scans/day. API key: unlimited."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_PAYLOAD_BYTES = 1_000_000

@app.middleware("http")
async def limit_payload(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        cl = request.headers.get("content-length")
        if cl and int(cl) > MAX_PAYLOAD_BYTES:
            return JSONResponse({"error": "Payload too large (max 1 MB)"}, status_code=413)
    return await call_next(request)

def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# --- Endpoints ---

@app.get("/health")
async def health():
    return {"status": "ok", "service": "euaiact-marketplace-api", "version": "1.0.0"}

@app.post("/v1/scan", response_model=ScanResponse)
async def scan(request: Request, body: ScanRequest):
    """Scan a GitHub repo URL or inline source code for EU AI Act compliance.

    Provide either `url` (GitHub HTTPS URL) or `code_source` (inline code).
    Returns risk score, detected frameworks, compliance score, and recommendations.
    """
    if not body.url and not body.code_source:
        raise HTTPException(400, "Provide either 'url' (GitHub repo) or 'code_source' (inline code)")
    if body.url and body.code_source:
        raise HTTPException(400, "Provide either 'url' or 'code_source', not both")
    if body.code_source and len(body.code_source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise HTTPException(413, f"Source code too large (max {MAX_SOURCE_BYTES // 1000} KB)")

    valid_categories = ["unacceptable", "high", "limited", "minimal"]
    if body.risk_category not in valid_categories:
        raise HTTPException(400, f"Invalid risk_category. Valid: {valid_categories}")

    # Rate limiting (skip for valid API keys)
    api_key = _extract_api_key(request)
    has_key = _validate_api_key(api_key)
    if not has_key:
        ip = _get_client_ip(request)
        allowed, remaining = _check_rate_limit(ip)
        if not allowed:
            raise HTTPException(429, {
                "error": "Rate limit exceeded (5/day)",
                "upgrade": "Get an API key for unlimited access",
                "reset": "Tomorrow 00:00 UTC",
            })

    # Scan
    tmp_dir = None
    source_label = ""
    try:
        if body.url:
            tmp_dir = _clone_repo(body.url)
            source_label = body.url
        else:
            tmp_dir = _write_source_to_temp(body.code_source)
            source_label = "inline_code"

        result = _run_scan(tmp_dir, body.risk_category)
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    scan_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    response = {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "source": source_label,
        **result,
    }

    _save_scan_result(scan_id, response)

    return response

@app.get("/v1/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Retrieve a previous scan result by ID."""
    # Basic UUID validation
    try:
        uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(400, "Invalid scan_id format")

    result = _load_scan_result(scan_id)
    if not result:
        raise HTTPException(404, "Scan not found or expired")
    return result

@app.get("/v1/usage")
async def usage(request: Request):
    """Check your current rate limit usage."""
    ip = _get_client_ip(request)
    api_key = _extract_api_key(request)
    has_key = _validate_api_key(api_key)
    if has_key:
        return {"plan": "pro", "rate_limit": "unlimited"}
    u = _get_usage(ip)
    now_dt = datetime.now(timezone.utc)
    midnight = (now_dt + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return {
        "plan": "free",
        "daily_limit": FREE_TIER_LIMIT,
        "used": u["used"],
        "remaining": u["remaining"],
        "resets_in_seconds": int((midnight - now_dt).total_seconds()),
    }

@app.post("/v1/scan/async", status_code=202)
async def scan_async(request: Request, body: ScanRequest, background_tasks: BackgroundTasks):
    """Start an async scan job. Returns immediately with a job_id.

    Use GET /v1/job/{job_id} to poll for results.
    Useful for large repos that may exceed the 60s synchronous timeout.
    """
    if not body.url and not body.code_source:
        raise HTTPException(400, "Provide either 'url' (GitHub repo) or 'code_source' (inline code)")
    if body.url and body.code_source:
        raise HTTPException(400, "Provide either 'url' or 'code_source', not both")
    if body.code_source and len(body.code_source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise HTTPException(413, f"Source code too large (max {MAX_SOURCE_BYTES // 1000} KB)")

    valid_categories = ["unacceptable", "high", "limited", "minimal"]
    if body.risk_category not in valid_categories:
        raise HTTPException(400, f"Invalid risk_category. Valid: {valid_categories}")

    # Rate limiting (same rules as sync endpoint)
    api_key = _extract_api_key(request)
    has_key = _validate_api_key(api_key)
    if not has_key:
        ip = _get_client_ip(request)
        allowed, remaining = _check_rate_limit(ip)
        if not allowed:
            raise HTTPException(429, {
                "error": "Rate limit exceeded (5/day)",
                "upgrade": "Get an API key for unlimited access",
                "reset": "Tomorrow 00:00 UTC",
            })

    job_id = str(uuid.uuid4())
    _create_job(job_id, {
        "url": body.url,
        "risk_category": body.risk_category,
        "has_code_source": body.code_source is not None,
    })

    # Run scan in a background thread (non-blocking for the HTTP response)
    thread = threading.Thread(
        target=_run_scan_job,
        args=(job_id, body.url, body.code_source, body.risk_category),
        daemon=True,
    )
    thread.start()

    return {
        "job_id": job_id,
        "status": "pending",
        "poll_url": f"/v1/job/{job_id}",
        "message": "Scan started. Poll poll_url for results.",
    }


@app.get("/v1/job/{job_id}")
async def get_job(job_id: str):
    """Poll an async scan job status.

    Status values: pending → running → done | error
    When status is 'done', the full scan result is in the 'result' field.
    """
    try:
        uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(400, "Invalid job_id format")

    job = _load_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found or expired")

    # Return minimal response to avoid large payloads while pending/running
    response = {
        "job_id": job["job_id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "completed_at": job.get("completed_at"),
    }
    if job["status"] == "done":
        response["result"] = job.get("result")
    elif job["status"] == "error":
        response["error"] = job.get("error")
    return response


if __name__ == "__main__":
    port = int(os.environ.get("EUAIACT_API_PORT", "8200"))
    logger.info("Starting EU AI Act Marketplace API on 0.0.0.0:%d", port)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
