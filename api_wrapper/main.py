"""
REST API wrapper for the EU AI Act Compliance Scanner.
Exposes the MCP scanner as a standard REST API for RapidAPI / CI/CD integration.

Endpoints:
    GET  /health      — Health check
    GET  /categories  — List EU AI Act risk categories and requirements
    POST /scan        — Scan code/text for AI framework usage + compliance check

Rate limiting: 10 requests/day (IP-based) without API key; unlimited with valid key.
API key: pass via X-Api-Key header or Authorization: Bearer <key>.
"""

import json
import sys
import tempfile
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

# Add parent dir to path so we can import server.py
_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from server import EUAIActChecker, RISK_CATEGORIES, ACTIONABLE_GUIDANCE

# --- Rate limiting config ---
_PARENT_DIR = Path(__file__).resolve().parent.parent
_DATA_DIR = _PARENT_DIR / "data"
_DATA_DIR.mkdir(exist_ok=True)
_RATE_LIMITS_FILE = _DATA_DIR / "wrapper_rate_limits.json"
_API_KEYS_FILE = _DATA_DIR / "api_keys.json"
_FREE_TIER_LIMIT = 10  # requests/day per IP


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


def _validate_api_key(key: Optional[str]) -> bool:
    if not key:
        return False
    keys = _load_json(_API_KEYS_FILE, {})
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


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(ip: str) -> tuple[bool, int]:
    """Returns (allowed, remaining). Increments counter if allowed."""
    limits = _load_json(_RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # Purge stale dates
    limits = {k: v for k, v in limits.items() if v.get("date") == today}
    entry = limits.get(ip, {"date": today, "count": 0})
    if entry.get("date") != today:
        entry = {"date": today, "count": 0}
    remaining = max(0, _FREE_TIER_LIMIT - entry["count"])
    if remaining > 0:
        entry["count"] += 1
        entry["date"] = today
        limits[ip] = entry
        _save_json(_RATE_LIMITS_FILE, limits)
        return True, remaining - 1
    return False, 0


app = FastAPI(
    title="EU AI Act Compliance Scanner API",
    description=(
        "Scan source code or project descriptions for AI framework usage "
        "and check EU AI Act regulatory compliance. "
        "Powered by ArkForge — https://mcp.arkforge.fr"
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


# --- Models ---

class ScanRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=500_000,
        description="Source code or project text to scan for AI framework usage",
    )
    context: str = Field(
        default="general",
        max_length=500,
        description="Context about the project (e.g. 'chatbot for customer support')",
    )
    risk_category: str = Field(
        default="limited",
        description="EU AI Act risk category: unacceptable, high, limited, minimal",
    )
    filename: str = Field(
        default="main.py",
        max_length=255,
        description="Filename hint for the submitted text (affects detection patterns)",
    )


class ScanResponse(BaseModel):
    scan: dict
    compliance: dict
    recommendations: list
    meta: dict


# --- Endpoints ---

@app.get("/health")
def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "eu-ai-act-scanner",
        "version": "1.0.0",
    }


@app.get("/categories")
def categories():
    """List all EU AI Act risk categories with descriptions and requirements."""
    result = {}
    for cat, info in RISK_CATEGORIES.items():
        result[cat] = {
            "description": info["description"],
            "requirements": info["requirements"],
            "requirements_count": len(info["requirements"]),
        }
    return {
        "categories": result,
        "guidance_available": sorted(ACTIONABLE_GUIDANCE.keys()),
    }


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest, request: Request):
    """Scan submitted text/code for AI framework usage and check EU AI Act compliance.

    The text is written to a temporary directory, scanned by the EU AI Act checker,
    and then cleaned up. No data is persisted.

    Rate limit: 10 requests/day per IP (free). Pass X-Api-Key or Authorization: Bearer
    for unlimited access.
    """
    # --- Rate limiting ---
    api_key = _extract_api_key(request)
    if not _validate_api_key(api_key):
        ip = _get_client_ip(request)
        allowed, remaining = _check_rate_limit(ip)
        if not allowed:
            now_dt = datetime.now(timezone.utc)
            midnight = (now_dt + timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "error": f"Rate limit exceeded ({_FREE_TIER_LIMIT}/day)",
                    "upgrade": "Pass X-Api-Key header for unlimited access",
                    "resets_in_seconds": int((midnight - now_dt).total_seconds()),
                },
            )

    if req.risk_category not in RISK_CATEGORIES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid risk_category '{req.risk_category}'. "
                   f"Valid: {list(RISK_CATEGORIES.keys())}",
        )

    # Sanitize filename to prevent path traversal
    safe_name = Path(req.filename).name
    if not safe_name:
        safe_name = "main.py"

    tmpdir = tempfile.mkdtemp(prefix="euaiact_scan_")
    try:
        # Write submitted text as a file
        target = Path(tmpdir) / safe_name
        target.write_text(req.text, encoding="utf-8")

        # If context mentions something useful, write a README for compliance checks
        if req.context and req.context != "general":
            readme = Path(tmpdir) / "README.md"
            readme.write_text(
                f"# Project\n\n{req.context}\n",
                encoding="utf-8",
            )

        # Run scanner
        checker = EUAIActChecker(tmpdir)
        scan_results = checker.scan_project()
        compliance_results = checker.check_compliance(req.risk_category)
        recommendations = checker._generate_recommendations(compliance_results)

        return ScanResponse(
            scan={
                "files_scanned": scan_results.get("files_scanned", 0),
                "detected_models": scan_results.get("detected_models", {}),
                "ai_files": scan_results.get("ai_files", []),
            },
            compliance={
                "risk_category": compliance_results.get("risk_category", req.risk_category),
                "description": compliance_results.get("description", ""),
                "compliance_score": compliance_results.get("compliance_score", "0/0"),
                "compliance_percentage": compliance_results.get("compliance_percentage", 0),
                "compliance_status": compliance_results.get("compliance_status", {}),
                "requirements": compliance_results.get("requirements", []),
            },
            recommendations=recommendations,
            meta={
                "risk_category_used": req.risk_category,
                "filename": safe_name,
                "pricing": "https://arkforge.tech/en/pricing.html?utm_source=rapidapi",
                "trust_layer": "https://arkforge.tech/trust?utm_source=rapidapi",
            },
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
