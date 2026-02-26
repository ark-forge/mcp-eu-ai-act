#!/usr/bin/env python3
"""
MCP EU AI Act - REST API
FastAPI server providing:
- Free tier: 10 scans/day per IP
- Pro tier: 29EUR/month via Stripe (https://arkforge.fr/pricing)
- Scan, compliance check, and report endpoints

Payment via Stripe payment link. API keys sent by email after subscription.
This service is a pure scanner with rate-limited free access.
"""

import os
import sys
import json
import hmac
import hashlib
import logging
import secrets
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

import stripe
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
API_KEYS_FILE = DATA_DIR / "api_keys.json"

FREE_TIER_LIMIT = 10  # scans per day per IP

logger = logging.getLogger("eu-ai-act-api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

# --- Load settings.env for Stripe keys ---
def _load_settings_env() -> dict:
    """Load key=value pairs from settings.env."""
    cfg = {}
    env_path = os.environ.get("SETTINGS_ENV_PATH", "/opt/claude-ceo/config/settings.env")
    try:
        for line in Path(env_path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return cfg

_settings = _load_settings_env()
STRIPE_WEBHOOK_SECRET = _settings.get("STRIPE_WEBHOOK_SECRET", "")
stripe.api_key = _settings.get("STRIPE_LIVE_SECRET_KEY", "")

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


MAX_PAYLOAD_BYTES = 1_000_000  # 1 MB max request body

@app.middleware("http")
async def limit_payload_size(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_PAYLOAD_BYTES:
            return JSONResponse({"error": "Payload too large (max 1 MB)"}, status_code=413)
    return await call_next(request)

FREE_TIER_BANNER = f"Free tier: {FREE_TIER_LIMIT}/day — Pro: unlimited scans + CI/CD API at 29EUR/mo → https://arkforge.fr/pricing"


def _check_free_tier(ip: str):
    """Check rate limit for free tier. Raises 429 if exceeded."""
    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        raise HTTPException(429, {
            "error": "Free tier limit reached (10/day)",
            "upgrade": "https://arkforge.fr/pricing",
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
        "paid_scans": "https://arkforge.fr/pricing",
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

INTERNAL_SECRET = os.environ.get("TRUST_LAYER_INTERNAL_SECRET", "")
if not INTERNAL_SECRET:
    logger.warning("TRUST_LAYER_INTERNAL_SECRET not set — /api/v1/scan-repo will reject all requests")

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
            "pro": {
                "price": "29 EUR/month",
                "description": "Unlimited scans + CI/CD API for teams",
                "features": [
                    "Unlimited scans",
                    "REST API for CI/CD pipelines",
                    "API key authentication",
                    "Scan history dashboard",
                    "Email alerts on risk changes",
                    "Priority support",
                ],
                "subscribe": "https://arkforge.fr/pricing",
            },
        },
        "contact": "contact@arkforge.fr",
    }


CONVERSIONS_FILE = DATA_DIR / "conversions.json"


@app.post("/api/trial-tracking/conversion")
async def track_conversion(request: Request):
    """Track a successful Stripe conversion from the success page."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    ip = get_client_ip(request)
    conversion = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "session_id": body.get("session_id", ""),
        "product": body.get("product", "unknown"),
    }

    conversions = _load_json(CONVERSIONS_FILE, [])
    conversions.append(conversion)
    if len(conversions) > 500:
        conversions = conversions[-500:]
    _save_json(CONVERSIONS_FILE, conversions)

    logger.info(f"Conversion tracked: session={conversion['session_id']} product={conversion['product']}")
    return {"status": "ok", "message": "Conversion tracked"}


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "mcp-eu-ai-act", "version": "1.1.0", "timestamp": datetime.now(timezone.utc).isoformat()}


# --- Pro API key extraction helper ---

def _extract_api_key(request: Request) -> Optional[str]:
    """Extract API key from X-API-Key header or Authorization: Bearer."""
    key = request.headers.get("x-api-key")
    if key:
        return key
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def _verify_pro_key(request: Request) -> dict:
    """Verify that request contains a valid Pro API key. Raises 401/403."""
    api_key = _extract_api_key(request)
    if not api_key:
        raise HTTPException(401, "API key required (X-API-Key header or Authorization: Bearer)")
    keys = _load_json(API_KEYS_FILE, {})
    entry = keys.get(api_key)
    if not entry or not entry.get("active"):
        raise HTTPException(401, "Invalid or inactive API key")
    plan = entry.get("plan", "free")
    if plan not in ("pro", "paid_scan"):
        raise HTTPException(403, "Pro plan required for this endpoint")
    return {**entry, "_key": api_key}


def _provision_api_key(email: str, stripe_customer_id: str, stripe_subscription_id: str = "unknown") -> str:
    """Create a new Pro API key for a paying customer. Returns the key string."""
    api_key = f"mcp_pro_{secrets.token_hex(24)}"
    keys = _load_json(API_KEYS_FILE, {})
    keys[api_key] = {
        "plan": "pro",
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "stripe_customer_id": stripe_customer_id,
        "stripe_subscription_id": stripe_subscription_id,
        "email": email,
        "scans_total": 0,
    }
    _save_json(API_KEYS_FILE, keys)
    logger.info(f"Provisioned Pro API key for {email} (customer={stripe_customer_id})")
    return api_key


def _send_api_key_email(email: str, api_key: str):
    """Send the API key to the customer via email_sender."""
    try:
        sys.path.insert(0, "/opt/claude-ceo/automation")
        from email_sender import send_email
        subject = "Your ArkForge MCP EU AI Act Pro API Key"
        body = (
            f"Thank you for subscribing to ArkForge MCP EU AI Act Pro!\n\n"
            f"Your API key: {api_key}\n\n"
            f"Usage:\n"
            f"  - HTTP header: X-API-Key: {api_key}\n"
            f"  - Or: Authorization: Bearer {api_key}\n\n"
            f"Documentation: https://arkforge.fr/docs\n"
            f"Support: contact@arkforge.fr\n\n"
            f"-- ArkForge"
        )
        send_email(email, subject, body, skip_warmup=True, skip_verify=True)
        logger.info(f"API key email sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send API key email to {email}: {e}")


# --- Stripe Webhook ---

@app.post("/api/stripe-webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events. Auto-provisions API keys on successful checkout."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    if not STRIPE_WEBHOOK_SECRET:
        logger.error("STRIPE_WEBHOOK_SECRET not configured")
        raise HTTPException(500, "Webhook not configured")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        logger.warning("Stripe webhook signature verification failed")
        raise HTTPException(400, "Invalid signature")
    except ValueError:
        raise HTTPException(400, "Invalid payload")

    event_type = event.get("type", "")
    logger.info(f"Stripe webhook: {event_type}")

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        customer_email = session.get("customer_details", {}).get("email") or session.get("customer_email", "")
        customer_id = session.get("customer", "")
        subscription_id = session.get("subscription", "unknown") or "unknown"

        if customer_email:
            # Check if customer already has an active key
            keys = _load_json(API_KEYS_FILE, {})
            existing_key = None
            for k, v in keys.items():
                if v.get("email", "").lower() == customer_email.lower() and v.get("active"):
                    existing_key = k
                    break

            if existing_key:
                # Update existing key with subscription info
                keys[existing_key]["stripe_customer_id"] = customer_id
                keys[existing_key]["stripe_subscription_id"] = subscription_id
                _save_json(API_KEYS_FILE, keys)
                _send_api_key_email(customer_email, existing_key)
                logger.info(f"Reactivated existing key for {customer_email}")
            else:
                api_key = _provision_api_key(customer_email, customer_id, subscription_id)
                _send_api_key_email(customer_email, api_key)
        else:
            logger.warning(f"Checkout completed but no customer email: session={session.get('id')}")

    elif event_type == "customer.subscription.deleted":
        sub = event["data"]["object"]
        sub_id = sub.get("id", "")
        # Deactivate keys linked to this subscription
        keys = _load_json(API_KEYS_FILE, {})
        for k, v in keys.items():
            if v.get("stripe_subscription_id") == sub_id and v.get("active"):
                v["active"] = False
                v["deactivated_at"] = datetime.now(timezone.utc).isoformat()
                v["deactivated_reason"] = "subscription_cancelled"
                logger.info(f"Deactivated key for cancelled subscription {sub_id}")
        _save_json(API_KEYS_FILE, keys)

    # Log all webhook events
    webhooks_file = DATA_DIR / "stripe_webhooks.json"
    webhooks = _load_json(webhooks_file, [])
    webhooks.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "event_id": event.get("id", ""),
    })
    if len(webhooks) > 200:
        webhooks = webhooks[-200:]
    _save_json(webhooks_file, webhooks)

    return {"received": True}


# --- Pro Dashboard ---

@app.get("/api/v1/dashboard")
async def pro_dashboard(request: Request):
    """Return scan history and usage stats for authenticated Pro user."""
    pro_info = _verify_pro_key(request)
    api_key = pro_info["_key"]
    key_prefix = api_key[:12] + "..."

    # Load scan history, filter for this key
    history = _load_json(SCAN_HISTORY_FILE, [])
    my_scans = [
        s for s in history
        if s.get("api_key") == key_prefix or s.get("api_key") == api_key
    ]

    # Usage stats
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    scans_today = sum(1 for s in my_scans if s.get("timestamp", "").startswith(today))

    last_7d_cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    scans_7d = sum(1 for s in my_scans if s.get("timestamp", "") >= last_7d_cutoff)

    return {
        "plan": pro_info.get("plan", "pro"),
        "email": pro_info.get("email", ""),
        "scans_total": pro_info.get("scans_total", 0),
        "scans_today": scans_today,
        "scans_last_7d": scans_7d,
        "member_since": pro_info.get("created_at", ""),
        "recent_scans": my_scans[-20:],  # Last 20 scans
    }


# --- Email Alerts Configuration ---

ALERTS_FILE = DATA_DIR / "alert_configs.json"

@app.get("/api/v1/alerts")
async def get_alerts(request: Request):
    """Get email alert preferences for authenticated Pro user."""
    pro_info = _verify_pro_key(request)
    email = pro_info.get("email", "")
    configs = _load_json(ALERTS_FILE, {})
    my_config = configs.get(email, {
        "enabled": False,
        "risk_change": True,
        "weekly_summary": True,
    })
    return {"email": email, "alerts": my_config}


@app.post("/api/v1/alerts")
async def update_alerts(request: Request):
    """Update email alert preferences for authenticated Pro user."""
    pro_info = _verify_pro_key(request)
    email = pro_info.get("email", "")
    body = await request.json()

    configs = _load_json(ALERTS_FILE, {})
    current = configs.get(email, {})
    if "enabled" in body:
        current["enabled"] = bool(body["enabled"])
    if "risk_change" in body:
        current["risk_change"] = bool(body["risk_change"])
    if "weekly_summary" in body:
        current["weekly_summary"] = bool(body["weekly_summary"])
    current["updated_at"] = datetime.now(timezone.utc).isoformat()
    configs[email] = current
    _save_json(ALERTS_FILE, configs)

    return {"status": "ok", "email": email, "alerts": current}


if __name__ == "__main__":
    logger.info("Starting MCP EU AI Act REST API on 0.0.0.0:8091")
    logger.info("Stripe configured: %s", "yes" if stripe.api_key else "NO — payments will fail")
    logger.info("Internal secret configured: %s", "yes" if INTERNAL_SECRET else "NO — Trust Layer calls will fail")
    uvicorn.run(app, host="0.0.0.0", port=8091, log_level="info")
