#!/usr/bin/env python3
"""
MCP EU AI Act - Paywall REST API
FastAPI server providing:
- Free tier: 10 scans/day per IP
- Pro tier: unlimited scans with API key (29€/month)
- Stripe Checkout + webhook
- Dashboard + CI/CD endpoint
"""

import os
import json
import hmac
import hashlib
import secrets
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

import stripe
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# --- Config ---
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

API_KEYS_FILE = DATA_DIR / "api_keys.json"
RATE_LIMITS_FILE = DATA_DIR / "rate_limits.json"
SCAN_HISTORY_FILE = DATA_DIR / "scan_history.json"

# Load Stripe keys from environment or settings.env
SETTINGS_ENV = Path(os.environ.get("SETTINGS_ENV_PATH", str(Path(__file__).resolve().parent / "config" / "settings.env")))
if SETTINGS_ENV.exists():
    for line in SETTINGS_ENV.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

STRIPE_LIVE_KEY = os.environ.get("STRIPE_LIVE_SECRET_KEY", "")
STRIPE_TEST_KEY = os.environ.get("STRIPE_TEST_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

# Default to live for non-authenticated endpoints (webhooks, checkout, free scans)
stripe.api_key = STRIPE_LIVE_KEY


def _stripe_key_for_api_key(api_key: str) -> str:
    """Return Stripe secret key based on API key prefix. mcp_test_* → test, else → live."""
    if api_key.startswith("mcp_test_"):
        return STRIPE_TEST_KEY
    return STRIPE_LIVE_KEY

FREE_TIER_LIMIT = 10  # scans per day per IP
PRO_PRICE_EUR = 29  # €/month

logger = logging.getLogger("paywall")
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


# --- API Key management ---

def load_api_keys() -> dict:
    return _load_json(API_KEYS_FILE, {})

def save_api_keys(keys: dict):
    _save_json(API_KEYS_FILE, keys)

def generate_api_key() -> str:
    return f"mcp_pro_{secrets.token_hex(24)}"

def validate_api_key(key: str) -> Optional[dict]:
    keys = load_api_keys()
    info = keys.get(key)
    if info and info.get("active"):
        return info
    return None

def create_api_key(stripe_customer_id: str, stripe_subscription_id: str, email: str = "") -> str:
    keys = load_api_keys()
    key = generate_api_key()
    keys[key] = {
        "plan": "pro",
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "stripe_customer_id": stripe_customer_id,
        "stripe_subscription_id": stripe_subscription_id,
        "email": email,
        "scans_total": 0,
    }
    save_api_keys(keys)
    logger.info("API key created for customer %s", stripe_customer_id)
    return key

def deactivate_key_by_subscription(subscription_id: str):
    keys = load_api_keys()
    for key, info in keys.items():
        if info.get("stripe_subscription_id") == subscription_id:
            info["active"] = False
            info["deactivated_at"] = datetime.now(timezone.utc).isoformat()
            logger.info("API key deactivated for subscription %s", subscription_id)
    save_api_keys(keys)

def find_key_by_subscription(subscription_id: str) -> Optional[str]:
    keys = load_api_keys()
    for key, info in keys.items():
        if info.get("stripe_subscription_id") == subscription_id and info.get("active"):
            return key
    return None


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

def record_scan(api_key: Optional[str], ip: str, scan_type: str, result_summary: dict):
    history = _load_json(SCAN_HISTORY_FILE, [])
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "api_key": api_key[:12] + "..." if api_key else None,
        "ip": ip,
        "plan": "pro" if api_key else "free",
        "scan_type": scan_type,
        "frameworks_detected": result_summary.get("frameworks_detected", []),
        "files_scanned": result_summary.get("files_scanned", 0),
    })
    # Keep last 1000 entries
    if len(history) > 1000:
        history = history[-1000:]
    _save_json(SCAN_HISTORY_FILE, history)

    # Increment key scan counter
    if api_key:
        keys = load_api_keys()
        if api_key in keys:
            keys[api_key]["scans_total"] = keys[api_key].get("scans_total", 0) + 1
            keys[api_key]["last_scan"] = datetime.now(timezone.utc).isoformat()
            save_api_keys(keys)


# --- Import scanner from server.py ---

from server import EUAIActChecker, _validate_project_path


# --- FastAPI app ---

app = FastAPI(
    title="MCP EU AI Act - Pro API",
    description="EU AI Act Compliance Scanner REST API. Free: 10 scans/day. Pro: unlimited at 29€/month.",
    version="1.0.0",
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


def get_api_key(authorization: Optional[str] = Header(None), x_api_key: Optional[str] = Header(None)) -> Optional[str]:
    """Extract API key from Authorization header or X-Api-Key header."""
    if x_api_key:
        return x_api_key
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]
    return None


FREE_TIER_BANNER = f"Free tier: {FREE_TIER_LIMIT}/day — Pro: unlimited at {PRO_PRICE_EUR}€/mo → https://arkforge.fr/pricing"


# --- Usage endpoint (for pricing page widget) ---

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


# --- API Key Verification Endpoint (Paywall Step 2) ---

@app.post("/api/verify-key")
async def verify_key(request: Request):
    """Verify an API key. Returns plan info if valid, 401 if invalid."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, 'Invalid JSON body. Expected: {"key": "your_api_key"}')

    api_key = body.get("key", "")
    if not api_key:
        raise HTTPException(400, 'Missing "key" field. Expected: {"key": "your_api_key"}')

    key_info = validate_api_key(api_key)
    if key_info:
        return {"valid": True, "plan": key_info.get("plan", "pro"), "email": key_info.get("email", "")}
    else:
        return JSONResponse(status_code=401, content={"valid": False, "error": "Invalid or inactive API key"})


# --- REST API Endpoints ---

@app.get("/api/v1/status")
async def api_status(request: Request):
    ip = get_client_ip(request)
    usage = get_rate_limit_usage(ip)
    return {
        "service": "MCP EU AI Act Compliance Checker",
        "version": "1.0.0",
        "your_plan": "free",
        "rate_limit": usage,
        "upgrade": f"https://arkforge.fr/pricing",
    }


@app.post("/api/v1/scan")
async def api_scan(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Scan a project for AI framework usage. CI/CD compatible."""
    body = await request.json()
    project_path = body.get("project_path", "")
    if not project_path:
        raise HTTPException(400, "project_path is required")

    ip = get_client_ip(request)
    api_key = get_api_key(authorization, x_api_key)

    # Auth check
    plan = "free"
    if api_key:
        key_info = validate_api_key(api_key)
        if not key_info:
            raise HTTPException(401, "Invalid or inactive API key")
        plan = "pro"
    else:
        allowed, remaining = check_rate_limit(ip)
        if not allowed:
            raise HTTPException(429, {
                "error": "Free tier limit reached (10/day)",
                "upgrade": "https://arkforge.fr/pricing",
                "reset": "Tomorrow 00:00 UTC",
            })

    # Path validation
    is_safe, error_msg = _validate_project_path(project_path)
    if not is_safe:
        raise HTTPException(403, error_msg)

    # Scan
    checker = EUAIActChecker(project_path)
    result = checker.scan_project()

    # Record
    summary = {
        "frameworks_detected": list(result.get("detected_models", {}).keys()),
        "files_scanned": result.get("files_scanned", 0),
    }
    record_scan(api_key, ip, "scan", summary)

    response = {
        "plan": plan,
        **result,
    }
    if plan == "free":
        usage = get_rate_limit_usage(ip)
        response["rate_limit"] = usage
        response["banner"] = FREE_TIER_BANNER

    return response


@app.post("/api/v1/check-compliance")
async def api_check_compliance(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Check EU AI Act compliance. CI/CD compatible."""
    body = await request.json()
    project_path = body.get("project_path", "")
    risk_category = body.get("risk_category", "limited")
    if not project_path:
        raise HTTPException(400, "project_path is required")

    ip = get_client_ip(request)
    api_key = get_api_key(authorization, x_api_key)

    plan = "free"
    if api_key:
        key_info = validate_api_key(api_key)
        if not key_info:
            raise HTTPException(401, "Invalid or inactive API key")
        plan = "pro"
    else:
        allowed, remaining = check_rate_limit(ip)
        if not allowed:
            raise HTTPException(429, {
                "error": "Free tier limit reached (10/day)",
                "upgrade": "https://arkforge.fr/pricing",
            })

    is_safe, error_msg = _validate_project_path(project_path)
    if not is_safe:
        raise HTTPException(403, error_msg)

    checker = EUAIActChecker(project_path)
    checker.scan_project()
    result = checker.check_compliance(risk_category)

    record_scan(api_key, ip, "compliance", {"frameworks_detected": [], "files_scanned": 0})

    response = {"plan": plan, **result}
    if plan == "free":
        response["rate_limit"] = get_rate_limit_usage(ip)
        response["banner"] = FREE_TIER_BANNER

    return response


@app.post("/api/v1/report")
async def api_report(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Generate full compliance report. CI/CD compatible."""
    body = await request.json()
    project_path = body.get("project_path", "")
    risk_category = body.get("risk_category", "limited")
    if not project_path:
        raise HTTPException(400, "project_path is required")

    ip = get_client_ip(request)
    api_key = get_api_key(authorization, x_api_key)

    plan = "free"
    if api_key:
        key_info = validate_api_key(api_key)
        if not key_info:
            raise HTTPException(401, "Invalid or inactive API key")
        plan = "pro"
    else:
        allowed, remaining = check_rate_limit(ip)
        if not allowed:
            raise HTTPException(429, {
                "error": "Free tier limit reached (10/day)",
                "upgrade": "https://arkforge.fr/pricing",
            })

    is_safe, error_msg = _validate_project_path(project_path)
    if not is_safe:
        raise HTTPException(403, error_msg)

    checker = EUAIActChecker(project_path)
    scan_results = checker.scan_project()
    compliance_results = checker.check_compliance(risk_category)
    report = checker.generate_report(scan_results, compliance_results)

    record_scan(api_key, ip, "report", {
        "frameworks_detected": list(scan_results.get("detected_models", {}).keys()),
        "files_scanned": scan_results.get("files_scanned", 0),
    })

    response = {"plan": plan, **report}
    if plan == "free":
        response["rate_limit"] = get_rate_limit_usage(ip)
        response["banner"] = FREE_TIER_BANNER

    return response


# --- Stripe endpoints ---

@app.post("/api/create-checkout")
async def create_checkout_session(request: Request):
    """Create a Stripe Checkout session for Pro subscription."""
    if not STRIPE_LIVE_KEY and not STRIPE_TEST_KEY:
        raise HTTPException(500, "Stripe not configured")

    body = await request.json()
    email = body.get("email", "")

    try:
        # Create or find Stripe price for 29€/month
        prices = stripe.Price.list(
            lookup_keys=["mcp_pro_monthly"],
            active=True,
            limit=1,
        )

        if prices.data:
            price_id = prices.data[0].id
        else:
            # Create product + price if not exists
            product = stripe.Product.create(
                name="MCP EU AI Act - Pro",
                description="Unlimited AI compliance scans, CI/CD integration, dashboard, alerts",
                metadata={"type": "mcp_pro"},
            )
            price = stripe.Price.create(
                product=product.id,
                unit_amount=PRO_PRICE_EUR * 100,  # cents
                currency="eur",
                recurring={"interval": "month"},
                lookup_key="mcp_pro_monthly",
            )
            price_id = price.id

        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            success_url="https://arkforge.fr/fr/mcp-success.html?session_id={CHECKOUT_SESSION_ID}",
            cancel_url="https://arkforge.fr/fr/pricing.html?canceled=true",
            customer_email=email if email else None,
            metadata={"product": "mcp_pro"},
        )

        return {"checkout_url": session.url, "session_id": session.id}

    except stripe.StripeError as e:
        logger.error("Stripe error: %s", e)
        raise HTTPException(500, f"Stripe error: {str(e)}")


@app.post("/api/v1/setup-payment-method")
async def setup_payment_method(request: Request):
    """Create a Stripe Checkout Session in setup mode to save a card for future off-session payments."""
    if not STRIPE_LIVE_KEY and not STRIPE_TEST_KEY:
        raise HTTPException(500, "Stripe not configured")

    body = await request.json()
    email = body.get("email", "")
    if not email:
        raise HTTPException(400, "email is required")

    try:
        # Find or create customer
        customers = stripe.Customer.list(email=email, limit=1)
        if customers.data:
            customer = customers.data[0]
        else:
            customer = stripe.Customer.create(
                email=email,
                metadata={"source": "agent-client-setup"},
            )

        session = stripe.checkout.Session.create(
            mode="setup",
            payment_method_types=["card"],
            customer=customer.id,
            success_url="https://arkforge.fr/fr/mcp-success.html?card_saved=true&session_id={CHECKOUT_SESSION_ID}",
            cancel_url="https://arkforge.fr/fr/pricing.html?canceled=true",
            metadata={"product": "agent_client_setup", "email": email},
        )

        return {"checkout_url": session.url, "session_id": session.id, "customer_id": customer.id}

    except stripe.StripeError as e:
        logger.error("Stripe setup error: %s", e)
        raise HTTPException(500, f"Stripe error: {str(e)}")


PAID_SCAN_PRICE_CENTS = 50  # 0.50 EUR


@app.post("/api/v1/paid-scan")
async def paid_scan(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Execute a paid scan: charge 0.50 EUR on saved card, then scan repo."""
    if not STRIPE_LIVE_KEY and not STRIPE_TEST_KEY:
        raise HTTPException(500, "Stripe not configured")

    api_key = get_api_key(authorization, x_api_key)
    if not api_key:
        raise HTTPException(401, "API key required. Set X-Api-Key header.")

    key_info = validate_api_key(api_key)
    if not key_info:
        raise HTTPException(401, "Invalid or inactive API key")

    customer_id = key_info.get("stripe_customer_id", "")
    if not customer_id:
        raise HTTPException(400, "No Stripe customer linked to this API key")

    # Switch Stripe key based on API key prefix (test vs live)
    sk = _stripe_key_for_api_key(api_key)
    if not sk:
        raise HTTPException(500, "Stripe key not configured for this mode")

    body = await request.json()
    repo_url = body.get("repo_url", "")
    if not repo_url:
        raise HTTPException(400, "repo_url is required")

    # Step 1: Find default payment method
    try:
        customer = stripe.Customer.retrieve(customer_id, api_key=sk)
        pm_id = None
        # Check invoice_settings default
        if customer.get("invoice_settings", {}).get("default_payment_method"):
            pm_id = customer["invoice_settings"]["default_payment_method"]
        # Fallback: list payment methods
        if not pm_id:
            pms = stripe.PaymentMethod.list(customer=customer_id, type="card", limit=1, api_key=sk)
            if pms.data:
                pm_id = pms.data[0].id
        # Fallback: try link type
        if not pm_id:
            pms = stripe.PaymentMethod.list(customer=customer_id, type="link", limit=1, api_key=sk)
            if pms.data:
                pm_id = pms.data[0].id

        if not pm_id:
            raise HTTPException(400, "No payment method found. Run setup_card.py first.")

    except stripe.StripeError as e:
        logger.error("Stripe customer error: %s", e)
        raise HTTPException(500, f"Stripe error: {str(e)}")

    # Step 2: Charge 0.50 EUR off-session
    try:
        intent = stripe.PaymentIntent.create(
            amount=PAID_SCAN_PRICE_CENTS,
            currency="eur",
            customer=customer_id,
            payment_method=pm_id,
            off_session=True,
            confirm=True,
            description=f"EU AI Act scan: {repo_url[:80]}",
            metadata={
                "product": "paid_scan",
                "repo_url": repo_url[:200],
                "api_key_prefix": api_key[:12],
                "human_clicks": "0",
            },
            api_key=sk,
        )

        if intent.status != "succeeded":
            raise HTTPException(402, f"Payment failed: {intent.status}")

    except stripe.CardError as e:
        logger.error("Card declined: %s", e)
        raise HTTPException(402, f"Card declined: {e.user_message}")
    except stripe.StripeError as e:
        logger.error("Stripe payment error: %s", e)
        raise HTTPException(500, f"Stripe error: {str(e)}")

    # Step 3: Execute scan — clone repo if URL, else use as local path
    import tempfile
    import subprocess
    import shutil

    clone_dir = None
    scan_path = repo_url

    if repo_url.startswith("http://") or repo_url.startswith("https://"):
        clone_dir = tempfile.mkdtemp(prefix="scan_")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, clone_dir],
                check=True, capture_output=True, text=True, timeout=60,
            )
            scan_path = clone_dir
        except subprocess.CalledProcessError as e:
            shutil.rmtree(clone_dir, ignore_errors=True)
            logger.error("Git clone failed: %s", e.stderr)
            raise HTTPException(400, f"Cannot clone repo: {e.stderr[:200]}")
        except subprocess.TimeoutExpired:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise HTTPException(408, "Git clone timed out (60s limit)")

    try:
        checker = EUAIActChecker(scan_path)
        scan_result = checker.scan_project()
        compliance = checker.check_compliance("limited")
        report = checker.generate_report(scan_result, compliance)
        scan_result["report"] = report
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)

    ip = get_client_ip(request)
    summary = {
        "frameworks_detected": list(scan_result.get("detected_models", {}).keys()),
        "files_scanned": scan_result.get("files_scanned", 0),
    }
    record_scan(api_key, ip, "paid_scan", summary)

    # Update scan count on API key
    keys = load_api_keys()
    if api_key in keys:
        keys[api_key]["scans_total"] = keys[api_key].get("scans_total", 0) + 1
        save_api_keys(keys)

    payment_proof = {
        "payment_intent_id": intent.id,
        "amount_eur": PAID_SCAN_PRICE_CENTS / 100,
        "currency": "eur",
        "status": intent.status,
        "receipt_url": stripe.Charge.retrieve(intent.latest_charge, api_key=sk).receipt_url if intent.latest_charge else None,
    }

    # Send proof email to client (best effort, non-blocking)
    client_email = key_info.get("email", "")
    try:
        _send_proof_email(client_email, payment_proof, scan_result, repo_url)
    except Exception as e:
        logger.warning("Proof email error: %s", e)

    return {
        "payment_proof": payment_proof,
        "scan_result": {
            "plan": "paid_scan",
            "repo_url": repo_url,
            **scan_result,
        },
    }


@app.post("/api/stripe-webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    # Verify signature if webhook secret is configured
    if STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        except (ValueError, stripe.SignatureVerificationError) as e:
            logger.error("Webhook signature verification failed: %s", e)
            raise HTTPException(400, "Invalid signature")
    else:
        # No webhook secret configured — parse raw payload
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            raise HTTPException(400, "Invalid JSON")
        logger.warning("Webhook received without signature verification (STRIPE_WEBHOOK_SECRET not set)")

    event_type = event.get("type", "")
    data = event.get("data", {}).get("object", {})

    logger.info("Stripe webhook: %s", event_type)

    if event_type == "checkout.session.completed":
        customer_id = data.get("customer", "")
        subscription_id = data.get("subscription", "")
        payment_intent_id = data.get("payment_intent", "")
        customer_email = data.get("customer_email", "") or data.get("customer_details", {}).get("email", "")
        mode = data.get("mode", "")

        # Generate API key for both subscription and one-time payment modes
        ref_id = subscription_id or payment_intent_id or "unknown"
        if customer_id or customer_email:
            api_key = create_api_key(customer_id, ref_id, customer_email)
            logger.info("NEW PRO CUSTOMER: %s → key created (mode=%s, ref=%s)", customer_email, mode, ref_id)

            # Send API key via email (best effort)
            try:
                _send_welcome_email(customer_email, api_key)
            except Exception as e:
                logger.error("Failed to send welcome email: %s", e)
        else:
            logger.warning("checkout.session.completed with no customer/email — skipping key creation")

    elif event_type == "customer.subscription.deleted":
        subscription_id = data.get("id", "")
        deactivate_key_by_subscription(subscription_id)
        logger.info("Subscription %s canceled → key deactivated", subscription_id)

    elif event_type == "customer.subscription.updated":
        subscription_id = data.get("id", "")
        status = data.get("status", "")
        if status in ("canceled", "unpaid", "past_due"):
            deactivate_key_by_subscription(subscription_id)
            logger.info("Subscription %s status=%s → key deactivated", subscription_id, status)

    elif event_type == "invoice.payment_failed":
        subscription_id = data.get("subscription", "")
        if subscription_id:
            logger.warning("Payment failed for subscription %s", subscription_id)

    return {"received": True}


def _send_welcome_email(email: str, api_key: str):
    """Send welcome email with API key via SMTP OVH. Best effort."""
    if not email:
        return

    import smtplib
    import ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.utils import formatdate, make_msgid

    subject = "Your MCP EU AI Act Pro API Key"
    body_text = f"""Welcome to MCP EU AI Act Pro!

Your API key: {api_key}

Quick start:
  curl -X POST https://arkforge.fr/api/v1/scan \\
    -H "X-Api-Key: {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{"project_path": "/path/to/your/project"}}'

Dashboard: https://arkforge.fr/api/dashboard?key={api_key}
Docs: https://arkforge.fr/pricing

Support: contact@arkforge.fr
"""
    try:
        # Load SMTP config from settings.env
        config = {}
        settings_path = SETTINGS_ENV
        if settings_path.exists():
            for line in settings_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()

        smtp_host = config.get("SMTP_HOST", "ssl0.ovh.net")
        smtp_port = int(config.get("SMTP_PORT", "465"))
        smtp_user = config.get("IMAP_USER", "contact@arkforge.fr")
        smtp_pass = config.get("IMAP_PASSWORD", "")

        if not smtp_pass:
            logger.warning("Welcome email skipped: SMTP password not configured")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"ArkForge <{smtp_user}>"
        msg["To"] = email
        msg["Reply-To"] = smtp_user
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain="arkforge.fr")
        msg["List-Unsubscribe"] = f"<mailto:{smtp_user}?subject=unsubscribe>"
        msg.attach(MIMEText(body_text, "plain", "utf-8"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=15) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, email, msg.as_string())

        logger.info("Welcome email sent via SMTP to %s", email)
    except Exception as e:
        logger.warning("Could not send welcome email via SMTP: %s", e)


def _send_proof_email(email: str, payment_proof: dict, scan_result: dict, repo_url: str):
    """Send transaction proof email to client after paid scan. Best effort."""
    if not email:
        return

    import smtplib
    import ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.utils import formatdate, make_msgid

    ts = datetime.now(timezone.utc).isoformat()
    frameworks = list(scan_result.get("detected_models", {}).keys())
    report = scan_result.get("report", {})
    risk_score = report.get("risk_score", scan_result.get("risk_score", "N/A"))
    files_scanned = scan_result.get("scan", {}).get("files_scanned", scan_result.get("files_scanned", 0))

    body = f"""EU AI ACT COMPLIANCE SCAN — PROOF OF TRANSACTION
{'=' * 55}

Timestamp:  {ts}
Repository: {repo_url}

PAYMENT PROOF
  Payment Intent: {payment_proof.get('payment_intent_id', 'N/A')}
  Amount:         {payment_proof.get('amount_eur', 0.50)} EUR
  Status:         {payment_proof.get('status', 'N/A')}
  Receipt:        {payment_proof.get('receipt_url', 'N/A')}

SCAN RESULT
  Risk Score:     {risk_score}
  Frameworks:     {', '.join(frameworks) if frameworks else 'none detected'}
  Files scanned:  {files_scanned}

{'=' * 55}
This is an automated proof of an agent-to-agent transaction.
Service: ArkForge MCP EU AI Act (https://arkforge.fr)

TRANSPARENCY: This scan was executed via the ArkForge paid API.
Both the scanning service and the agent client are open-source.
"""

    try:
        config = {}
        if SETTINGS_ENV.exists():
            for line in SETTINGS_ENV.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()

        smtp_host = config.get("SMTP_HOST", "ssl0.ovh.net")
        smtp_port = int(config.get("SMTP_PORT", "465"))
        smtp_user = config.get("IMAP_USER", "contact@arkforge.fr")
        smtp_pass = config.get("IMAP_PASSWORD", "")

        if not smtp_pass:
            logger.warning("Proof email skipped: SMTP not configured")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[PROOF] EU AI Act Scan — {repo_url.split('/')[-1] if '/' in repo_url else repo_url}"
        msg["From"] = f"ArkForge <{smtp_user}>"
        msg["To"] = email
        msg["Reply-To"] = smtp_user
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain="arkforge.fr")
        msg.attach(MIMEText(body, "plain", "utf-8"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=15) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, email, msg.as_string())

        logger.info("Proof email sent to %s for %s", email, repo_url)
    except Exception as e:
        logger.warning("Could not send proof email: %s", e)


# --- Dashboard ---

@app.get("/api/dashboard")
async def dashboard(request: Request, key: Optional[str] = None, format: Optional[str] = None):
    """Dashboard for Pro users. Returns HTML by default, JSON with ?format=json."""
    if not key:
        raise HTTPException(401, "API key required. Add ?key=your_api_key")

    key_info = validate_api_key(key)
    if not key_info:
        raise HTTPException(401, "Invalid or inactive API key")

    # Get scan history for this key
    history = _load_json(SCAN_HISTORY_FILE, [])
    key_prefix = key[:12] + "..."
    my_scans = [s for s in history if s.get("api_key") == key_prefix]

    # Aggregate stats
    frameworks_seen = {}
    for scan in my_scans:
        for fw in scan.get("frameworks_detected", []):
            frameworks_seen[fw] = frameworks_seen.get(fw, 0) + 1

    data = {
        "plan": "pro",
        "email": key_info.get("email", ""),
        "created_at": key_info.get("created_at", ""),
        "scans_total": key_info.get("scans_total", 0),
        "last_scan": key_info.get("last_scan"),
        "recent_scans": my_scans[-20:],
        "frameworks_detected": frameworks_seen,
        "api_key_prefix": key_prefix,
    }

    if format == "json":
        return data

    # Build HTML dashboard
    scans_rows = ""
    for s in reversed(my_scans[-20:]):
        fws = ", ".join(s.get("frameworks_detected", [])) or "-"
        scans_rows += f"<tr><td>{s.get('timestamp', '')[:19]}</td><td>{s.get('scan_type', '')}</td><td>{fws}</td><td>{s.get('files_scanned', 0)}</td></tr>"

    fw_items = ""
    for fw, count in sorted(frameworks_seen.items(), key=lambda x: -x[1]):
        fw_items += f"<li><strong>{fw}</strong>: {count} detection(s)</li>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP EU AI Act Pro - Dashboard</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f9fafb;color:#1a1a1a}}
.header{{background:linear-gradient(135deg,#6366f1,#4f46e5);color:#fff;padding:2rem;text-align:center}}
.header h1{{margin:0 0 .5rem;font-size:1.8rem}}
.header p{{opacity:.85;margin:0}}
.container{{max-width:900px;margin:0 auto;padding:2rem}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:2rem}}
.stat-card{{background:#fff;border-radius:.75rem;padding:1.5rem;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
.stat-value{{font-size:2rem;font-weight:800;color:#6366f1}}
.stat-label{{color:#666;font-size:.9rem}}
.section{{background:#fff;border-radius:.75rem;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
.section h2{{margin:0 0 1rem;font-size:1.3rem;color:#333}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:.6rem .8rem;text-align:left;border-bottom:1px solid #f0f0f0;font-size:.9rem}}
th{{background:#f8f9fa;font-weight:600;color:#555}}
ul{{list-style:none;padding:0}}
li{{padding:.4rem 0;color:#555}}
.key-display{{background:#f3f4f6;padding:.5rem 1rem;border-radius:.4rem;font-family:monospace;font-size:.85rem;display:inline-block}}
.footer{{text-align:center;padding:2rem;color:#999;font-size:.85rem}}
</style>
</head>
<body>
<div class="header">
<h1>MCP EU AI Act Pro</h1>
<p>Dashboard &mdash; {key_info.get('email','')}</p>
</div>
<div class="container">
<div class="stats">
<div class="stat-card"><div class="stat-value">{key_info.get('scans_total',0)}</div><div class="stat-label">Total Scans</div></div>
<div class="stat-card"><div class="stat-value">{len(frameworks_seen)}</div><div class="stat-label">Frameworks Detected</div></div>
<div class="stat-card"><div class="stat-value">{len(my_scans)}</div><div class="stat-label">Recent Scans (logged)</div></div>
</div>

<div class="section">
<h2>Your API Key</h2>
<p class="key-display">{key_prefix}</p>
<p style="color:#888;font-size:.85rem;margin-top:.5rem;">Full key was sent to your email. Use header: <code>X-Api-Key: your_key</code></p>
</div>

<div class="section">
<h2>Frameworks Detected</h2>
{f'<ul>{fw_items}</ul>' if fw_items else '<p style="color:#888">No frameworks detected yet. Run your first scan!</p>'}
</div>

<div class="section">
<h2>Recent Scans</h2>
{f'<table><thead><tr><th>Date</th><th>Type</th><th>Frameworks</th><th>Files</th></tr></thead><tbody>{scans_rows}</tbody></table>' if scans_rows else '<p style="color:#888">No scans yet. Use the API to start scanning.</p>'}
</div>

<div class="section">
<h2>Quick Start</h2>
<pre style="background:#1e293b;color:#e2e8f0;padding:1rem;border-radius:.5rem;overflow-x:auto;font-size:.85rem">curl -X POST https://arkforge.fr/api/v1/scan \\
  -H "X-Api-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{{"project_path": "/path/to/your/project"}}'</pre>
</div>
</div>
<div class="footer">MCP EU AI Act Pro &mdash; <a href="mailto:contact@arkforge.fr" style="color:#6366f1">contact@arkforge.fr</a> &mdash; <a href="https://arkforge.fr/fr/mcp-eu-ai-act.html" style="color:#6366f1">Back to site</a></div>
</body></html>"""

    return HTMLResponse(html)


# --- Pricing info ---

@app.get("/api/pricing")
async def pricing():
    return {
        "plans": {
            "free": {
                "price": "0€",
                "scans_per_day": FREE_TIER_LIMIT,
                "features": [
                    "10 scans/day",
                    "Full compliance reports",
                    "16 AI frameworks detected",
                    "MCP protocol access",
                ],
            },
            "pro": {
                "price": f"{PRO_PRICE_EUR}€/month",
                "scans_per_day": "unlimited",
                "features": [
                    "Unlimited scans",
                    "REST API for CI/CD pipelines",
                    "API key authentication",
                    "Dashboard with scan history",
                    "Priority support",
                    "16 AI frameworks detected",
                ],
            },
        },
        "checkout_url": "https://arkforge.fr/api/create-checkout",
        "contact": "contact@arkforge.fr",
    }


# --- Health check ---

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "mcp-eu-ai-act-paywall", "timestamp": datetime.now(timezone.utc).isoformat()}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8091, log_level="info")
