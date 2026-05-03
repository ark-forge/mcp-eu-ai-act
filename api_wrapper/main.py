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
import hmac
import hashlib
import base64
import urllib.parse
import urllib.request
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# --- Vault loader (graceful fallback to env vars) ---
def _load_stripe_config() -> dict:
    """Load Stripe config from vault, falling back to environment variables."""
    try:
        _vault_parent = str(Path(__file__).resolve().parent.parent.parent.parent.parent)
        if _vault_parent not in sys.path:
            sys.path.insert(0, _vault_parent)
        from automation.vault import vault
        s = vault.get_section('stripe') or {}
        mode = s.get('mode', 'live')
        return {
            'secret_key': s.get('live_secret_key') if mode == 'live' else s.get('test_secret_key'),
            'webhook_secret': s.get('mcp_webhook_secret') if mode == 'live' else s.get('webhook_secret_test'),
            'price_pro': s.get('mcp_pro_price_id'),
            'price_certified': s.get('mcp_certified_price_id'),
        }
    except Exception:
        # Fallback to environment variables
        return {
            'secret_key': os.environ.get('STRIPE_SECRET_KEY'),
            'webhook_secret': os.environ.get('STRIPE_WEBHOOK_SECRET'),
            'price_pro': os.environ.get('STRIPE_PRICE_PRO'),
            'price_certified': os.environ.get('STRIPE_PRICE_CERTIFIED'),
        }

_STRIPE = _load_stripe_config()

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

# Add parent dir to path so we can import server.py
_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from server import EUAIActChecker, RISK_CATEGORIES, ACTIONABLE_GUIDANCE, _api_key_manager

logger = logging.getLogger(__name__)

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
        "Powered by ArkForge — https://mcp.arkforge.tech"
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


@app.post("/api/register")
async def api_register(request: Request):
    """Register for a free API key. Accepts {"email": "...", "source": "cli"}."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "Invalid JSON body. Expected: {\"email\": \"user@example.com\"}"})

    email = (body.get("email") or "").strip()
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail={"error": "Valid email required"})

    plan = body.get("plan", "free")
    if plan not in ("free", "pro"):
        plan = "free"

    result = _api_key_manager.register_key(email, plan)

    reg_ip = _get_client_ip(request)
    source = body.get("source", "api_direct")
    reg_log = _DATA_DIR / "registration_log.jsonl"
    try:
        with open(reg_log, "a") as f:
            f.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "email": email, "plan": plan, "source": source,
                "ip": reg_ip, "key": result.get("key", ""),
            }) + "\n")
    except Exception:
        pass

    return {"key": result.get("key", ""), "email": email, "plan": plan}


@app.post("/api/cli-ping")
async def cli_ping(request: Request):
    """Anonymous CLI usage telemetry. No PII. Fail-silent."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    ping_path = _DATA_DIR / "cli_pings.jsonl"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "ip": _get_client_ip(request),
        "v": body.get("v", "?"),
        "fw": body.get("fw", 0),
        "fw_names": body.get("fw_names", []),
        "files": body.get("files", 0),
        "risk": body.get("risk", "?"),
        "pct": body.get("pct", 0),
        "py": body.get("py", "?"),
        "os": body.get("os", "?"),
    }
    try:
        with open(ping_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    return {"ok": True}


@app.post("/api/checkout")
async def checkout(request: Request):
    """Create a Stripe Checkout Session for pro or certified plan."""
    stripe_secret = _STRIPE.get('secret_key')
    if not stripe_secret:
        raise HTTPException(status_code=503, detail={"error": "Stripe not configured"})

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "Invalid JSON body"})

    plan = body.get("plan", "")
    email = body.get("email", "")

    if plan not in ("pro", "certified"):
        raise HTTPException(
            status_code=400,
            detail={"error": f"Invalid plan '{plan}'. Must be 'pro' or 'certified'"},
        )

    if plan == "pro":
        price_id = _STRIPE.get('price_pro', '')
    else:
        price_id = _STRIPE.get('price_certified', '')

    if not price_id:
        raise HTTPException(
            status_code=503,
            detail={"error": f"Stripe price not configured for plan '{plan}'"},
        )

    params = {
        "payment_method_types[0]": "card",
        "mode": "subscription",
        "success_url": "https://arkforge.tech/en/scanner-pro-success.html",
        "cancel_url": "https://arkforge.tech/en/scanner-pro.html?checkout=cancelled",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "subscription_data[trial_period_days]": "14",
        "metadata[plan]": plan,
        "metadata[email]": email,
    }
    if email:
        params["customer_email"] = email

    encoded = urllib.parse.urlencode(params).encode("utf-8")
    credentials = base64.b64encode(f"{stripe_secret}:".encode()).decode()
    req = urllib.request.Request(
        "https://api.stripe.com/v1/checkout/sessions",
        data=encoded,
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            session = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        logger.error("Stripe API error %s: %s", e.code, error_body)
        try:
            stripe_err = json.loads(error_body)
            detail = stripe_err.get("error", {}).get("message", "Stripe error")
        except Exception:
            detail = "Stripe API error"
        raise HTTPException(status_code=502, detail={"error": detail})
    except Exception as e:
        logger.error("Stripe request failed: %s", e)
        raise HTTPException(status_code=502, detail={"error": "Failed to reach Stripe"})

    logger.info("Stripe checkout session created: %s plan=%s email=%s", session.get("id"), plan, email)
    return {"checkout_url": session.get("url"), "session_id": session.get("id")}


@app.post("/api/webhook")
async def webhook(request: Request):
    """Handle Stripe webhook events."""
    webhook_secret = _STRIPE.get('webhook_secret')
    if not webhook_secret:
        raise HTTPException(status_code=503, detail={"error": "Stripe webhook not configured"})

    raw_body = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    # Parse timestamp and v1 signature from Stripe-Signature header
    # Format: t=timestamp,v1=signature[,v1=signature...]
    ts = None
    v1_sig = None
    for part in sig_header.split(","):
        part = part.strip()
        if part.startswith("t="):
            ts = part[2:]
        elif part.startswith("v1="):
            v1_sig = part[3:]

    if not ts or not v1_sig:
        raise HTTPException(status_code=400, detail={"error": "Invalid signature header"})

    # Compute expected signature
    signed_payload = f"{ts}.{raw_body.decode('utf-8')}"
    expected = hmac.new(
        webhook_secret.encode("utf-8"),
        signed_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, v1_sig):
        raise HTTPException(status_code=400, detail={"error": "Invalid signature"})

    try:
        event = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail={"error": "Invalid JSON payload"})

    event_type = event.get("type", "")
    logger.info("Stripe webhook received: %s", event_type)

    if event_type == "checkout.session.completed":
        obj = event.get("data", {}).get("object", {})
        email = obj.get("customer_email") or obj.get("customer_details", {}).get("email", "") or obj.get("metadata", {}).get("email", "")
        plan = obj.get("metadata", {}).get("plan", "pro")
        if email:
            entry = _api_key_manager.register_key(email, plan)
            logger.info(
                "Stripe checkout completed — registered key %s for %s plan=%s",
                entry.get("key"),
                email,
                plan,
            )
        else:
            logger.warning("Stripe checkout.session.completed: no email found in event")

    elif event_type == "customer.subscription.deleted":
        obj = event.get("data", {}).get("object", {})
        customer_id = obj.get("customer", "unknown")
        logger.info("Stripe subscription deleted for customer: %s", customer_id)

    return {"received": True}


# ---------------------------------------------------------------------------
# OAuth 2.1 PKCE — minimal implementation for claude.ai web connector
#
# Flow: POST /register → GET /oauth/authorize → POST /oauth/token
# Tokens are free-tier bearer tokens stored in memory (TTL 24h).
# Paid users can pass their ak_... key directly as Bearer token in MCP.
# ---------------------------------------------------------------------------

import secrets
import hashlib as _hashlib
import base64 as _base64
from urllib.parse import urlparse as _urlparse, urlencode as _urlencode

# In-memory stores (survive process restart via json flush, but memory is fine for OAuth codes)
_oauth_codes: dict = {}   # code → {client_id, redirect_uri, code_challenge, expires_at}
_oauth_tokens: dict = {}  # token → {plan, expires_at}

_OAUTH_CODE_TTL = 60        # seconds
_OAUTH_TOKEN_TTL = 86400    # 24h


def _oauth_token_for_key(api_key: str) -> str:
    """Return a stable bearer token for an existing API key (paid users)."""
    return f"bearer_{api_key}"


@app.post("/register")
async def oauth_register(request: Request):
    """RFC 7591 dynamic client registration — returns a public client_id."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    # Any client is accepted — we issue a static public client_id
    client_id = body.get("client_id") or f"mcpclient_{secrets.token_hex(8)}"
    return {
        "client_id": client_id,
        "client_secret_expires_at": 0,
        "redirect_uris": body.get("redirect_uris", []),
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }


_AUTHORIZE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect to ArkForge MCP</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Playfair+Display:wght@700&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d0d14;color:#e8e4d8;font-family:'IBM Plex Mono',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem}}
  .card{{background:#13131f;border:1px solid #2a2a40;border-radius:12px;padding:2.5rem;max-width:420px;width:100%}}
  h1{{font-family:'Playfair Display',serif;font-size:1.6rem;color:#e8e4d8;margin-bottom:.4rem}}
  .sub{{color:#6b6b88;font-size:.78rem;margin-bottom:2rem;line-height:1.5}}
  label{{display:block;font-size:.72rem;color:#9d7c2e;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.5rem}}
  input{{width:100%;background:#0d0d14;border:1px solid #2a2a40;border-radius:6px;padding:.75rem 1rem;color:#e8e4d8;font-family:'IBM Plex Mono',monospace;font-size:.85rem;outline:none;transition:border-color .2s}}
  input:focus{{border-color:#9d7c2e}}
  input::placeholder{{color:#3a3a55}}
  .hint{{font-size:.72rem;color:#6b6b88;margin-top:.5rem;line-height:1.4}}
  .hint a{{color:#9d7c2e;text-decoration:none}}
  .btn{{width:100%;margin-top:1.5rem;padding:.9rem;background:#1a3a8f;border:none;border-radius:6px;color:#e8e4d8;font-family:'IBM Plex Mono',monospace;font-size:.85rem;font-weight:500;cursor:pointer;transition:background .2s;letter-spacing:.04em}}
  .btn:hover{{background:#2348b8}}
  .plan-badge{{display:inline-block;margin-top:1rem;padding:.3rem .7rem;border-radius:4px;font-size:.7rem;letter-spacing:.06em;text-transform:uppercase}}
  .free{{background:#1a1a2e;border:1px solid #2a2a40;color:#6b6b88}}
  .paid{{background:#1a2a1a;border:1px solid #2a402a;color:#4a9a4a}}
  .error{{color:#c41a1a;font-size:.78rem;margin-top:.75rem;padding:.5rem .75rem;background:#1a0a0a;border:1px solid #3a1a1a;border-radius:4px}}
</style>
</head>
<body>
<div class="card">
  <h1>ArkForge MCP</h1>
  <p class="sub">EU AI Act Compliance Scanner — connecting to claude.ai</p>
  <form method="post" action="/oauth/authorize">
    <input type="hidden" name="response_type" value="{response_type}">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
    <input type="hidden" name="scope" value="{scope}">
    <label for="api_key">API Key <span style="color:#6b6b88;font-weight:400;text-transform:none">(optional — leave blank for free tier)</span></label>
    <input type="text" id="api_key" name="api_key" placeholder="ak_..." autocomplete="off" spellcheck="false">
    <p class="hint">No key? <a href="https://arkforge.tech/en/pricing.html?utm_source=mcp_oauth&utm_medium=web" target="_blank">Get one here</a> for unlimited scans + roadmap + Annex IV.</p>
    {error_block}
    <button type="submit" class="btn">Connect &rarr;</button>
  </form>
</div>
</body>
</html>"""


@app.get("/oauth/authorize")
async def oauth_authorize_get(
    request: Request,
    response_type: str = "code",
    client_id: str = "",
    redirect_uri: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    scope: str = "mcp",
):
    """Show API key entry form before issuing OAuth code."""
    from fastapi.responses import HTMLResponse

    if not redirect_uri:
        raise HTTPException(status_code=400, detail={"error": "missing redirect_uri"})

    parsed = _urlparse(redirect_uri)
    if parsed.scheme not in ("https", "http") or (
        parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1")
    ):
        raise HTTPException(status_code=400, detail={"error": "invalid redirect_uri scheme"})

    html = _AUTHORIZE_HTML.format(
        response_type=response_type, client_id=client_id, redirect_uri=redirect_uri,
        state=state, code_challenge=code_challenge,
        code_challenge_method=code_challenge_method, scope=scope, error_block="",
    )
    return HTMLResponse(html)


@app.post("/oauth/authorize")
async def oauth_authorize_post(request: Request):
    """Process API key form submission — issue OAuth code."""
    from fastapi.responses import RedirectResponse, HTMLResponse

    body = dict(await request.form())
    redirect_uri = body.get("redirect_uri", "")
    api_key = (body.get("api_key") or "").strip()

    if not redirect_uri:
        raise HTTPException(status_code=400, detail={"error": "missing redirect_uri"})

    # Validate API key if provided
    plan = "free"
    error_block = ""
    if api_key:
        info = _api_key_manager.verify(api_key)
        if not info:
            error_block = '<p class="error">Invalid API key. Leave blank for free tier or <a href="https://arkforge.tech/en/pricing.html?utm_source=mcp_oauth&utm_medium=web" style="color:#c41a1a" target="_blank">get a valid key</a>.</p>'
            html = _AUTHORIZE_HTML.format(
                response_type=body.get("response_type", "code"),
                client_id=body.get("client_id", ""),
                redirect_uri=redirect_uri,
                state=body.get("state", ""),
                code_challenge=body.get("code_challenge", ""),
                code_challenge_method=body.get("code_challenge_method", "S256"),
                scope=body.get("scope", "mcp"),
                error_block=error_block,
            )
            return HTMLResponse(html, status_code=400)
        plan = info.get("plan", "free")

    code = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc).timestamp() + _OAUTH_CODE_TTL
    _oauth_codes[code] = {
        "client_id": body.get("client_id", ""),
        "redirect_uri": redirect_uri,
        "code_challenge": body.get("code_challenge", ""),
        "code_challenge_method": body.get("code_challenge_method", "S256"),
        "expires_at": expires,
        "plan": plan,
        "api_key": api_key if api_key and plan != "free" else None,
    }

    params = {"code": code}
    if body.get("state"):
        params["state"] = body["state"]
    return RedirectResponse(f"{redirect_uri}?{_urlencode(params)}", status_code=302)


@app.post("/oauth/token")
async def oauth_token(request: Request):
    """Token endpoint — exchanges authorization code for a free-tier bearer token."""
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type:
        body = dict(await request.form())
    else:
        try:
            body = await request.json()
        except Exception:
            body = {}

    grant_type = body.get("grant_type", "")
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail={"error": "unsupported_grant_type"})

    code = body.get("code", "")
    code_verifier = body.get("code_verifier", "")
    redirect_uri = body.get("redirect_uri", "")

    entry = _oauth_codes.pop(code, None)
    if not entry:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Code not found or expired"})

    now = datetime.now(timezone.utc).timestamp()
    if now > entry["expires_at"]:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Code expired"})

    # Verify PKCE S256
    if entry.get("code_challenge") and code_verifier:
        digest = _hashlib.sha256(code_verifier.encode()).digest()
        expected = _base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if not hmac.compare_digest(expected, entry["code_challenge"]):
            raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "PKCE verification failed"})

    plan = entry.get("plan", "free")
    api_key = entry.get("api_key")

    if api_key and plan != "free":
        # Paid user — token IS the API key, validated at MCP layer
        token = api_key
    else:
        # Free tier — issue a scoped OAuth token
        token = f"ak_oauth_{secrets.token_hex(16)}"
        _oauth_tokens[token] = {
            "plan": "free",
            "expires_at": now + _OAUTH_TOKEN_TTL,
        }

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": _OAUTH_TOKEN_TTL,
        "scope": "mcp",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
