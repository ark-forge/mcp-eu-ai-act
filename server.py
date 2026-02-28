#!/usr/bin/env python3
"""
MCP Server: EU AI Act Compliance Checker
Scans projects to detect AI model usage and verify EU AI Act compliance
"""

import os
import re
import json
import time
import secrets
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from enum import Enum

from mcp.server.fastmcp import FastMCP
from gdpr_module import GDPRChecker, GDPR_TEMPLATES, GDPR_REQUIREMENTS

logger = logging.getLogger(__name__)

# --- API Key Management (Paywall Step 2) ---
API_KEYS_PATH = Path(__file__).parent / "api_keys.json"
API_KEYS_DATA_PATH = Path(__file__).parent / "data" / "api_keys.json"


class ApiKeyManager:
    """Loads and validates API keys from both api_keys.json files.
    Supports two formats:
    - Root api_keys.json: {"keys": [{"key": "...", "email": "...", ...}]}
    - data/api_keys.json: {"mcp_pro_...": {"email": "...", "active": true, ...}}
    """

    def __init__(self, path: Path = API_KEYS_PATH, data_path: Path = API_KEYS_DATA_PATH):
        self._path = path
        self._data_path = data_path
        self._keys: Dict[str, Dict] = {}
        self._loaded_at: float = 0
        self._reload()

    def _reload(self):
        """Reload keys from both files (cached for 60s)."""
        merged: Dict[str, Dict] = {}
        for path in [self._path, self._data_path]:
            try:
                data = json.loads(path.read_text())
                # List format: {"keys": [{"key": "...", ...}]}
                for entry in data.get("keys", []):
                    merged[entry["key"]] = entry
                # Dict format: {"api_key_value": {"tier": "pro", ...}}
                for api_key, info in data.items():
                    if api_key == "keys":
                        continue
                    if isinstance(info, dict):
                        info["key"] = api_key
                        merged[api_key] = info
            except (FileNotFoundError, json.JSONDecodeError, KeyError):
                pass
        self._keys = merged
        self._loaded_at = time.time()

    def verify(self, key: str) -> Optional[Dict]:
        """Verify an API key. Returns key info if valid+active, None otherwise.
        Reloads from disk every 60s to pick up new keys without restart."""
        if time.time() - self._loaded_at > 60:
            self._reload()
        entry = self._keys.get(key)
        if entry and entry.get("active"):
            plan = entry.get("plan", entry.get("tier", "pro"))
            return {"email": entry.get("email", ""), "plan": plan}
        return None

    def get_entry(self, key: str) -> Dict:
        """Get the full entry for an API key (for usage stats)."""
        if time.time() - self._loaded_at > 60:
            self._reload()
        return self._keys.get(key, {})

    def increment_scans(self, key: str):
        """Increment scans_total for an API key and persist to data file."""
        if time.time() - self._loaded_at > 60:
            self._reload()
        entry = self._keys.get(key)
        if not entry:
            return
        entry["scans_total"] = entry.get("scans_total", 0) + 1
        entry["last_scan"] = datetime.now(timezone.utc).isoformat()
        # Persist to data file (canonical source for paywall_api.py compatibility)
        try:
            data = json.loads(self._data_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        if key in data:
            data[key]["scans_total"] = entry["scans_total"]
            data[key]["last_scan"] = entry["last_scan"]
            self._data_path.parent.mkdir(parents=True, exist_ok=True)
            self._data_path.write_text(json.dumps(data, indent=2))

    def register_key(self, email: str, plan: str = "free") -> Dict:
        """Register a new API key. Writes to data/api_keys.json.
        Returns the created entry with the generated key."""
        api_key = f"ak_{secrets.token_hex(20)}"
        entry = {
            "plan": plan,
            "active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "email": email,
            "scans_total": 0,
        }
        # Load existing data file, add new key, write back
        data = {}
        try:
            data = json.loads(self._data_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        data[api_key] = entry
        self._data_path.parent.mkdir(parents=True, exist_ok=True)
        self._data_path.write_text(json.dumps(data, indent=2))
        # Refresh in-memory cache
        self._reload()
        return {"key": api_key, **entry}


_api_key_manager = ApiKeyManager()


# --- Rate Limiting (Paywall Step 1) ---
FREE_TIER_DAILY_LIMIT = 10


class RateLimiter:
    """IP rate limiter with file persistence. 10 requests per calendar day (UTC) per IP.
    Counters survive server restarts via JSON file. Resets automatically when the UTC date changes."""

    # Shared with paywall_api.py so free-tier limits are enforced across both MCP and REST
    _PERSIST_PATH = Path(__file__).parent / "data" / "rate_limits.json"

    def __init__(self, max_requests: int = FREE_TIER_DAILY_LIMIT):
        self.max_requests = max_requests
        self._clients: Dict[str, Dict] = {}  # {ip: {"count": int, "date": str}}
        self._last_cleanup: float = time.time()
        self._load()

    def _load(self):
        """Load persisted rate limits from disk."""
        try:
            if self._PERSIST_PATH.exists():
                data = json.loads(self._PERSIST_PATH.read_text())
                today = self._today()
                self._clients = {ip: e for ip, e in data.items() if e.get("date") == today}
        except (json.JSONDecodeError, OSError):
            self._clients = {}

    def _save(self):
        """Persist current rate limits to disk (atomic write)."""
        try:
            self._PERSIST_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._PERSIST_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._clients))
            tmp.rename(self._PERSIST_PATH)
        except OSError:
            pass

    @staticmethod
    def _today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def check(self, ip: str) -> tuple[bool, int]:
        """Check if IP is allowed. Returns (allowed, remaining)."""
        today = self._today()
        # Periodic cleanup every hour to prevent memory leak from expired entries
        now = time.time()
        if now - self._last_cleanup > 3600:
            self.cleanup()
            self._last_cleanup = now
        entry = self._clients.get(ip)
        if entry is None or entry["date"] != today:
            self._clients[ip] = {"count": 1, "date": today}
            self._save()
            return True, self.max_requests - 1
        if entry["count"] >= self.max_requests:
            return False, 0
        entry["count"] += 1
        self._save()
        return True, self.max_requests - entry["count"]

    def cleanup(self):
        """Remove expired entries (old dates) to prevent memory leak."""
        today = self._today()
        expired = [ip for ip, e in self._clients.items() if e["date"] != today]
        for ip in expired:
            del self._clients[ip]
        if expired:
            self._save()


_rate_limiter = RateLimiter()

# --- Scan history logging (shared with paywall_api.py) ---
_SCAN_HISTORY_PATH = Path(__file__).parent / "data" / "scan_history.json"


def _record_mcp_scan(api_key: Optional[str], ip: str, tool_name: str):
    """Record an MCP tool call to scan_history.json for visibility."""
    try:
        history = json.loads(_SCAN_HISTORY_PATH.read_text()) if _SCAN_HISTORY_PATH.exists() else []
    except (json.JSONDecodeError, OSError):
        history = []
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "api_key": api_key[:12] + "..." if api_key else None,
        "ip": ip,
        "plan": "pro" if api_key else "free",
        "scan_type": f"mcp_{tool_name}",
        "frameworks_detected": [],
        "files_scanned": 0,
    })
    if len(history) > 1000:
        history = history[-1000:]
    try:
        tmp = _SCAN_HISTORY_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(history, indent=2, default=str))
        tmp.rename(_SCAN_HISTORY_PATH)
    except OSError:
        pass


def _get_header(scope, name: bytes) -> Optional[str]:
    """Extract a header value from ASGI scope."""
    for header_name, header_val in scope.get("headers", []):
        if header_name == name:
            return header_val.decode()
    return None


def _extract_api_key(scope) -> Optional[str]:
    """Extract API key from X-API-Key header or Authorization: Bearer."""
    key = _get_header(scope, b"x-api-key")
    if key:
        return key
    auth = _get_header(scope, b"authorization")
    if auth and auth.startswith("Bearer "):
        return auth[7:]
    return None


class RateLimitMiddleware:
    """ASGI middleware: rate-limits MCP tools/call requests per client IP.
    Handles /api/verify-key endpoint. Pro API keys bypass rate limiting."""

    def __init__(self, app):
        self.app = app

    async def _json_response(self, send, status: int, body: dict, extra_headers: list = None):
        """Send a JSON HTTP response with optional extra headers."""
        resp = json.dumps(body).encode()
        headers = [
            [b"content-type", b"application/json"],
            [b"content-length", str(len(resp)).encode()],
        ]
        if extra_headers:
            headers.extend(extra_headers)
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        })
        await send({"type": "http.response.body", "body": resp})

    @staticmethod
    def _rate_limit_headers(remaining: int) -> list:
        """Build X-RateLimit-Remaining and X-RateLimit-Reset headers."""
        from datetime import timedelta
        now_dt = datetime.now(timezone.utc)
        midnight = (now_dt + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        reset = int((midnight - now_dt).total_seconds())
        return [
            [b"x-ratelimit-remaining", str(remaining).encode()],
            [b"x-ratelimit-reset", str(reset).encode()],
        ]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # --- /api/usage endpoint (GET) — free tier usage status ---
        if path == "/api/usage" and scope.get("method") == "GET":
            ip = _get_header(scope, b"x-real-ip")
            if not ip:
                xff = _get_header(scope, b"x-forwarded-for")
                if xff:
                    ip = xff.split(",")[-1].strip()
            if not ip:
                client = scope.get("client")
                ip = client[0] if client else "unknown"
            entry = _rate_limiter._clients.get(ip)
            today = _rate_limiter._today()
            if entry is None or entry["date"] != today:
                used, remaining, resets_in = 0, _rate_limiter.max_requests, 0
            else:
                used = entry["count"]
                remaining = max(0, _rate_limiter.max_requests - used)
                # Seconds until midnight UTC
                from datetime import timedelta
                now_dt = datetime.now(timezone.utc)
                midnight = (now_dt + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
                resets_in = int((midnight - now_dt).total_seconds())
            await self._json_response(send, 200, {
                "plan": "free",
                "daily_limit": _rate_limiter.max_requests,
                "used": used,
                "remaining": remaining,
                "resets_in_seconds": resets_in,
                "upgrade": FREE_TIER_BANNER,
            })
            return

        # --- /api/register endpoint (POST) — generate new API key ---
        if path == "/api/register" and scope.get("method") == "POST":
            body_parts = []
            while True:
                message = await receive()
                body_parts.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            body = b"".join(body_parts)
            try:
                data = json.loads(body)
                email = data.get("email", "").strip()
                plan = data.get("plan", "free")
            except (json.JSONDecodeError, ValueError, TypeError):
                await self._json_response(send, 400, {"error": "Invalid JSON body. Expected: {\"email\": \"user@example.com\"}"})
                return
            if not email or "@" not in email:
                await self._json_response(send, 400, {"error": "Valid email is required"})
                return
            if plan not in ("free", "pro"):
                await self._json_response(send, 400, {"error": "Plan must be 'free' or 'pro'"})
                return
            result = _api_key_manager.register_key(email, plan)
            await self._json_response(send, 201, result)
            return

        # --- /api/verify-key endpoint (POST) ---
        if path == "/api/verify-key" and scope.get("method") == "POST":
            body_parts = []
            while True:
                message = await receive()
                body_parts.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            body = b"".join(body_parts)
            try:
                data = json.loads(body)
                api_key = data.get("key", "")
            except (json.JSONDecodeError, ValueError, TypeError):
                await self._json_response(send, 400, {"valid": False, "error": "Invalid JSON body. Expected: {\"key\": \"your_api_key\"}"})
                return
            result = _api_key_manager.verify(api_key)
            if result:
                await self._json_response(send, 200, {"valid": True, "plan": result["plan"], "email": result["email"]})
            else:
                await self._json_response(send, 401, {"valid": False, "error": "Invalid or inactive API key"})
            return

        if scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        # Buffer request body
        body_parts = []
        while True:
            message = await receive()
            body_parts.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(body_parts)

        # Only rate-limit tools/call JSON-RPC requests
        is_tool_call = False
        request_id = None
        tool_name = None
        try:
            data = json.loads(body)
            if data.get("method") == "tools/call":
                is_tool_call = True
                request_id = data.get("id")
                tool_name = (data.get("params") or {}).get("name", "unknown")
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        if is_tool_call:
            # Extract IP early (needed for both pro and free logging)
            ip = _get_header(scope, b"x-real-ip")
            if not ip:
                xff = _get_header(scope, b"x-forwarded-for")
                if xff:
                    ip = xff.split(",")[-1].strip()
            if not ip:
                client = scope.get("client")
                ip = client[0] if client else "unknown"

            # Check API key — Pro keys bypass rate limiting
            api_key = _extract_api_key(scope)
            if api_key:
                key_info = _api_key_manager.verify(api_key)
                if key_info and key_info["plan"] == "pro":
                    # Track scan for Pro user
                    _api_key_manager.increment_scans(api_key)
                    _record_mcp_scan(api_key, ip, tool_name)
                    # Pro user: skip rate limiting, pass through
                    body_sent = False

                    async def receive_bypass():
                        nonlocal body_sent
                        if not body_sent:
                            body_sent = True
                            return {"type": "http.request", "body": body, "more_body": False}
                        return await receive()

                    await self.app(scope, receive_bypass, send)
                    return

            # Free tier: apply IP rate limiting
            allowed, remaining = _rate_limiter.check(ip)
            rl_headers = self._rate_limit_headers(remaining)
            if not allowed:
                await self._json_response(send, 429, {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "Free tier limit reached. Upgrade to Pro: https://mcp.arkforge.fr/fr/pricing.html?utm_source=pypi",
                    },
                    "id": request_id,
                }, extra_headers=rl_headers)
                return
            # Free tier scan allowed — log it
            _record_mcp_scan(None, ip, tool_name)

        # Replay buffered body to the app
        body_sent = False

        async def receive_replay():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        # Inject rate limit headers into successful free-tier tool call responses
        if is_tool_call:
            _rl_headers = rl_headers

            async def send_with_headers(message):
                if message.get("type") == "http.response.start":
                    message = dict(message)
                    message["headers"] = list(message.get("headers", [])) + _rl_headers
                await send(message)

            await self.app(scope, receive_replay, send_with_headers)
        else:
            await self.app(scope, receive_replay, send)


# Config/manifest files to scan for AI dependencies
CONFIG_FILE_NAMES = {
    "package.json", "package-lock.json",
    "requirements.txt", "requirements-dev.txt", "requirements_dev.txt",
    "setup.py", "setup.cfg", "pyproject.toml",
    "Pipfile", "Pipfile.lock",
    "environment.yml", "conda.yml",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "Cargo.toml", "go.mod",
}

# Patterns for detecting AI dependencies in config/manifest files
CONFIG_DEPENDENCY_PATTERNS = {
    "openai": [r'"openai"', r"\bopenai\s*[>=<~!]", r"\bopenai\s*$"],
    "anthropic": [r'"anthropic"', r"\banthropic\s*[>=<~!]", r"\banthropic\s*$", r'"@anthropic-ai/'],
    "huggingface": [r'"transformers"', r"\btransformers\s*[>=<~!]", r'"diffusers"', r"\bdiffusers\s*[>=<~!]", r'"accelerate"', r"\baccelerate\s*[>=<~!]", r'"smolagents"', r"\bsmolagents\s*[>=<~!]"],
    "tensorflow": [r'"tensorflow"', r"\btensorflow\s*[>=<~!]"],
    "pytorch": [r'"torch"', r"\btorch\s*[>=<~!]", r"\btorch\s*$", r'"torchvision"', r"\btorchvision\s*[>=<~!]", r'"torchaudio"'],
    "langchain": [r'"langchain"', r"\blangchain\s*[>=<~!]", r"\blangchain\s*$", r"\blangchain-core\b", r"\blangchain-community\b", r"\blangchain-openai\b", r"\blangchain-anthropic\b", r'"@langchain/'],
    "gemini": [r'"google-generativeai"', r"\bgoogle-generativeai\s*[>=<~!]", r'"google-genai"', r"\bgoogle-genai\s*[>=<~!]", r'"@google/generative-ai"'],
    "vertex_ai": [r'"google-cloud-aiplatform"', r"\bgoogle-cloud-aiplatform\s*[>=<~!]"],
    "mistral": [r'"mistralai"', r"\bmistralai\s*[>=<~!]", r'"@mistralai/'],
    "cohere": [r'"cohere"', r"\bcohere\s*[>=<~!]", r"\bcohere\s*$"],
    "aws_bedrock": [r'"amazon-bedrock"', r'"@aws-sdk/client-bedrock"', r"\bamazon-bedrock\s*[>=<~!]", r"\bamazon-bedrock\s*$"],
    "azure_openai": [r'"azure-ai-openai"', r'"@azure/openai"', r"\bazure-ai-openai\s*[>=<~!]", r"\bazure-ai-openai\s*$"],
    "ollama": [r'"ollama"', r"\bollama\s*[>=<~!]"],
    "llamaindex": [r'"llama-index"', r"\bllama-index\s*[>=<~!]", r"\bllama.index\s*[>=<~!]"],
    "replicate": [r'"replicate"', r"\breplicate\s*[>=<~!]"],
    "groq": [r'"groq"', r"\bgroq\s*[>=<~!]"],
}

# Patterns for detecting AI model usage in source code
# Last veille update: 2026-02-19 — 16 frameworks, enhanced patterns + false-positive reduction
AI_MODEL_PATTERNS = {
    "openai": [
        r"openai\.ChatCompletion",
        r"openai\.Completion",
        r"from openai import",
        r"import openai",
        r"gpt-3\.5",
        r"gpt-4",
        r"gpt-4o",
        r"gpt-4-turbo",
        r"text-davinci",
        r"\bo1-preview\b",
        r"\bo1-mini\b",
        r"\bo3\b",
        r"text-embedding-3",
    ],
    "anthropic": [
        r"from anthropic import",
        r"import anthropic",
        r"claude-",
        r"Anthropic\(\)",
        r"messages\.create",
        r"claude-opus",
        r"claude-sonnet",
        r"claude-haiku",
    ],
    "huggingface": [
        r"from transformers import",
        r"AutoModel",
        r"AutoTokenizer",
        r"transformers\.pipeline",
        r"huggingface_hub",
        r"from diffusers import",
        r"from accelerate import",
        r"from smolagents import",
    ],
    "tensorflow": [
        r"import tensorflow",
        r"from tensorflow import",
        r"tf\.keras",
        r"\.h5$",  # model files
    ],
    "pytorch": [
        r"import torch",
        r"from torch import",
        r"nn\.Module",
        r"\.pt$",  # model files
        r"\.pth$",
    ],
    "langchain": [
        r"from langchain import",
        r"import langchain",
        r"LLMChain",
        r"ChatOpenAI",
        r"from langchain_core import",
        r"from langchain_community import",
        r"from langchain_openai import",
        r"from langchain_anthropic import",
    ],
    "gemini": [
        r"from google import genai",
        r"from google\.genai import",
        r"import google\.generativeai",
        r"from google\.generativeai import",
        r"GenerativeModel",
        r"gemini-pro",
        r"gemini-ultra",
        r"gemini-1\.5",
        r"gemini-2",
        r"gemini-3",
        r"gemini-flash",
    ],
    "vertex_ai": [
        r"from vertexai import",
        r"import vertexai",
        r"vertexai\.generative_models",
        r"google\.cloud\.aiplatform",
        r"from vertexai\.generative_models import",
    ],
    "mistral": [
        r"from mistralai import",
        r"import mistralai",
        r"from mistralai\.client import",
        r"Mistral\(",
        r"mistral-large",
        r"mistral-medium",
        r"mistral-small",
        r"mistral-nemo",
        r"magistral",
        r"codestral",
        r"mixtral",
    ],
    "cohere": [
        r"from cohere import",
        r"import cohere",
        r"cohere\.Client",
        r"cohere\.ClientV2",
        r"command-r",
        r"command-r-plus",
        r"embed-english",
        r"embed-multilingual",
        r"CohereClient",
    ],
    "aws_bedrock": [
        r"bedrock-runtime",
        r"bedrock-agent-runtime",
        r"BedrockRuntime",
        r"invoke_model",
        r"\.converse\(\s*modelId",
        r"from boto3.*bedrock",
        r"anthropic\.bedrock",
    ],
    "azure_openai": [
        r"AzureOpenAI",
        r"azure\.ai\.openai",
        r"azure_endpoint\s*=",
        r"AZURE_OPENAI",
        r"from openai import AzureOpenAI",
    ],
    "ollama": [
        r"import ollama",
        r"from ollama import",
        r"ollama\.chat",
        r"ollama\.generate",
        r"ollama\.Client",
    ],
    "llamaindex": [
        r"from llama_index import",
        r"import llama_index",
        r"from llama_index\.core import",
        r"from llama_index\.llms import",
        r"from llamaindex import",
        r"VectorStoreIndex",
        r"SimpleDirectoryReader",
        r"LlamaIndex",
    ],
    "replicate": [
        r"import replicate",
        r"from replicate import",
        r"replicate\.run",
        r"replicate\.models",
        r"replicate\.Client",
    ],
    "groq": [
        r"from groq import",
        r"import groq",
        r"groq\.Groq",
        r"Groq\(\)",
    ],
}

# EU AI Act - Risk categories
RISK_CATEGORIES = {
    "unacceptable": {
        "description": "Prohibited systems (behavioral manipulation, social scoring, mass biometric surveillance)",
        "requirements": ["Prohibited system - Do not deploy"],
    },
    "high": {
        "description": "High-risk systems (recruitment, credit scoring, law enforcement)",
        "requirements": [
            "Complete technical documentation",
            "Risk management system",
            "Data quality and governance",
            "Transparency and user information",
            "Human oversight",
            "Robustness, accuracy and cybersecurity",
            "Quality management system",
            "Registration in EU database",
        ],
    },
    "limited": {
        "description": "Limited-risk systems (chatbots, deepfakes)",
        "requirements": [
            "Transparency obligations",
            "Clear user information about AI interaction",
            "AI-generated content marking",
        ],
    },
    "minimal": {
        "description": "Minimal-risk systems (spam filters, video games)",
        "requirements": [
            "No specific obligations",
            "Voluntary code of conduct encouraged",
        ],
    },
}


# Actionable guidance per compliance check — tells users exactly WHAT, WHY, HOW
ACTIONABLE_GUIDANCE = {
    "technical_documentation": {
        "what": "Create technical documentation describing your AI system's architecture, training data, and intended use",
        "why": "Art. 11 - High-risk systems require complete technical documentation for conformity assessment",
        "how": [
            "Create docs/TECHNICAL_DOCUMENTATION.md (use generate_compliance_templates tool)",
            "Document: system architecture, training data sources, model performance metrics",
            "Document: intended purpose, foreseeable misuse, limitations",
            "Include version history and change log",
        ],
        "eu_article": "Art. 11",
        "effort": "high",
    },
    "risk_management": {
        "what": "Implement a risk management system covering the full AI lifecycle",
        "why": "Art. 9 - High-risk systems must have continuous risk identification and mitigation",
        "how": [
            "Create docs/RISK_MANAGEMENT.md (use generate_compliance_templates tool)",
            "Identify known and foreseeable risks to health, safety, fundamental rights",
            "Define risk mitigation measures for each identified risk",
            "Plan testing procedures to validate mitigation effectiveness",
            "Schedule regular risk reassessment (at least annually)",
        ],
        "eu_article": "Art. 9",
        "effort": "high",
    },
    "transparency": {
        "what": "Ensure users know they are interacting with an AI system",
        "why": "Art. 52 - Users must be informed when they interact with AI",
        "how": [
            "Add clear AI disclosure in README.md and user-facing interfaces",
            "Example: 'This system uses [framework] for [purpose]. Users interact with AI-generated content.'",
            "For chatbots: display notice BEFORE first interaction",
            "For generated content: label outputs as AI-generated",
        ],
        "eu_article": "Art. 52",
        "effort": "low",
    },
    "user_disclosure": {
        "what": "Clearly inform users that AI is involved in the system",
        "why": "Art. 52(1) - Natural persons must be notified of AI interaction",
        "how": [
            "Add an 'AI Disclosure' section to your README.md",
            "Include: which AI models are used, what they do, what data they process",
            "For web apps: add AI disclosure in footer or about page",
            "For APIs: include AI disclosure in API documentation",
        ],
        "eu_article": "Art. 52(1)",
        "effort": "low",
    },
    "content_marking": {
        "what": "Mark AI-generated content so users can distinguish it from human content",
        "why": "Art. 52(3) - AI-generated text/image/audio/video must be labeled",
        "how": [
            "Add metadata or visible label to AI-generated outputs",
            "For text: prepend '[AI-generated]' or add metadata field",
            "For images: embed C2PA metadata or visible watermark",
            "In code: add comment '# AI-generated' or equivalent marker",
        ],
        "eu_article": "Art. 52(3)",
        "effort": "low",
    },
    "data_governance": {
        "what": "Document data quality, collection, and governance practices",
        "why": "Art. 10 - Training data must meet quality criteria and be documented",
        "how": [
            "Create docs/DATA_GOVERNANCE.md (use generate_compliance_templates tool)",
            "Document: data sources, collection methods, preprocessing steps",
            "Document: data quality metrics, bias assessment, representativeness",
            "Define data retention and deletion policies",
            "If using personal data: ensure GDPR compliance (consent, DPA, DPIA)",
        ],
        "eu_article": "Art. 10",
        "effort": "high",
    },
    "human_oversight": {
        "what": "Ensure humans can monitor, intervene, and override AI decisions",
        "why": "Art. 14 - High-risk systems must allow effective human oversight",
        "how": [
            "Create docs/HUMAN_OVERSIGHT.md (use generate_compliance_templates tool)",
            "Design: human-in-the-loop or human-on-the-loop mechanism",
            "Implement: override/stop button for AI decisions",
            "Define: who has oversight responsibility and their qualifications",
            "Log: all AI decisions for post-hoc review",
        ],
        "eu_article": "Art. 14",
        "effort": "medium",
    },
    "robustness": {
        "what": "Ensure AI system accuracy, robustness, and cybersecurity",
        "why": "Art. 15 - High-risk systems must be resilient and secure",
        "how": [
            "Create docs/ROBUSTNESS.md (use generate_compliance_templates tool)",
            "Test: accuracy metrics on representative datasets",
            "Test: adversarial robustness (prompt injection, data poisoning)",
            "Implement: input validation and output filtering",
            "Plan: incident response for AI failures",
        ],
        "eu_article": "Art. 15",
        "effort": "high",
    },
    "basic_documentation": {
        "what": "Create a README.md describing the project",
        "why": "Best practice for all AI systems, even minimal risk",
        "how": [
            "Create README.md with: project description, setup instructions, usage examples",
            "Mention any AI/ML components and their purpose",
        ],
        "eu_article": "Voluntary (Art. 69)",
        "effort": "low",
    },
}

# Compliance document templates — actual starter content for each required document
COMPLIANCE_TEMPLATES = {
    "risk_management": {
        "filename": "RISK_MANAGEMENT.md",
        "content": """# Risk Management System — EU AI Act Art. 9

## 1. System Description
- **System name**: [Your AI system name]
- **Version**: [Version]
- **Intended purpose**: [What the system does]
- **Deployer**: [Organization name]

## 2. Risk Identification
| Risk ID | Description | Likelihood | Impact | Affected Rights |
|---------|-------------|------------|--------|-----------------|
| R-001 | [e.g. Biased outputs for protected groups] | [Low/Med/High] | [Low/Med/High] | [e.g. Non-discrimination] |
| R-002 | [e.g. Incorrect classification leading to harm] | [Low/Med/High] | [Low/Med/High] | [e.g. Safety] |

## 3. Risk Mitigation Measures
| Risk ID | Mitigation | Status | Responsible |
|---------|------------|--------|-------------|
| R-001 | [e.g. Bias testing on diverse datasets] | [Planned/Active] | [Person/Team] |
| R-002 | [e.g. Confidence thresholds + human review] | [Planned/Active] | [Person/Team] |

## 4. Residual Risks
[Describe risks that cannot be fully mitigated and why they are acceptable]

## 5. Testing & Validation
- **Test schedule**: [e.g. Before each release + quarterly]
- **Test datasets**: [Description]
- **Acceptance criteria**: [Metrics and thresholds]

## 6. Review Schedule
- **Next review**: [Date]
- **Review frequency**: [e.g. Annually or after significant changes]
""",
    },
    "technical_documentation": {
        "filename": "TECHNICAL_DOCUMENTATION.md",
        "content": """# Technical Documentation — EU AI Act Art. 11

## 1. General Description
- **System name**: [Your AI system name]
- **Version**: [Version]
- **Provider**: [Organization]
- **Intended purpose**: [Primary use case]
- **Foreseeable misuse**: [What the system should NOT be used for]

## 2. Architecture
- **AI models used**: [e.g. GPT-4, Claude, custom model]
- **Frameworks**: [e.g. OpenAI API, LangChain, PyTorch]
- **System diagram**: [Link or description of architecture]

## 3. Training Data
- **Data sources**: [List sources]
- **Data volume**: [Size]
- **Data preprocessing**: [Steps applied]
- **Known limitations**: [Gaps, biases in data]

## 4. Performance Metrics
| Metric | Value | Dataset | Date |
|--------|-------|---------|------|
| Accuracy | [%] | [Test set] | [Date] |
| Precision | [%] | [Test set] | [Date] |
| Recall | [%] | [Test set] | [Date] |

## 5. Limitations
- [Limitation 1: e.g. Does not work well for languages other than English]
- [Limitation 2: e.g. Performance degrades for inputs longer than X tokens]

## 6. Changes Log
| Version | Date | Changes |
|---------|------|---------|
| 1.0 | [Date] | Initial release |
""",
    },
    "data_governance": {
        "filename": "DATA_GOVERNANCE.md",
        "content": """# Data Governance — EU AI Act Art. 10

## 1. Data Sources
| Source | Type | Volume | Personal Data? | Legal Basis |
|--------|------|--------|----------------|-------------|
| [Source 1] | [Training/Validation/Test] | [Size] | [Yes/No] | [Consent/Legitimate interest/...] |

## 2. Data Quality Criteria
- **Completeness**: [How you ensure data completeness]
- **Accuracy**: [Validation methods]
- **Representativeness**: [How you ensure demographic/geographic coverage]
- **Bias assessment**: [Methods used to detect and mitigate bias]

## 3. Data Preprocessing
1. [Step 1: e.g. Remove duplicates]
2. [Step 2: e.g. Anonymize personal data]
3. [Step 3: e.g. Balance class distribution]

## 4. Data Retention
- **Retention period**: [Duration]
- **Deletion procedure**: [How data is deleted]
- **Legal basis for retention**: [GDPR article]

## 5. GDPR Compliance (if personal data)
- [ ] Data Protection Impact Assessment (DPIA) completed
- [ ] Data Processing Agreement (DPA) with sub-processors
- [ ] Privacy notice updated
- [ ] Data subject rights process in place
""",
    },
    "human_oversight": {
        "filename": "HUMAN_OVERSIGHT.md",
        "content": """# Human Oversight — EU AI Act Art. 14

## 1. Oversight Mechanism
- **Type**: [Human-in-the-loop / Human-on-the-loop / Human-in-command]
- **Description**: [How humans monitor and intervene]

## 2. Responsible Persons
| Role | Responsibility | Qualifications |
|------|---------------|----------------|
| [AI Operator] | [Monitor outputs, handle escalations] | [Required training/experience] |
| [Supervisor] | [Override decisions, system stop] | [Required training/experience] |

## 3. Intervention Mechanisms
- **Override**: [How to override an AI decision — button, API, process]
- **Stop**: [How to stop the system entirely]
- **Escalation**: [When and how to escalate to a human]

## 4. Monitoring
- **Real-time monitoring**: [Yes/No — what is monitored]
- **Logging**: [What decisions are logged and where]
- **Alerting**: [What triggers human notification]

## 5. Training
- **Training program**: [Description of operator training]
- **Frequency**: [e.g. Before first use + annual refresher]
""",
    },
    "robustness": {
        "filename": "ROBUSTNESS.md",
        "content": """# Robustness, Accuracy & Cybersecurity — EU AI Act Art. 15

## 1. Accuracy
- **Metrics**: [Accuracy, precision, recall, F1 on representative test sets]
- **Benchmarks**: [Industry benchmarks if applicable]
- **Known failure modes**: [When the system fails]

## 2. Robustness Testing
- [ ] Tested with adversarial inputs (prompt injection, jailbreak attempts)
- [ ] Tested with out-of-distribution data
- [ ] Tested with edge cases and boundary conditions
- [ ] Tested under high load / stress conditions

## 3. Cybersecurity
- [ ] Input validation implemented
- [ ] Output filtering implemented
- [ ] API authentication and rate limiting
- [ ] Dependency vulnerability scanning (Dependabot, Snyk)
- [ ] Incident response plan documented

## 4. Fallback Behavior
- **On error**: [What happens when the AI fails]
- **On uncertainty**: [What happens when confidence is low]
- **Graceful degradation**: [How the system degrades under failure]

## 5. Update & Maintenance
- **Patch frequency**: [e.g. Monthly security updates]
- **Model retraining**: [Schedule and triggers]
""",
    },
    "transparency": {
        "filename": "TRANSPARENCY.md",
        "content": """# Transparency — EU AI Act Art. 52

## 1. AI Disclosure
This system uses artificial intelligence. Specifically:

- **AI models**: [List models used]
- **Purpose**: [What the AI does in this system]
- **Scope**: [What decisions/outputs are AI-generated]

## 2. User Notification
- Users are informed of AI involvement via: [README / UI notice / API docs / Terms of Service]
- Notification is provided: [Before first interaction / At point of use / In documentation]

## 3. AI-Generated Content Labeling
- AI-generated outputs are marked with: [Label / Metadata / Watermark]
- Method: [Describe how content is labeled]

## 4. Contact
For questions about AI usage in this system: [contact email]
""",
    },
}

# Risk category suggestion based on use-case keywords
RISK_CATEGORY_INDICATORS = {
    "unacceptable": {
        "keywords": ["social scoring", "social credit", "mass surveillance", "biometric identification real-time",
                     "subliminal manipulation", "exploit vulnerabilities", "emotion recognition workplace",
                     "emotion recognition education", "predictive policing individual"],
        "description": "Prohibited AI practices under Art. 5",
    },
    "high": {
        "keywords": ["recruitment", "hiring", "credit scoring", "credit assessment", "insurance pricing",
                     "law enforcement", "border control", "immigration", "asylum",
                     "education admission", "student assessment", "critical infrastructure",
                     "medical device", "medical diagnosis", "biometric", "facial recognition",
                     "justice", "court", "democratic process", "election",
                     "essential services", "emergency services", "safety component"],
        "description": "High-risk AI systems under Annex III",
    },
    "limited": {
        "keywords": ["chatbot", "chat bot", "conversational", "content generation", "text generation",
                     "image generation", "deepfake", "synthetic media", "recommendation",
                     "customer support bot", "virtual assistant", "ai assistant"],
        "description": "AI systems with transparency obligations under Art. 52",
    },
    "minimal": {
        "keywords": ["spam filter", "spam detection", "video game", "search optimization",
                     "inventory management", "autocomplete", "spell check", "translation"],
        "description": "Minimal-risk AI systems (voluntary code of conduct)",
    },
}


# Security: directories that must NEVER be scanned
# Dynamically resolve the installation root (4 levels up from server.py)
_INSTALL_ROOT = os.environ.get("ARKFORGE_ROOT", str(Path(__file__).resolve().parent.parent.parent.parent))
BLOCKED_PATHS = [
    _INSTALL_ROOT,
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/boot",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/snap",
    "/mnt",
    "/media",
]

# Security: max files to scan (prevent DoS)
MAX_FILES_TO_SCAN = 5000
MAX_FILE_SIZE_BYTES = 1_000_000  # 1MB

# Directories to skip during scanning (dependencies, build artifacts, VCS)
SKIP_DIRS = {
    ".venv", "venv", ".env", "env", "node_modules", ".git",
    "__pycache__", ".pytest_cache", ".tox", ".mypy_cache",
    "dist", "build", ".eggs", ".smithery", ".cache",
}


def _validate_project_path(project_path: str) -> tuple[bool, str]:
    """Validate that a project path is safe to scan.

    Returns:
        (is_safe, error_message)
    """
    try:
        resolved = Path(project_path).resolve()
    except (ValueError, OSError):
        return False, f"Invalid path: {project_path}"

    resolved_str = str(resolved)

    # Block absolute paths to sensitive directories
    for blocked in BLOCKED_PATHS:
        if resolved_str == blocked or resolved_str.startswith(blocked + "/"):
            return False, f"Access denied: scanning {blocked} is not allowed for security reasons"

    # Block symlinks that escape to blocked paths
    if resolved != Path(project_path):
        for blocked in BLOCKED_PATHS:
            if resolved_str.startswith(blocked + "/"):
                return False, f"Access denied: symlink resolves to blocked path"

    return True, ""


class EUAIActChecker:
    """EU AI Act compliance checker"""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.detected_models = {}
        self.files_scanned = 0
        self.ai_files = []

    def scan_project(self) -> Dict[str, Any]:
        """Scan the project to detect AI model usage"""
        logger.info("Scanning project: %s", self.project_path)

        # Security: validate path before scanning
        is_safe, error_msg = _validate_project_path(str(self.project_path))
        if not is_safe:
            return {"error": error_msg, "detected_models": {}}

        if not self.project_path.exists():
            return {
                "error": f"Project path does not exist: {self.project_path}",
                "detected_models": {},
            }

        # File extensions to scan
        code_extensions = {".py", ".js", ".ts", ".java", ".go", ".rs", ".cpp", ".c"}

        for file_path in self.project_path.rglob("*"):
            if SKIP_DIRS.intersection(file_path.parts):
                continue
            if self.files_scanned >= MAX_FILES_TO_SCAN:
                logger.warning("Max files limit reached (%d)", MAX_FILES_TO_SCAN)
                break
            if not file_path.is_file():
                continue
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue
            if file_path.suffix in code_extensions:
                self._scan_file(file_path)
            elif file_path.name in CONFIG_FILE_NAMES:
                self._scan_config_file(file_path)

        return {
            "files_scanned": self.files_scanned,
            "ai_files": self.ai_files,
            "detected_models": self.detected_models,
        }

    def _scan_file(self, file_path: Path):
        """Scan a file for AI patterns"""
        self.files_scanned += 1
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            file_detections = []
            for framework, patterns in AI_MODEL_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        file_detections.append(framework)
                        if framework not in self.detected_models:
                            self.detected_models[framework] = []
                        self.detected_models[framework].append(str(file_path.relative_to(self.project_path)))
                        break  # One detection per framework per file

            if file_detections:
                self.ai_files.append({
                    "file": str(file_path.relative_to(self.project_path)),
                    "frameworks": list(set(file_detections)),
                })

        except Exception as e:
            logger.warning("Error scanning %s: %s", file_path, e)

    def _scan_config_file(self, file_path: Path):
        """Scan a config/manifest file for AI dependency declarations"""
        self.files_scanned += 1
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            file_detections = []
            for framework, patterns in CONFIG_DEPENDENCY_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        file_detections.append(framework)
                        if framework not in self.detected_models:
                            self.detected_models[framework] = []
                        self.detected_models[framework].append(str(file_path.relative_to(self.project_path)))
                        break

            if file_detections:
                self.ai_files.append({
                    "file": str(file_path.relative_to(self.project_path)),
                    "frameworks": list(set(file_detections)),
                    "source": "config",
                })

        except Exception as e:
            logger.warning("Error scanning config %s: %s", file_path, e)

    def check_compliance(self, risk_category: str = "limited") -> Dict[str, Any]:
        """Check EU AI Act compliance for a given risk category"""
        if risk_category not in RISK_CATEGORIES:
            return {
                "error": f"Invalid risk category: {risk_category}. Valid: {list(RISK_CATEGORIES.keys())}",
            }

        category_info = RISK_CATEGORIES[risk_category]
        requirements = category_info["requirements"]

        compliance_checks = {
            "risk_category": risk_category,
            "description": category_info["description"],
            "requirements": requirements,
            "compliance_status": {},
        }

        # Basic compliance checks
        docs_path = self.project_path / "docs"
        readme_exists = (self.project_path / "README.md").exists()

        if risk_category == "high":
            compliance_checks["compliance_status"] = {
                "technical_documentation": self._check_technical_docs(),
                "risk_management": self._check_file_exists("RISK_MANAGEMENT.md"),
                "transparency": self._check_file_exists("TRANSPARENCY.md") or readme_exists,
                "data_governance": self._check_file_exists("DATA_GOVERNANCE.md"),
                "human_oversight": self._check_file_exists("HUMAN_OVERSIGHT.md"),
                "robustness": self._check_file_exists("ROBUSTNESS.md"),
            }
        elif risk_category == "limited":
            compliance_checks["compliance_status"] = {
                "transparency": readme_exists or self._check_file_exists("TRANSPARENCY.md"),
                "user_disclosure": self._check_ai_disclosure(),
                "content_marking": self._check_content_marking(),
            }
        elif risk_category == "minimal":
            compliance_checks["compliance_status"] = {
                "basic_documentation": readme_exists,
            }

        # Calculate compliance score
        total_checks = len(compliance_checks["compliance_status"])
        passed_checks = sum(1 for v in compliance_checks["compliance_status"].values() if v)
        compliance_checks["compliance_score"] = f"{passed_checks}/{total_checks}"
        compliance_checks["compliance_percentage"] = round((passed_checks / total_checks) * 100, 1) if total_checks > 0 else 0

        return compliance_checks

    def _check_technical_docs(self) -> bool:
        """Check for technical documentation"""
        docs = ["README.md", "ARCHITECTURE.md", "API.md", "docs/"]
        return any((self.project_path / doc).exists() for doc in docs)

    def _check_file_exists(self, filename: str) -> bool:
        """Check if a file exists"""
        return (self.project_path / filename).exists() or (self.project_path / "docs" / filename).exists()

    def _check_ai_disclosure(self) -> bool:
        """Check if the project clearly discloses AI usage"""
        readme_path = self.project_path / "README.md"
        if readme_path.exists():
            content = readme_path.read_text(encoding="utf-8", errors="ignore").lower()
            ai_keywords = ["ai", "artificial intelligence", "intelligence artificielle", "machine learning", "deep learning", "gpt", "claude", "llm"]
            return any(keyword in content for keyword in ai_keywords)
        return False

    def _check_content_marking(self) -> bool:
        """Check if generated content is properly marked"""
        markers = [
            "generated by ai",
            "généré par ia",
            "ai-generated",
            "machine-generated",
        ]
        for file_path in self.project_path.rglob("*.py"):
            if SKIP_DIRS.intersection(file_path.parts):
                continue
            if file_path.is_file():
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
                    if any(marker in content for marker in markers):
                        return True
                except OSError:
                    pass
        return False

    def generate_report(self, scan_results: Dict, compliance_results: Dict) -> Dict[str, Any]:
        """Generate a complete compliance report"""
        report = {
            "report_date": datetime.now(timezone.utc).isoformat(),
            "project_path": str(self.project_path),
            "scan_summary": {
                "files_scanned": scan_results.get("files_scanned", 0),
                "ai_files_detected": len(scan_results.get("ai_files", [])),
                "frameworks_detected": list(scan_results.get("detected_models", {}).keys()),
            },
            "compliance_summary": {
                "risk_category": compliance_results.get("risk_category", "unknown"),
                "compliance_score": compliance_results.get("compliance_score", "0/0"),
                "compliance_percentage": compliance_results.get("compliance_percentage", 0),
            },
            "detailed_findings": {
                "detected_models": scan_results.get("detected_models", {}),
                "compliance_checks": compliance_results.get("compliance_status", {}),
                "requirements": compliance_results.get("requirements", []),
            },
            "recommendations": self._generate_recommendations(compliance_results),
        }

        return report

    def _generate_recommendations(self, compliance_results: Dict) -> List[Dict[str, Any]]:
        """Generate actionable recommendations with concrete steps for each failing check"""
        recommendations = []
        compliance_status = compliance_results.get("compliance_status", {})
        risk_category = compliance_results.get("risk_category", "limited")

        for check, passed in compliance_status.items():
            if not passed:
                guidance = ACTIONABLE_GUIDANCE.get(check, {})
                recommendations.append({
                    "check": check,
                    "status": "FAIL",
                    "what": guidance.get("what", f"Missing: {check.replace('_', ' ')}"),
                    "why": guidance.get("why", "Required by EU AI Act"),
                    "how": guidance.get("how", [f"Create {check}.md documentation"]),
                    "template_available": check in COMPLIANCE_TEMPLATES,
                    "eu_article": guidance.get("eu_article", ""),
                    "effort": guidance.get("effort", "medium"),
                })
            else:
                recommendations.append({
                    "check": check,
                    "status": "PASS",
                })

        if risk_category == "high":
            recommendations.append({
                "check": "eu_database_registration",
                "status": "ACTION_REQUIRED",
                "what": "Register system in EU AI database before deployment",
                "why": "Art. 60 - Mandatory for all high-risk AI systems",
                "how": [
                    "Go to https://ec.europa.eu/ai-act-database (when available)",
                    "Prepare: system name, provider info, intended purpose, risk category",
                    "Submit registration BEFORE placing system on market",
                ],
                "eu_article": "Art. 60",
                "effort": "low",
            })

        return recommendations


class RiskCategory(str, Enum):
    """EU AI Act risk categories"""
    unacceptable = "unacceptable"
    high = "high"
    limited = "limited"
    minimal = "minimal"


FREE_TIER_BANNER = "Free tier: 10 scans/day — Pro: unlimited scans + CI/CD API at 29€/mo → https://mcp.arkforge.fr/fr/pricing.html?utm_source=pypi"
TRUST_LAYER_CTA = "Certify this compliance scan with ArkForge Trust Layer — tamper-proof, verifiable, signed proofs → https://arkforge.fr/trust?utm_source=pypi"


def _add_banner(result: dict) -> dict:
    """Add free tier upgrade banner and Trust Layer CTA to MCP tool responses."""
    result["upgrade"] = FREE_TIER_BANNER
    result["trust_layer"] = TRUST_LAYER_CTA
    return result


def create_server():
    """Create and return the EU AI Act Compliance Checker MCP server."""
    mcp = FastMCP(
        name="ArkForge Compliance Scanner",
        instructions="Multi-regulation compliance scanner. Supports EU AI Act and GDPR. Scan projects to detect AI model usage, personal data processing, and verify regulatory compliance. Free: 10 scans/day. Pro: unlimited + CI/CD API at 29€/mo → https://mcp.arkforge.fr/fr/pricing.html?utm_source=pypi | Certify scans with Trust Layer → https://arkforge.fr/trust?utm_source=pypi",
        host="0.0.0.0",
        port=8090,
    )

    @mcp.tool()
    def scan_project(project_path: str) -> dict:
        """Scan a project to detect AI model usage (OpenAI, Anthropic, Google Gemini, Vertex AI, Mistral, Cohere, HuggingFace, TensorFlow, PyTorch, LangChain, AWS Bedrock, Azure OpenAI, Ollama, LlamaIndex, Replicate, Groq).

        Args:
            project_path: Absolute path to the project to scan
        """
        is_safe, error_msg = _validate_project_path(project_path)
        if not is_safe:
            return {"error": error_msg, "detected_models": {}}
        checker = EUAIActChecker(project_path)
        return _add_banner(checker.scan_project())

    @mcp.tool()
    def check_compliance(project_path: str, risk_category: RiskCategory = RiskCategory.limited) -> dict:
        """Check EU AI Act compliance for a given risk category.

        Args:
            project_path: Absolute path to the project
            risk_category: EU AI Act risk category (unacceptable, high, limited, minimal)
        """
        is_safe, error_msg = _validate_project_path(project_path)
        if not is_safe:
            return {"error": error_msg}
        checker = EUAIActChecker(project_path)
        checker.scan_project()
        return _add_banner(checker.check_compliance(risk_category.value))

    @mcp.tool()
    def generate_report(project_path: str, risk_category: RiskCategory = RiskCategory.limited) -> dict:
        """Generate a complete EU AI Act compliance report with scan results, compliance checks, and recommendations.

        Args:
            project_path: Absolute path to the project
            risk_category: EU AI Act risk category (unacceptable, high, limited, minimal)
        """
        is_safe, error_msg = _validate_project_path(project_path)
        if not is_safe:
            return {"error": error_msg}
        checker = EUAIActChecker(project_path)
        scan_results = checker.scan_project()
        compliance_results = checker.check_compliance(risk_category.value)
        return _add_banner(checker.generate_report(scan_results, compliance_results))

    @mcp.tool()
    def suggest_risk_category(system_description: str) -> dict:
        """Suggest the most likely EU AI Act risk category based on your AI system's description.

        Analyzes your system description against EU AI Act criteria (Art. 5, 6, Annex III, Art. 52)
        to suggest which risk category applies. Helps users who don't know their risk category.

        Args:
            system_description: Description of what your AI system does (e.g. "chatbot for customer support", "CV screening tool for recruitment")
        """
        description_lower = system_description.lower()
        matches = {}

        for category, info in RISK_CATEGORY_INDICATORS.items():
            matched_keywords = [kw for kw in info["keywords"] if kw in description_lower]
            if matched_keywords:
                matches[category] = {
                    "matched_keywords": matched_keywords,
                    "match_count": len(matched_keywords),
                    "description": info["description"],
                }

        if not matches:
            suggested = "limited"
            confidence = "low"
            reasoning = "No specific risk indicators detected. Defaulting to 'limited' (most common for AI applications). Review the category descriptions below to confirm."
        else:
            # Pick highest-risk matched category
            priority = ["unacceptable", "high", "limited", "minimal"]
            suggested = next(cat for cat in priority if cat in matches)
            match_info = matches[suggested]
            confidence = "high" if match_info["match_count"] >= 2 else "medium"
            reasoning = f"Matched {match_info['match_count']} indicator(s): {', '.join(match_info['matched_keywords'])}. {match_info['description']}."

        return {
            "suggested_category": suggested,
            "confidence": confidence,
            "reasoning": reasoning,
            "all_matches": matches,
            "categories_reference": {
                cat: {
                    "description": RISK_CATEGORIES[cat]["description"],
                    "requirements_count": len(RISK_CATEGORIES[cat]["requirements"]),
                }
                for cat in RISK_CATEGORIES
            },
            "next_step": f"Run check_compliance with risk_category='{suggested}' to see what's needed",
            "upgrade": FREE_TIER_BANNER,
        }

    @mcp.tool()
    def generate_compliance_templates(risk_category: RiskCategory = RiskCategory.high) -> dict:
        """Generate starter compliance document templates for your EU AI Act risk category.

        Returns ready-to-use markdown templates for each required compliance document.
        Save these files in your project's docs/ directory, then fill in the [bracketed] sections.

        Args:
            risk_category: EU AI Act risk category (high, limited, minimal). Templates are most useful for 'high' risk.
        """
        category = risk_category.value
        category_info = RISK_CATEGORIES.get(category, {})

        if category == "unacceptable":
            return {
                "error": "Unacceptable-risk systems are PROHIBITED under Art. 5. No compliance templates available — this system type cannot be deployed in the EU.",
                "recommendation": "Redesign your system to avoid prohibited practices, or consult legal counsel.",
            }

        # Determine which templates apply to this risk category
        template_mapping = {
            "high": ["risk_management", "technical_documentation", "data_governance", "human_oversight", "robustness", "transparency"],
            "limited": ["transparency"],
            "minimal": [],
        }

        applicable = template_mapping.get(category, [])
        templates = {}

        for template_key in applicable:
            if template_key in COMPLIANCE_TEMPLATES:
                tmpl = COMPLIANCE_TEMPLATES[template_key]
                templates[template_key] = {
                    "filename": f"docs/{tmpl['filename']}",
                    "content": tmpl["content"],
                    "instructions": f"Save as docs/{tmpl['filename']} in your project, then fill in [bracketed] sections",
                }

        return {
            "risk_category": category,
            "description": category_info.get("description", ""),
            "templates_count": len(templates),
            "templates": templates,
            "usage": "Save each template file in your project's docs/ directory. Fill in [bracketed] sections with your system's details. Re-run check_compliance to verify progress.",
        }

    @mcp.tool()
    def validate_api_key(api_key: str) -> dict:
        """Validate an API key and return its tier and usage information.

        Args:
            api_key: The API key to validate
        """
        result = _api_key_manager.verify(api_key)
        if not result:
            return {"valid": False, "error": "Invalid or inactive API key"}
        entry = _api_key_manager.get_entry(api_key)
        return {
            "valid": True,
            "tier": result["plan"],
            "email": result["email"],
            "usage": {
                "scans_total": entry.get("scans_total", 0),
                "last_scan": entry.get("last_scan", None),
            },
        }

    # ============================================================
    # GDPR Compliance Tools
    # ============================================================

    class ProcessingRole(str, Enum):
        """GDPR processing roles"""
        controller = "controller"
        processor = "processor"
        minimal_processing = "minimal_processing"

    @mcp.tool()
    def gdpr_scan_project(project_path: str) -> dict:
        """Scan a project to detect personal data processing patterns (GDPR).

        Detects: PII fields, database queries, cookies, tracking, analytics,
        geolocation, file uploads, consent mechanisms, encryption, data deletion.

        Args:
            project_path: Absolute path to the project to scan
        """
        is_safe, error_msg = _validate_project_path(project_path)
        if not is_safe:
            return {"error": error_msg, "detected_patterns": {}}
        checker = GDPRChecker(project_path)
        return _add_banner(checker.scan_project())

    @mcp.tool()
    def gdpr_check_compliance(project_path: str, processing_role: ProcessingRole = ProcessingRole.controller) -> dict:
        """Check GDPR compliance for a project based on its data processing role.

        Args:
            project_path: Absolute path to the project
            processing_role: Your GDPR role (controller, processor, or minimal_processing)
        """
        is_safe, error_msg = _validate_project_path(project_path)
        if not is_safe:
            return {"error": error_msg}
        checker = GDPRChecker(project_path)
        checker.scan_project()
        return _add_banner(checker.check_compliance(processing_role.value))

    @mcp.tool()
    def gdpr_generate_report(project_path: str, processing_role: ProcessingRole = ProcessingRole.controller) -> dict:
        """Generate a complete GDPR compliance report with data processing scan, compliance checks, and recommendations.

        Args:
            project_path: Absolute path to the project
            processing_role: Your GDPR role (controller, processor, or minimal_processing)
        """
        is_safe, error_msg = _validate_project_path(project_path)
        if not is_safe:
            return {"error": error_msg}
        checker = GDPRChecker(project_path)
        scan_results = checker.scan_project()
        compliance_results = checker.check_compliance(processing_role.value)
        return _add_banner(checker.generate_report(scan_results, compliance_results))

    @mcp.tool()
    def gdpr_generate_templates(processing_role: ProcessingRole = ProcessingRole.controller) -> dict:
        """Generate starter GDPR compliance document templates for your processing role.

        Returns ready-to-use templates: Privacy Policy, DPIA, Records of Processing, Data Breach Procedure.

        Args:
            processing_role: Your GDPR role (controller, processor, or minimal_processing)
        """
        checker = GDPRChecker("/tmp")  # Templates don't need a real path
        return checker.get_templates(processing_role.value)

    @mcp.tool()
    def get_pricing() -> dict:
        """Get pricing plans and upgrade information for the ArkForge Compliance Scanner.

        Shows free tier limits, Pro plan features, and how to upgrade.
        """
        return {
            "plans": {
                "free": {
                    "price": "0",
                    "limit": "10 scans/day per IP",
                    "features": [
                        "Full compliance reports",
                        "22 AI frameworks detected",
                        "EU AI Act + GDPR checks",
                    ],
                },
                "pro": {
                    "price": "29 EUR/month",
                    "limit": "Unlimited",
                    "features": [
                        "Unlimited scans",
                        "CI/CD integration via REST API",
                        "API key authentication",
                        "Scan history dashboard",
                        "Email alerts on risk changes",
                        "Priority support",
                    ],
                    "subscribe_url": "https://mcp.arkforge.fr/fr/pricing.html?utm_source=pypi",
                },
            },
            "pricing_page": "https://mcp.arkforge.fr/fr/pricing.html?utm_source=pypi",
            "contact": "contact@arkforge.fr",
        }

    return mcp


# Legacy interface for backward compatibility
class MCPServer:
    """Legacy MCP Server interface (use create_server() for MCP protocol)"""

    def __init__(self):
        self._tools = {
            "scan_project": lambda **params: {"tool": "scan_project", "results": EUAIActChecker(params["project_path"]).scan_project()},
            "check_compliance": lambda **params: {"tool": "check_compliance", "results": (lambda c: (c.scan_project(), c.check_compliance(params.get("risk_category", "limited")))[-1])(EUAIActChecker(params["project_path"]))},
            "generate_report": lambda **params: {"tool": "generate_report", "results": (lambda c: c.generate_report(c.scan_project(), c.check_compliance(params.get("risk_category", "limited"))))(EUAIActChecker(params["project_path"]))},
            "suggest_risk_category": lambda **params: self._suggest_risk_category(params["system_description"]),
            "generate_compliance_templates": lambda **params: self._generate_compliance_templates(params.get("risk_category", "high")),
        }

    def _suggest_risk_category(self, system_description: str) -> Dict[str, Any]:
        description_lower = system_description.lower()
        matches = {}
        for category, info in RISK_CATEGORY_INDICATORS.items():
            matched_keywords = [kw for kw in info["keywords"] if kw in description_lower]
            if matched_keywords:
                matches[category] = {"matched_keywords": matched_keywords, "match_count": len(matched_keywords), "description": info["description"]}
        if not matches:
            suggested, confidence = "limited", "low"
            reasoning = "No specific risk indicators detected. Defaulting to 'limited'."
        else:
            priority = ["unacceptable", "high", "limited", "minimal"]
            suggested = next(cat for cat in priority if cat in matches)
            confidence = "high" if matches[suggested]["match_count"] >= 2 else "medium"
            reasoning = f"Matched: {', '.join(matches[suggested]['matched_keywords'])}. {matches[suggested]['description']}."
        return {"tool": "suggest_risk_category", "results": {"suggested_category": suggested, "confidence": confidence, "reasoning": reasoning, "all_matches": matches}}

    def _generate_compliance_templates(self, risk_category: str) -> Dict[str, Any]:
        if risk_category == "unacceptable":
            return {"tool": "generate_compliance_templates", "error": "Unacceptable-risk systems are PROHIBITED under Art. 5."}
        template_mapping = {"high": ["risk_management", "technical_documentation", "data_governance", "human_oversight", "robustness", "transparency"], "limited": ["transparency"], "minimal": []}
        templates = {k: {"filename": f"docs/{COMPLIANCE_TEMPLATES[k]['filename']}", "content": COMPLIANCE_TEMPLATES[k]["content"]} for k in template_mapping.get(risk_category, []) if k in COMPLIANCE_TEMPLATES}
        return {"tool": "generate_compliance_templates", "results": {"risk_category": risk_category, "templates_count": len(templates), "templates": templates}}

    def handle_request(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name not in self._tools:
            return {"error": f"Unknown tool: {tool_name}", "available_tools": list(self._tools.keys())}
        try:
            return self._tools[tool_name](**params)
        except Exception as e:
            return {"error": f"Error executing {tool_name}: {str(e)}"}

    def list_tools(self) -> Dict[str, Any]:
        return {"tools": [
            {"name": "scan_project", "description": "Scan a project to detect AI model usage", "parameters": {"project_path": "string (required)"}},
            {"name": "check_compliance", "description": "Check EU AI Act compliance", "parameters": {"project_path": "string (required)", "risk_category": "string (optional)"}},
            {"name": "generate_report", "description": "Generate a complete compliance report", "parameters": {"project_path": "string (required)", "risk_category": "string (optional)"}},
            {"name": "suggest_risk_category", "description": "Suggest risk category from system description", "parameters": {"system_description": "string (required)"}},
            {"name": "generate_compliance_templates", "description": "Generate compliance document templates", "parameters": {"risk_category": "string (optional, default: high)"}},
        ]}


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    server = create_server()
    if "--http" in sys.argv:
        import uvicorn
        logger.info("Starting MCP EU AI Act scanner (HTTP mode) on %s:%s", server.settings.host, server.settings.port)
        app = RateLimitMiddleware(server.streamable_http_app())
        config = uvicorn.Config(
            app,
            host=server.settings.host,
            port=server.settings.port,
            log_level="info",
        )
        uvicorn.Server(config).run()
    else:
        logger.info("Starting MCP EU AI Act scanner (stdio mode)")
        server.run(transport="stdio")
