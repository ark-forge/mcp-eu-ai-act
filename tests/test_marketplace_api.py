"""Tests for the EU AI Act Marketplace API."""

import json
import uuid
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

# Patch server imports before importing marketplace_api
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import time
from marketplace_api import app, SCANS_DIR, JOBS_DIR, RATE_LIMITS_FILE, _save_json, FREE_TIER_LIMIT, MAX_JOBS

client = TestClient(app)


# --- Fixtures ---

@pytest.fixture(autouse=True, scope="session")
def clean_excess_scans():
    """Remove excess scan files so cleanup code doesn't trigger concurrent deletes."""
    scan_files = sorted(SCANS_DIR.glob("*.json"), key=lambda f: f.stat().st_mtime if f.exists() else 0)
    if len(scan_files) > 50:
        for old in scan_files[:len(scan_files) - 50]:
            old.unlink(missing_ok=True)
    yield


@pytest.fixture(autouse=True)
def clean_rate_limits():
    """Reset rate limits before each test."""
    if RATE_LIMITS_FILE.exists():
        RATE_LIMITS_FILE.unlink()
    yield
    if RATE_LIMITS_FILE.exists():
        RATE_LIMITS_FILE.unlink()


@pytest.fixture
def sample_project(tmp_path):
    """Create a temp project with AI code for scanning."""
    py_file = tmp_path / "app.py"
    py_file.write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "response = client.chat.completions.create(model='gpt-4')\n"
    )
    readme = tmp_path / "README.md"
    readme.write_text("# My AI App\nThis project uses AI for chat.")
    return str(tmp_path)


# --- Health ---

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["service"] == "euaiact-marketplace-api"


# --- POST /v1/scan — Happy path with inline code ---

def test_scan_inline_code():
    r = client.post("/v1/scan", json={
        "code_source": "import openai\nclient = openai.OpenAI()\n",
        "risk_category": "limited",
    })
    assert r.status_code == 200
    data = r.json()
    assert "scan_id" in data
    assert "timestamp" in data
    assert "risk_score" in data
    assert isinstance(data["risk_score"], (int, float))
    assert "frameworks_detected" in data
    assert isinstance(data["frameworks_detected"], list)
    assert "openai" in data["frameworks_detected"]
    assert "recommendations" in data
    assert data["source"] == "inline_code"
    # Validate scan_id is a UUID
    uuid.UUID(data["scan_id"])


def test_scan_inline_no_ai():
    """Scan code without AI frameworks — should return empty frameworks."""
    r = client.post("/v1/scan", json={
        "code_source": "print('hello world')\n",
        "risk_category": "minimal",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["frameworks_detected"] == []
    assert data["files_scanned"] >= 1


# --- POST /v1/scan — with project path via mock ---

def test_scan_with_project_path(sample_project):
    """Scan a local project by providing code_source (simulating real use)."""
    code = Path(sample_project, "app.py").read_text()
    r = client.post("/v1/scan", json={
        "code_source": code,
        "risk_category": "limited",
    })
    assert r.status_code == 200
    data = r.json()
    assert "openai" in data["frameworks_detected"]


# --- GET /v1/scan/{id} — Retrieve previous scan ---

def test_get_scan_result():
    # First create a scan
    r = client.post("/v1/scan", json={
        "code_source": "import anthropic\n",
        "risk_category": "limited",
    })
    assert r.status_code == 200
    scan_id = r.json()["scan_id"]

    # Retrieve it
    r2 = client.get(f"/v1/scan/{scan_id}")
    assert r2.status_code == 200
    data = r2.json()
    assert data["scan_id"] == scan_id
    assert "anthropic" in data["frameworks_detected"]


def test_get_scan_not_found():
    fake_id = str(uuid.uuid4())
    r = client.get(f"/v1/scan/{fake_id}")
    assert r.status_code == 404


def test_get_scan_invalid_id():
    r = client.get("/v1/scan/not-a-uuid")
    assert r.status_code == 400


# --- Validation errors ---

def test_scan_no_input():
    r = client.post("/v1/scan", json={})
    assert r.status_code == 400


def test_scan_both_inputs():
    r = client.post("/v1/scan", json={
        "url": "https://github.com/example/repo",
        "code_source": "import openai\n",
    })
    assert r.status_code == 400


def test_scan_invalid_risk_category():
    r = client.post("/v1/scan", json={
        "code_source": "import openai\n",
        "risk_category": "extreme",
    })
    assert r.status_code == 400


def test_scan_source_too_large():
    huge = "x" * 600_000
    r = client.post("/v1/scan", json={
        "code_source": huge,
        "risk_category": "limited",
    })
    assert r.status_code == 413


# --- Rate limiting ---

def test_rate_limit_free_tier():
    """Free tier allows 5 scans/day, then blocks."""
    for i in range(FREE_TIER_LIMIT):
        r = client.post("/v1/scan", json={
            "code_source": f"# scan {i}\nprint('test')\n",
            "risk_category": "minimal",
        })
        assert r.status_code == 200, f"Scan {i+1} should succeed"

    # 6th should be rate limited
    r = client.post("/v1/scan", json={
        "code_source": "print('blocked')\n",
        "risk_category": "minimal",
    })
    assert r.status_code == 429


def test_rate_limit_bypassed_with_api_key():
    """Valid API key bypasses rate limit."""
    # Create a fake pro key in the data file
    from marketplace_api import API_KEYS_FILE, _save_json
    keys = {}
    test_key = "mcp_pro_test1234567890abcdef1234567890abcdef12345678"
    keys[test_key] = {
        "plan": "pro",
        "active": True,
        "email": "test@example.com",
    }
    _save_json(API_KEYS_FILE, keys)

    try:
        # Exhaust free tier first
        for i in range(FREE_TIER_LIMIT + 2):
            r = client.post(
                "/v1/scan",
                json={"code_source": f"# {i}\n", "risk_category": "minimal"},
                headers={"X-API-Key": test_key},
            )
            assert r.status_code == 200, f"Pro scan {i+1} should succeed"
    finally:
        # Clean up
        keys_data = json.loads(API_KEYS_FILE.read_text())
        keys_data.pop(test_key, None)
        _save_json(API_KEYS_FILE, keys_data)


# --- Usage endpoint ---

def test_usage_free():
    r = client.get("/v1/usage")
    assert r.status_code == 200
    data = r.json()
    assert data["plan"] == "free"
    assert data["daily_limit"] == FREE_TIER_LIMIT
    assert "remaining" in data


# --- URL scan with mock ---

def test_scan_url_invalid_scheme():
    """Non-HTTPS URLs should be rejected."""
    r = client.post("/v1/scan", json={
        "url": "http://github.com/example/repo",
        "risk_category": "limited",
    })
    assert r.status_code == 400


def test_scan_url_clone_failure():
    """Git clone failure should return 400."""
    r = client.post("/v1/scan", json={
        "url": "https://github.com/nonexistent-user-xyz/nonexistent-repo-xyz",
        "risk_category": "limited",
    })
    assert r.status_code == 400


# --- Risk categories ---

def test_scan_high_risk():
    r = client.post("/v1/scan", json={
        "code_source": "import openai\nclient = openai.OpenAI()\n",
        "risk_category": "high",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["risk_category"] == "high"
    # High risk without docs → high risk score
    assert data["risk_score"] > 0
    assert len(data["recommendations"]) > 0


# --- Async scan endpoints ---

@pytest.fixture(autouse=False)
def clean_jobs():
    """Remove job files before/after test."""
    for f in JOBS_DIR.glob("*.json"):
        f.unlink(missing_ok=True)
    yield
    for f in JOBS_DIR.glob("*.json"):
        f.unlink(missing_ok=True)


def test_async_scan_returns_job_id(clean_jobs):
    """POST /v1/scan/async should return 202 with job_id immediately."""
    r = client.post("/v1/scan/async", json={
        "code_source": "import openai\nclient = openai.OpenAI()\n",
        "risk_category": "limited",
    })
    assert r.status_code == 202
    data = r.json()
    assert "job_id" in data
    assert data["status"] == "pending"
    assert "poll_url" in data
    uuid.UUID(data["job_id"])  # must be valid UUID


def test_async_scan_completes(clean_jobs):
    """Async scan should complete and result be retrievable via /v1/job/{id}."""
    r = client.post("/v1/scan/async", json={
        "code_source": "import anthropic\n",
        "risk_category": "limited",
    })
    assert r.status_code == 202
    job_id = r.json()["job_id"]

    # Poll until done (max 10s)
    deadline = time.time() + 10
    status = "pending"
    while time.time() < deadline:
        r2 = client.get(f"/v1/job/{job_id}")
        assert r2.status_code == 200
        status = r2.json()["status"]
        if status in ("done", "error"):
            break
        time.sleep(0.2)

    assert status == "done", f"Job did not complete in time, status={status}"
    data = r2.json()
    assert "result" in data
    result = data["result"]
    assert "scan_id" in result
    assert "anthropic" in result["frameworks_detected"]


def test_async_job_not_found(clean_jobs):
    """GET /v1/job/{unknown_id} should return 404."""
    fake_id = str(uuid.uuid4())
    r = client.get(f"/v1/job/{fake_id}")
    assert r.status_code == 404


def test_async_job_invalid_id(clean_jobs):
    """GET /v1/job/{invalid} should return 400."""
    r = client.get("/v1/job/not-a-uuid")
    assert r.status_code == 400


def test_async_scan_validation_errors(clean_jobs):
    """Async endpoint should validate inputs same as sync."""
    # No input
    r = client.post("/v1/scan/async", json={})
    assert r.status_code == 400

    # Both inputs
    r = client.post("/v1/scan/async", json={
        "url": "https://github.com/example/repo",
        "code_source": "import openai\n",
    })
    assert r.status_code == 400

    # Invalid risk category
    r = client.post("/v1/scan/async", json={
        "code_source": "import openai\n",
        "risk_category": "extreme",
    })
    assert r.status_code == 400


def test_async_scan_rate_limited(clean_jobs):
    """Async endpoint should respect rate limits."""
    # Exhaust free tier
    for i in range(FREE_TIER_LIMIT):
        r = client.post("/v1/scan/async", json={
            "code_source": f"# {i}\n",
            "risk_category": "minimal",
        })
        assert r.status_code == 202, f"Scan {i+1} should be accepted"

    # Next should be rate-limited
    r = client.post("/v1/scan/async", json={
        "code_source": "print('blocked')\n",
        "risk_category": "minimal",
    })
    assert r.status_code == 429
