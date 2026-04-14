"""Shared fixtures for MCP EU AI Act test suite."""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

import server as server_module
from server import RateLimiter, _current_plan


@pytest.fixture(autouse=True)
def isolate_rate_limiter_persistence(tmp_path):
    """Ensure each test gets an isolated RateLimiter persistence file.

    Without this, all RateLimiter instances share data/mcp_rate_limits.json,
    causing cross-test pollution when one test's writes affect another test's reads.
    """
    original_path = RateLimiter._PERSIST_PATH
    RateLimiter._PERSIST_PATH = tmp_path / "mcp_rate_limits.json"
    yield
    RateLimiter._PERSIST_PATH = original_path


@pytest.fixture(autouse=True)
def set_certified_plan():
    """Set plan to 'certified' for all tests so paywall gates don't block tool tests.

    Tests that specifically test the paywall behavior should override this by
    setting _current_plan.set('free') at the start of the test.
    """
    token = _current_plan.set("certified")
    old_transport = server_module._fallback_transport
    server_module._fallback_transport = "mcp_jsonrpc"
    yield
    _current_plan.reset(token)
    server_module._fallback_transport = old_transport
