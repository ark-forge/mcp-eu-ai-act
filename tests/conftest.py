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
def isolate_tool_call_log(tmp_path):
    """Redirect tool call telemetry to tmp_path during tests.

    Without this, every test that calls scan/check/report tools appends
    'certified' plan entries to the production data/tool_calls.jsonl,
    polluting funnel metrics (1031 false 'certified' entries observed).
    """
    original_path = server_module._TOOL_CALL_LOG_PATH
    server_module._TOOL_CALL_LOG_PATH = tmp_path / "tool_calls.jsonl"
    yield
    server_module._TOOL_CALL_LOG_PATH = original_path


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
