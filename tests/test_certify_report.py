"""Tests for certify_compliance_report MCP tool.

Tests the certification logic including key validation and network error handling.
"""

import json
import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import create_server


def _unwrap_result(result):
    """Unwrap TextContent list to dict — JSON block is always last."""
    if isinstance(result, list) and len(result) >= 2 and hasattr(result[-1], "text"):
        for block in reversed(result):
            try:
                return json.loads(block.text)
            except (json.JSONDecodeError, ValueError):
                continue
    return result


# ---------------------------------------------------------------------------
# Helper: invoke the tool via the MCP server instance
# ---------------------------------------------------------------------------

def _get_certify_tool():
    """Return the certify_compliance_report function from the MCP server."""
    server = create_server()
    return server._tool_manager._tools["certify_compliance_report"].fn


def _certify(report_data, trust_layer_key):
    tool = _get_certify_tool()
    return _unwrap_result(tool(report_data=report_data, trust_layer_key=trust_layer_key))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_missing_key_returns_error():
    """An empty trust_layer_key should return a response with 'error' key."""
    result = _certify(report_data='{"test": 1}', trust_layer_key="")
    assert "error" in result, "Expected 'error' key when trust_layer_key is empty"


def test_missing_key_status_is_missing_key():
    """An empty trust_layer_key should set status='missing_key'."""
    result = _certify(report_data='{"test": 1}', trust_layer_key="")
    assert result.get("status") == "missing_key", (
        f"Expected status='missing_key', got {result.get('status')!r}"
    )


def test_valid_json_string_accepted():
    """A valid JSON string as report_data should not produce a JSON parse error."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        result = _certify(report_data='{"test": 1}', trust_layer_key="ak_testkey123")
    # Should not have a JSON-related error — only a network error
    assert "error" in result, "Expected an error (network), got none"
    error_msg = result["error"].lower()
    assert "json" not in error_msg, (
        f"Got a JSON parse error instead of network error: {result['error']!r}"
    )


def test_non_json_string_accepted():
    """A non-JSON string as report_data should not crash the tool."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        try:
            result = _certify(report_data="plain text report", trust_layer_key="ak_testkey123")
        except Exception as exc:
            pytest.fail(f"Tool crashed on non-JSON report_data: {exc}")
    # Any result is acceptable as long as there is no unhandled exception
    assert isinstance(result, dict), "Expected a dict result"


def test_network_error_returns_error_status():
    """A URLError from urllib should result in an error status in the response."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("test")):
        result = _certify(
            report_data='{"compliance_percentage": 83}',
            trust_layer_key="ak_testkey123456789",
        )
    assert "error" in result or "status" in result, (
        "Expected 'error' or 'status' key on network failure"
    )
    status = result.get("status", "")
    assert "error" in status.lower() or status == "network_error", (
        f"Expected error-related status on URLError, got: {status!r}"
    )
