"""Tests for generate_annex4_package MCP tool.

Tests the Annex IV ZIP package generation logic via the create_server() tool.
"""

import sys
import io
import re
import zipfile
import json
from pathlib import Path
from datetime import datetime

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import create_server, RiskCategory


# ---------------------------------------------------------------------------
# Helper: invoke the tool via the MCP server instance
# ---------------------------------------------------------------------------

def _get_annex4_tool():
    """Return the generate_annex4_package function from the MCP server."""
    server = create_server()
    return server._tool_manager._tools["generate_annex4_package"].fn


def _unwrap_result(result):
    """Unwrap TextContent list to dict if needed."""
    if isinstance(result, list) and len(result) >= 2 and hasattr(result[0], "text"):
        return json.loads(result[0].text)
    return result


def _annex4(project_path, sign_with_trust_layer=False, trust_layer_key=""):
    """Call generate_annex4_package with the given arguments."""
    tool = _get_annex4_tool()
    return _unwrap_result(tool(
        project_path=str(project_path),
        sign_with_trust_layer=sign_with_trust_layer,
        trust_layer_key=trust_layer_key,
    ))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_returns_sections_count(tmp_path):
    """Result should contain sections_count >= 8."""
    result = _annex4(tmp_path)
    assert "sections_count" in result, "Expected 'sections_count' key in result"
    assert result["sections_count"] >= 8, (
        f"Expected sections_count >= 8, got {result['sections_count']}"
    )


def test_sections_list_has_8_items(tmp_path):
    """The sections list should contain at least 8 items."""
    result = _annex4(tmp_path)
    assert "sections" in result, "Expected 'sections' key in result"
    assert isinstance(result["sections"], list), "sections should be a list"
    assert len(result["sections"]) >= 8, (
        f"Expected at least 8 sections, got {len(result['sections'])}"
    )


def test_sha256_present(tmp_path):
    """Result should have a sha256 field that is a 64-character hex string."""
    result = _annex4(tmp_path)
    assert "sha256" in result, "Expected 'sha256' key in result"
    sha = result["sha256"]
    assert isinstance(sha, str), "sha256 should be a string"
    assert len(sha) == 64, f"Expected 64-char hex, got length {len(sha)}: {sha!r}"
    assert re.fullmatch(r"[0-9a-f]{64}", sha), (
        f"sha256 should be lowercase hex, got: {sha!r}"
    )


def test_status_generated(tmp_path):
    """status should be 'generated' (or 'generated_and_certified' if signed)."""
    result = _annex4(tmp_path)
    assert "status" in result, "Expected 'status' key in result"
    assert result["status"] in ("generated", "generated_and_certified"), (
        f"Unexpected status: {result['status']!r}"
    )


def test_zip_size_positive(tmp_path):
    """zip_size_bytes should be a positive integer."""
    result = _annex4(tmp_path)
    assert "zip_size_bytes" in result, "Expected 'zip_size_bytes' key in result"
    assert isinstance(result["zip_size_bytes"], int), "zip_size_bytes should be int"
    assert result["zip_size_bytes"] > 0, (
        f"zip_size_bytes should be positive, got {result['zip_size_bytes']}"
    )


def test_sign_without_key_returns_error(tmp_path):
    """sign_with_trust_layer=True with empty trust_layer_key should return an error."""
    result = _annex4(tmp_path, sign_with_trust_layer=True, trust_layer_key="")
    assert "error" in result, (
        "Expected 'error' key when sign_with_trust_layer=True and trust_layer_key is empty"
    )


def test_generated_at_is_iso_format(tmp_path):
    """generated_at should be a parseable ISO datetime string."""
    result = _annex4(tmp_path)
    assert "generated_at" in result, "Expected 'generated_at' key in result"
    generated_at = result["generated_at"]
    try:
        datetime.fromisoformat(generated_at)
    except (ValueError, TypeError) as exc:
        pytest.fail(
            f"generated_at could not be parsed as ISO datetime: {generated_at!r} — {exc}"
        )
