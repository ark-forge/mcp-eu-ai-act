"""Tests targeting uncovered pure functions to bring coverage above 80%."""

import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

import server
from server import (
    _detect_client_hint,
    _get_header,
    _is_automated_polling,
    _sanitize_email,
    _validate_email,
    _classify_ip,
    _require_plan,
    _track_unique_client,
    _record_registration,
    _compute_funnel_metrics,
    _tools_list_timestamps,
    ApiKeyManager,
    _is_anthropic_gateway,
)


class TestDetectClientHint:
    def _scope(self, ua: str) -> dict:
        return {"type": "http", "headers": [(b"user-agent", ua.encode())]}

    def test_claude_desktop(self):
        assert _detect_client_hint(self._scope("Claude-Desktop/1.2")) == "claude-desktop"

    def test_anthropic(self):
        assert _detect_client_hint(self._scope("Anthropic-SDK/0.3")) == "claude-desktop"

    def test_cursor(self):
        assert _detect_client_hint(self._scope("Cursor/0.44")) == "cursor"

    def test_continue(self):
        assert _detect_client_hint(self._scope("Continue/1.0")) == "continue"

    def test_cline(self):
        assert _detect_client_hint(self._scope("Cline/2.1")) == "cline"

    def test_browser(self):
        assert _detect_client_hint(self._scope("Mozilla/5.0 Chrome/120")) == "browser"

    def test_safari(self):
        assert _detect_client_hint(self._scope("Safari/605.1")) == "browser"

    def test_unknown_agent(self):
        assert _detect_client_hint(self._scope("some-bot/1.0")) == "unknown"

    def test_no_ua_header(self):
        assert _detect_client_hint({"type": "http", "headers": []}) == "unknown"

    def test_non_dict_scope(self):
        assert _detect_client_hint("not-a-dict") == "unknown"


class TestIsAutomatedPolling:
    def setup_method(self):
        _tools_list_timestamps.clear()

    def test_first_call_not_polling(self):
        assert _is_automated_polling("1.2.3.4") is False

    def test_many_calls_becomes_polling(self):
        for _ in range(20):
            _is_automated_polling("1.2.3.5")
        assert _is_automated_polling("1.2.3.5") is True

    def test_different_ips_independent(self):
        for _ in range(20):
            _is_automated_polling("1.2.3.6")
        assert _is_automated_polling("1.2.3.7") is False


class TestSanitizeEmail:
    def test_empty(self):
        assert _sanitize_email("") == ""

    def test_mailto_prefix(self):
        assert _sanitize_email("mailto:user@test.com") == "user@test.com"

    def test_email_prefix(self):
        assert _sanitize_email("email:user@test.com") == "user@test.com"

    def test_Email_prefix(self):
        assert _sanitize_email("Email: user@test.com") == "user@test.com"

    def test_angle_brackets(self):
        assert _sanitize_email("<user@test.com>") == "user@test.com"

    def test_embedded_in_text(self):
        assert _sanitize_email("my email is user@test.com ok") == "user@test.com"


class TestValidateEmail:
    def test_empty(self):
        assert _validate_email("") is not None

    def test_too_long(self):
        assert _validate_email("a" * 255 + "@test.com") is not None

    def test_disposable(self):
        result = _validate_email("user@mailinator.com")
        assert result is not None
        assert "disposable" in result.lower() or "temporary" in result.lower()

    def test_valid(self):
        assert _validate_email("user@legit-company.com") is None

    def test_bad_format(self):
        assert _validate_email("not-an-email") is not None


class TestClassifyIp:
    def test_empty_ip(self):
        assert _classify_ip("") == "internal"

    def test_unknown_ip(self):
        assert _classify_ip("unknown") == "stdio"

    def test_infra_ip(self):
        assert _classify_ip("57.131.27.61") == "internal"

    def test_private_range(self):
        assert _classify_ip("10.0.0.1") == "internal"

    def test_anthropic_gateway(self):
        assert _classify_ip("160.79.106.42") == "gateway"

    def test_datacenter_hetzner(self):
        assert _classify_ip("5.78.100.1") == "crawler"

    def test_external_ip(self):
        assert _classify_ip("8.8.8.8") == "external"


class TestIsAnthropicGateway:
    def test_gateway_ip(self):
        assert _is_anthropic_gateway("160.79.106.1") is True

    def test_non_gateway(self):
        assert _is_anthropic_gateway("8.8.8.8") is False


class TestRequirePlan:
    def test_sufficient_plan(self):
        with patch.object(server, "_get_plan", return_value="pro"):
            assert _require_plan("pro", "some_tool") is None

    def test_free_needs_pro(self):
        with patch.object(server, "_get_plan", return_value="free"):
            result = _require_plan("pro", "generate_compliance_roadmap")
            assert result is not None
            assert result["upgrade_required"] is True
            assert result["tool"] == "generate_compliance_roadmap"
            assert result["required_plan"] == "pro"
            assert "29 EUR" in result["message"]

    def test_free_needs_certified(self):
        with patch.object(server, "_get_plan", return_value="free"):
            result = _require_plan("certified", "certify_compliance_report")
            assert result is not None
            assert result["required_plan"] == "certified"
            assert "99 EUR" in result["message"]

    def test_annex4_package(self):
        with patch.object(server, "_get_plan", return_value="free"):
            result = _require_plan("pro", "generate_annex4_package")
            assert result is not None
            assert "Annex IV" in result["message"]

    def test_unknown_tool_fallback(self):
        with patch.object(server, "_get_plan", return_value="free"):
            result = _require_plan("pro", "some_unknown_tool")
            assert result is not None
            assert result["upgrade_required"] is True


class TestTrackUniqueClient:
    def test_non_external_source_skipped(self):
        with patch.object(server, "_UNIQUE_CLIENTS_PATH", Path("/tmp/test_unique_noop.json")):
            _track_unique_client("1.2.3.4", "internal", "unknown")
            assert not Path("/tmp/test_unique_noop.json").exists()

    def test_external_source_tracked(self, tmp_path):
        clients_path = tmp_path / "unique.json"
        with patch.object(server, "_UNIQUE_CLIENTS_PATH", clients_path):
            _track_unique_client("1.2.3.4", "external", "claude-desktop")
            assert clients_path.exists()
            data = json.loads(clients_path.read_text())
            today_data = list(data.values())[0]
            assert today_data["count"] == 1

    def test_stdio_source_tracked(self, tmp_path):
        clients_path = tmp_path / "unique.json"
        with patch.object(server, "_UNIQUE_CLIENTS_PATH", clients_path):
            _track_unique_client("unknown", "stdio", "unknown")
            assert clients_path.exists()

    def test_mcp_session_changes_ident(self, tmp_path):
        clients_path = tmp_path / "unique.json"
        with patch.object(server, "_UNIQUE_CLIENTS_PATH", clients_path):
            _track_unique_client("1.2.3.4", "external", "cursor", "session-abc")
            _track_unique_client("1.2.3.4", "external", "cursor", "session-def")
            data = json.loads(clients_path.read_text())
            today_data = list(data.values())[0]
            assert today_data["count"] == 2

    def test_duplicate_ip_not_counted_twice(self, tmp_path):
        clients_path = tmp_path / "unique.json"
        with patch.object(server, "_UNIQUE_CLIENTS_PATH", clients_path):
            _track_unique_client("1.2.3.4", "external", "cursor")
            _track_unique_client("1.2.3.4", "external", "cursor")
            data = json.loads(clients_path.read_text())
            today_data = list(data.values())[0]
            assert today_data["count"] == 1


class TestRecordRegistration:
    def test_records_entry(self, tmp_path):
        log_path = tmp_path / "reg.jsonl"
        with patch.object(server, "_REGISTRATION_LOG_PATH", log_path):
            _record_registration(email="a@b.com", source="test", ip="1.2.3.4", api_key="ak_test123")
            lines = log_path.read_text().strip().split("\n")
            assert len(lines) == 1
            entry = json.loads(lines[0])
            assert entry["source"] == "test"
            assert entry["api_key_prefix"].startswith("ak_test123")


class TestComputeFunnelMetrics:
    def test_returns_dict_with_empty_data(self, tmp_path):
        with patch.object(server, "_UNIQUE_CLIENTS_PATH", tmp_path / "none.json"), \
             patch.object(server, "_TOOL_CALL_LOG_PATH", tmp_path / "none.jsonl"), \
             patch.object(server, "_SCAN_HISTORY_PATH", tmp_path / "none2.json"), \
             patch.object(server, "_REGISTRATION_LOG_PATH", tmp_path / "none3.jsonl"):
            result = _compute_funnel_metrics()
            assert isinstance(result, dict)
            assert result["unique_users_today"] == 0
            assert result["unique_users_7d"] == 0


class TestApiKeyManagerRegisterAndIncrement:
    def test_register_and_increment(self, tmp_path):
        data_path = tmp_path / "data_keys.json"
        mgr = ApiKeyManager(path=tmp_path / "no.json", data_path=data_path)
        result = mgr.register_key("test@test.com", "pro")
        assert "key" in result
        assert result["plan"] == "pro"
        key = result["key"]
        assert mgr.verify(key) is not None
        mgr.increment_scans(key)
        data = json.loads(data_path.read_text())
        assert data[key]["scans_total"] == 1

    def test_increment_nonexistent_key(self, tmp_path):
        mgr = ApiKeyManager(path=tmp_path / "no.json", data_path=tmp_path / "no2.json")
        mgr.increment_scans("nonexistent_key")

    def test_get_entry_triggers_reload(self, tmp_path):
        data_path = tmp_path / "data_keys.json"
        mgr = ApiKeyManager(path=tmp_path / "no.json", data_path=data_path)
        result = mgr.register_key("t@t.com")
        mgr._loaded_at = 0
        entry = mgr.get_entry(result["key"])
        assert entry is not None
