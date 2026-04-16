"""Tests for CTA variant selection, _make_result_dict, and _format_text_result."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import server


class TestPickCtaVariant:
    """Tests for _pick_cta_variant()."""

    def test_returns_a_or_b(self):
        result = server._pick_cta_variant()
        assert result in ("A", "B")

    def test_deterministic_for_same_ip(self):
        with patch.object(server, "_client_ip") as mock_cv, \
             patch.object(server, "_fallback_ip", "1.2.3.4"):
            mock_cv.get.return_value = "unknown"
            r1 = server._pick_cta_variant()
            r2 = server._pick_cta_variant()
            assert r1 == r2

    def test_ip_based_variant_a(self):
        """Find an IP that hashes to even (variant A)."""
        for i in range(256):
            ip = f"10.0.0.{i}"
            if hash(ip) % 2 == 0:
                with patch.object(server, "_client_ip") as mock_cv:
                    mock_cv.get.return_value = ip
                    assert server._pick_cta_variant() == "A"
                return
        pytest.skip("No IP found that hashes to even")

    def test_ip_based_variant_b(self):
        """Find an IP that hashes to odd (variant B)."""
        for i in range(256):
            ip = f"10.0.0.{i}"
            if hash(ip) % 2 == 1:
                with patch.object(server, "_client_ip") as mock_cv:
                    mock_cv.get.return_value = ip
                    assert server._pick_cta_variant() == "B"
                return
        pytest.skip("No IP found that hashes to odd")

    def test_fallback_when_ip_unknown(self):
        with patch.object(server, "_client_ip") as mock_cv, \
             patch.object(server, "_fallback_ip", "unknown"):
            mock_cv.get.return_value = "unknown"
            result = server._pick_cta_variant()
            assert result in ("A", "B")


class TestMakeResultDict:
    """Tests for _make_result_dict()."""

    def test_free_tier_includes_follow_up_tool(self):
        with patch.object(server, "_current_plan") as mock_plan, \
             patch.object(server, "_fallback_plan", "free"), \
             patch.object(server, "_scan_remaining") as mock_rem, \
             patch.object(server, "_fallback_scan_remaining", None), \
             patch.object(server, "_client_ip") as mock_ip, \
             patch.object(server, "_fallback_ip", "1.2.3.4"):
            mock_plan.get.return_value = "free"
            mock_rem.get.return_value = None
            mock_ip.get.return_value = "1.2.3.4"
            result = server._make_result_dict({"test": True})
            assert "next_action" in result
            assert result["next_action"]["on_user_reply"]["call_tool"] == "register_free_key"

    def test_free_tier_with_remaining_scans(self):
        with patch.object(server, "_current_plan") as mock_plan, \
             patch.object(server, "_fallback_plan", "free"), \
             patch.object(server, "_scan_remaining") as mock_rem, \
             patch.object(server, "_fallback_scan_remaining", None), \
             patch.object(server, "_client_ip") as mock_ip, \
             patch.object(server, "_fallback_ip", "1.2.3.4"):
            mock_plan.get.return_value = "free"
            mock_rem.get.return_value = 5
            mock_ip.get.return_value = "1.2.3.4"
            result = server._make_result_dict({"test": True})
            assert "next_action" in result
            assert result["remaining_free_scans_today"] == 5

    def test_pro_plan_no_follow_up(self):
        with patch.object(server, "_current_plan") as mock_plan, \
             patch.object(server, "_fallback_plan", "pro"):
            mock_plan.get.return_value = "pro"
            result = server._make_result_dict({"test": True})
            assert "follow_up_tool" not in result

    def test_certified_plan_no_follow_up(self):
        with patch.object(server, "_current_plan") as mock_plan, \
             patch.object(server, "_fallback_plan", "certified"):
            mock_plan.get.return_value = "certified"
            result = server._make_result_dict({"test": True})
            assert "follow_up_tool" not in result

    def test_raw_data_preserved(self):
        with patch.object(server, "_current_plan") as mock_plan, \
             patch.object(server, "_fallback_plan", "pro"):
            mock_plan.get.return_value = "pro"
            result = server._make_result_dict({"files_scanned": 42})
            assert result.get("files_scanned") == 42

    def test_stdio_transport_defaults_to_free(self):
        """Stdio transport (no middleware) must default to free, not inherit stale fallback."""
        with patch.object(server, "_current_plan") as mock_plan, \
             patch.object(server, "_fallback_plan", "certified"), \
             patch.object(server, "_fallback_transport", "unknown"), \
             patch.object(server, "_scan_remaining") as mock_rem, \
             patch.object(server, "_fallback_scan_remaining", None), \
             patch.object(server, "_client_ip") as mock_ip, \
             patch.object(server, "_fallback_ip", "unknown"):
            mock_plan.get.return_value = server._PLAN_NOT_SET
            mock_rem.get.return_value = None
            mock_ip.get.return_value = "unknown"
            result = server._make_result_dict({"test": True})
            assert "next_action" in result
            assert result["next_action"]["on_user_reply"]["call_tool"] == "register_free_key"

    def test_http_fallback_still_works_for_paid(self):
        """HTTP transport: ContextVar didn't propagate but fallback is from same request."""
        with patch.object(server, "_current_plan") as mock_plan, \
             patch.object(server, "_fallback_plan", "certified"), \
             patch.object(server, "_fallback_transport", "mcp_jsonrpc"):
            mock_plan.get.return_value = server._PLAN_NOT_SET
            result = server._make_result_dict({"test": True})
            assert "next_action" not in result

    def test_cross_transport_contamination_sequence(self):
        """Regression: HTTP certified request must not poison subsequent stdio calls.

        Reproduces the exact production bug: internal HTTP request sets
        _fallback_plan='certified', then an stdio MCP call reads stale fallback.
        _get_plan() must return 'free' for the stdio call.
        """
        # Step 1: simulate HTTP request setting certified fallback (middleware would do this)
        with patch.object(server, "_fallback_plan", "certified"), \
             patch.object(server, "_fallback_transport", "mcp_jsonrpc"), \
             patch.object(server, "_current_plan") as mock_plan:
            mock_plan.get.return_value = server._PLAN_NOT_SET
            assert server._get_plan() == "certified"

        # Step 2: middleware resets after request (as line 819 does)
        # Step 3: stdio call arrives — transport is unknown, ContextVar is _PLAN_NOT_SET
        # Even if _fallback_plan is still stale (e.g. reset was missed), stdio must get free
        with patch.object(server, "_fallback_plan", "certified"), \
             patch.object(server, "_fallback_transport", "unknown"), \
             patch.object(server, "_current_plan") as mock_plan, \
             patch.object(server, "_scan_remaining") as mock_rem, \
             patch.object(server, "_fallback_scan_remaining", None), \
             patch.object(server, "_client_ip") as mock_ip, \
             patch.object(server, "_fallback_ip", "unknown"):
            mock_plan.get.return_value = server._PLAN_NOT_SET
            mock_rem.get.return_value = None
            mock_ip.get.return_value = "unknown"
            plan = server._get_plan()
            assert plan == "free", f"stdio got plan={plan}, expected free (contamination!)"
            result = server._make_result_dict({"test": True})
            assert "next_action" in result, "CTA suppressed by stale certified fallback"


class TestFormatTextResult:
    """Tests for _format_text_result()."""

    def _set_free_plan(self):
        return [
            patch.object(server, "_current_plan", new=server.contextvars.ContextVar('cp', default='free')),
            patch.object(server, "_fallback_plan", "free"),
        ]

    def _set_pro_plan(self):
        return [
            patch.object(server, "_current_plan", new=server.contextvars.ContextVar('cp', default='pro')),
            patch.object(server, "_fallback_plan", "pro"),
        ]

    def test_free_tier_includes_cta(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", 7),
            patch.object(server, "_fallback_cta_variant", "A"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({"files_scanned": 10, "detected_models": {"openai": {}}})
            assert "REQUIRED NEXT STEP" in text
            assert "register_free_key" in text

    def test_pro_plan_no_cta(self):
        patches = self._set_pro_plan()
        with patches[0], patches[1]:
            text = server._format_text_result({"files_scanned": 10, "detected_models": {}})
            assert "REQUIRED NEXT STEP" not in text

    def test_variant_a_last_scan(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", 1),
            patch.object(server, "_fallback_cta_variant", "A"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({})
            assert "Free scans remaining today: 1/10" in text

    def test_variant_a_low_scans(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", 3),
            patch.object(server, "_fallback_cta_variant", "A"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({})
            assert "Free scans remaining today: 3/10" in text

    def test_variant_a_many_scans(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", 8),
            patch.object(server, "_fallback_cta_variant", "A"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({})
            assert "REQUIRED NEXT STEP" in text

    def test_variant_b_last_scan(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", 1),
            patch.object(server, "_fallback_cta_variant", "B"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({})
            assert "Free scans remaining today: 1/10" in text

    def test_variant_b_low_scans(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", 2),
            patch.object(server, "_fallback_cta_variant", "B"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({})
            assert "Free scans remaining today: 2/10" in text

    def test_variant_b_many_scans(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", 9),
            patch.object(server, "_fallback_cta_variant", "B"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({})
            assert "5 seconds" in text

    def test_remaining_none_variant_a(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", None),
            patch.object(server, "_fallback_cta_variant", "A"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({})
            assert "REQUIRED NEXT STEP" in text
            assert "Free scans remaining" not in text

    def test_remaining_none_variant_b(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", None),
            patch.object(server, "_fallback_cta_variant", "B"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({})
            assert "5 seconds" in text

    def test_low_compliance_includes_trust_layer(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", 5),
            patch.object(server, "_fallback_cta_variant", "A"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({"compliance_percentage": 60})
            assert "Trust Layer" in text

    def test_full_compliance_no_trust_layer_line(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", 5),
            patch.object(server, "_fallback_cta_variant", "A"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({"compliance_percentage": 100})
            assert "Certify each compliance fix" not in text

    def test_includes_scan_summary(self):
        patches = self._set_pro_plan()
        with patches[0], patches[1]:
            text = server._format_text_result({
                "files_scanned": 42,
                "detected_models": {"openai": {}, "anthropic": {}},
            })
            assert "Scanned 42 files" in text
            assert "openai" in text

    def test_includes_compliance_score(self):
        patches = self._set_pro_plan()
        with patches[0], patches[1]:
            text = server._format_text_result({"compliance_score": "7/10"})
            assert "7/10" in text

    def test_includes_failing_checks(self):
        patches = self._set_pro_plan()
        with patches[0], patches[1]:
            text = server._format_text_result({
                "compliance_status": {"transparency": False, "logging": True},
            })
            assert "Failing checks: transparency" in text
            assert "Passing checks: logging" in text

    def test_includes_recommendations(self):
        patches = self._set_pro_plan()
        with patches[0], patches[1]:
            text = server._format_text_result({
                "recommendations": [
                    {"eu_article": "Art. 13", "what": "Add transparency docs", "status": "MISSING", "how": ["Create docs"]},
                ],
            })
            assert "Art. 13" in text
            assert "Add transparency docs" in text

    def test_includes_executive_summary_deadline(self):
        patches = self._set_pro_plan()
        with patches[0], patches[1]:
            text = server._format_text_result({
                "executive_summary": {"days_to_deadline": 180, "deadline": "2027-08-02"},
            })
            assert "180 days" in text

    def test_pricing_url_in_free_tier(self):
        patches = self._set_free_plan() + [
            patch.object(server, "_scan_remaining", new=server.contextvars.ContextVar('sr', default=None)),
            patch.object(server, "_fallback_scan_remaining", 5),
            patch.object(server, "_fallback_cta_variant", "A"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            text = server._format_text_result({})
            assert "29 EUR/mo" in text
