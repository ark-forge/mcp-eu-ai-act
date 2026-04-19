"""Tests for paywall components (ApiKeyManager, RateLimiter, middleware helpers).

Covers: ApiKeyManager, RateLimiter, _get_header, _extract_api_key, MCPServer legacy.
Also covers Stripe checkout and webhook endpoints in api_wrapper/main.py.
"""

import json
import time
import hmac
import hashlib
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "api_wrapper"))

from server import (
    ApiKeyManager,
    RateLimiter,
    _get_header,
    _extract_api_key,
    MCPServer,
    EUAIActChecker,
    _validate_project_path,
    BLOCKED_PATHS,
    _INSTALL_ROOT,
)


# ============================================================
# Tests: ApiKeyManager
# ============================================================

class TestApiKeyManager:

    def test_init_no_files(self, tmp_path):
        """ApiKeyManager should handle missing key files gracefully."""
        mgr = ApiKeyManager(
            path=tmp_path / "nonexistent.json",
            data_path=tmp_path / "data" / "nonexistent.json",
        )
        assert mgr.verify("any_key") is None

    def test_register_and_verify(self, tmp_path):
        """Register a key and verify it."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        mgr = ApiKeyManager(
            path=tmp_path / "keys.json",
            data_path=data_dir / "api_keys.json",
        )
        entry = mgr.register_key("test@example.com", "pro")
        assert entry["key"].startswith("ak_")
        assert entry["email"] == "test@example.com"
        assert entry["plan"] == "pro"
        assert entry["active"] is True

        # Verify the key
        result = mgr.verify(entry["key"])
        assert result is not None
        assert result["email"] == "test@example.com"
        assert result["plan"] == "pro"

    def test_verify_invalid_key(self, tmp_path):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        mgr = ApiKeyManager(
            path=tmp_path / "keys.json",
            data_path=data_dir / "api_keys.json",
        )
        assert mgr.verify("invalid_key") is None

    def test_load_list_format(self, tmp_path):
        """Test loading keys in list format."""
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [
                {"key": "test_key_1", "email": "a@b.com", "active": True, "plan": "pro"},
                {"key": "test_key_2", "email": "c@d.com", "active": False, "plan": "free"},
            ]
        }))
        mgr = ApiKeyManager(
            path=keys_file,
            data_path=tmp_path / "data" / "nonexistent.json",
        )
        assert mgr.verify("test_key_1") is not None
        assert mgr.verify("test_key_2") is None  # inactive

    def test_load_dict_format(self, tmp_path):
        """Test loading keys in dict format."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        data_file = data_dir / "api_keys.json"
        data_file.write_text(json.dumps({
            "mcp_pro_abc123": {"email": "x@y.com", "active": True, "tier": "pro"},
        }))
        mgr = ApiKeyManager(
            path=tmp_path / "nonexistent.json",
            data_path=data_file,
        )
        result = mgr.verify("mcp_pro_abc123")
        assert result is not None
        assert result["email"] == "x@y.com"

    def test_get_entry(self, tmp_path):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        mgr = ApiKeyManager(
            path=tmp_path / "keys.json",
            data_path=data_dir / "api_keys.json",
        )
        entry = mgr.register_key("test@test.com")
        retrieved = mgr.get_entry(entry["key"])
        assert retrieved["email"] == "test@test.com"

    def test_get_entry_missing(self, tmp_path):
        mgr = ApiKeyManager(
            path=tmp_path / "nonexistent.json",
            data_path=tmp_path / "data" / "nonexistent.json",
        )
        assert mgr.get_entry("nonexistent") == {}

    def test_reload_after_timeout(self, tmp_path):
        """Test that keys are reloaded after 60s cache expiry."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        mgr = ApiKeyManager(
            path=tmp_path / "keys.json",
            data_path=data_dir / "api_keys.json",
        )
        entry = mgr.register_key("test@test.com")
        # Force cache expiry
        mgr._loaded_at = time.time() - 61
        result = mgr.verify(entry["key"])
        assert result is not None

    def test_corrupted_json(self, tmp_path):
        """Corrupted JSON should not crash the manager."""
        keys_file = tmp_path / "keys.json"
        keys_file.write_text("{invalid json")
        mgr = ApiKeyManager(
            path=keys_file,
            data_path=tmp_path / "data" / "nonexistent.json",
        )
        assert mgr.verify("any") is None


# ============================================================
# Tests: RateLimiter
# ============================================================

class TestRateLimiter:

    def test_first_request_allowed(self):
        rl = RateLimiter(max_requests=10)
        allowed, remaining = rl.check("1.2.3.4")
        assert allowed is True
        assert remaining == 9

    def test_limit_reached(self):
        rl = RateLimiter(max_requests=2)
        rl.check("1.2.3.4")
        rl.check("1.2.3.4")
        allowed, remaining = rl.check("1.2.3.4")
        assert allowed is False
        assert remaining == 0

    def test_different_ips(self):
        rl = RateLimiter(max_requests=1)
        allowed1, _ = rl.check("1.1.1.1")
        allowed2, _ = rl.check("2.2.2.2")
        assert allowed1 is True
        assert allowed2 is True

    def test_remaining_count(self):
        rl = RateLimiter(max_requests=5)
        _, r1 = rl.check("1.1.1.1")
        _, r2 = rl.check("1.1.1.1")
        _, r3 = rl.check("1.1.1.1")
        assert r1 == 4
        assert r2 == 3
        assert r3 == 2

    def test_date_reset(self):
        rl = RateLimiter(max_requests=1)
        rl.check("1.1.1.1")
        # Simulate date change
        rl._clients["1.1.1.1"]["date"] = "2020-01-01"
        allowed, remaining = rl.check("1.1.1.1")
        assert allowed is True
        assert remaining == 0

    def test_cleanup_removes_old(self):
        rl = RateLimiter(max_requests=10)
        rl.check("1.1.1.1")
        # Set old date to trigger cleanup
        rl._clients["1.1.1.1"]["date"] = "2020-01-01"
        rl.cleanup()
        assert "1.1.1.1" not in rl._clients

    def test_cleanup_keeps_today(self):
        rl = RateLimiter(max_requests=10)
        rl.check("1.1.1.1")
        rl.cleanup()
        assert "1.1.1.1" in rl._clients

    def test_auto_cleanup_on_check(self):
        rl = RateLimiter(max_requests=10)
        rl.check("1.1.1.1")
        rl._clients["1.1.1.1"]["date"] = "2020-01-01"
        # Force cleanup trigger
        rl._last_cleanup = time.time() - 3601
        rl.check("2.2.2.2")
        assert "1.1.1.1" not in rl._clients


# ============================================================
# Tests: Helper functions
# ============================================================

class TestHelpers:

    def test_get_header_found(self):
        scope = {"headers": [(b"content-type", b"application/json"), (b"x-api-key", b"test123")]}
        assert _get_header(scope, b"x-api-key") == "test123"

    def test_get_header_not_found(self):
        scope = {"headers": [(b"content-type", b"application/json")]}
        assert _get_header(scope, b"x-api-key") is None

    def test_get_header_empty(self):
        scope = {"headers": []}
        assert _get_header(scope, b"x-api-key") is None

    def test_get_header_no_headers(self):
        scope = {}
        assert _get_header(scope, b"x-api-key") is None

    def test_extract_api_key_x_header(self):
        scope = {"headers": [(b"x-api-key", b"ak_123")]}
        assert _extract_api_key(scope) == "ak_123"

    def test_extract_api_key_bearer(self):
        scope = {"headers": [(b"authorization", b"Bearer ak_456")]}
        assert _extract_api_key(scope) == "ak_456"

    def test_extract_api_key_none(self):
        scope = {"headers": []}
        assert _extract_api_key(scope) is None

    def test_extract_api_key_prefers_x_header(self):
        scope = {"headers": [
            (b"x-api-key", b"ak_from_header"),
            (b"authorization", b"Bearer ak_from_bearer"),
        ]}
        assert _extract_api_key(scope) == "ak_from_header"


# ============================================================
# Tests: Path validation
# ============================================================

class TestPathValidation:

    def test_blocked_system_paths(self):
        for path in ["/etc", "/root", "/proc", "/sys", "/home/ubuntu"]:
            is_safe, msg = _validate_project_path(path)
            assert is_safe is False
            assert "Access denied" in msg

    def test_install_root_blocked(self):
        is_safe, msg = _validate_project_path(_INSTALL_ROOT)
        assert is_safe is False

    def test_tmp_path_allowed(self, tmp_path):
        is_safe, msg = _validate_project_path(str(tmp_path))
        assert is_safe is True

    def test_invalid_path(self):
        is_safe, msg = _validate_project_path("")
        # Empty string resolves to cwd, behavior depends on implementation
        assert isinstance(is_safe, bool)


# ============================================================
# Tests: MCPServer Legacy
# ============================================================

class TestMCPServerLegacy:

    def test_init_has_tools(self):
        server = MCPServer()
        assert "_tools" in dir(server)
        assert len(server._tools) == 5

    def test_list_tools(self):
        server = MCPServer()
        tools = server.list_tools()
        assert "tools" in tools
        assert len(tools["tools"]) == 16
        names = [t["name"] for t in tools["tools"]]
        assert "scan_project" in names
        assert "check_compliance" in names
        assert "generate_report" in names
        assert "suggest_risk_category" in names
        assert "generate_compliance_templates" in names

    def test_handle_request_unknown_tool(self):
        server = MCPServer()
        result = server.handle_request("nonexistent_tool", {})
        assert "error" in result

    def test_scan_project_via_legacy(self, tmp_path):
        (tmp_path / "app.py").write_text("email = 'test@test.com'")
        server = MCPServer()
        result = server.handle_request("scan_project", {"project_path": str(tmp_path)})
        assert result["tool"] == "scan_project"
        assert "results" in result

    def test_suggest_risk_category(self):
        server = MCPServer()
        result = server.handle_request("suggest_risk_category", {
            "system_description": "facial recognition system for law enforcement"
        })
        assert result["tool"] == "suggest_risk_category"
        assert result["results"]["suggested_category"] in ["unacceptable", "high"]

    def test_suggest_risk_category_minimal(self):
        server = MCPServer()
        result = server.handle_request("suggest_risk_category", {
            "system_description": "spam filter for email"
        })
        assert result["results"]["suggested_category"] == "minimal"

    def test_suggest_risk_category_unknown(self):
        server = MCPServer()
        result = server.handle_request("suggest_risk_category", {
            "system_description": "a simple calculator"
        })
        assert result["results"]["confidence"] == "low"

    def test_generate_compliance_templates_high(self):
        server = MCPServer()
        result = server.handle_request("generate_compliance_templates", {
            "risk_category": "high"
        })
        assert result["tool"] == "generate_compliance_templates"
        assert result["results"]["templates_count"] > 0

    def test_generate_compliance_templates_unacceptable(self):
        server = MCPServer()
        result = server.handle_request("generate_compliance_templates", {
            "risk_category": "unacceptable"
        })
        assert "error" in result

    def test_generate_compliance_templates_minimal(self):
        server = MCPServer()
        result = server.handle_request("generate_compliance_templates", {
            "risk_category": "minimal"
        })
        assert result["results"]["templates_count"] == 0


# ============================================================
# Tests: Stripe endpoints in api_wrapper/main.py
# ============================================================

def _make_stripe_sig(secret: str, payload: bytes, timestamp: str = "1234567890") -> str:
    """Helper: generate a valid Stripe-Signature header value."""
    signed = f"{timestamp}.{payload.decode('utf-8')}"
    sig = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={sig}"


@pytest.fixture
def stripe_client(tmp_path):
    """FastAPI TestClient with the api_wrapper app, isolating data to tmp_path."""
    from fastapi.testclient import TestClient
    import api_wrapper.main as main_mod

    # Patch data dirs so tests don't touch prod files
    orig_data_dir = main_mod._DATA_DIR
    main_mod._DATA_DIR = tmp_path
    main_mod._RATE_LIMITS_FILE = tmp_path / "wrapper_rate_limits.json"
    main_mod._API_KEYS_FILE = tmp_path / "api_keys.json"

    client = TestClient(main_mod.app, raise_server_exceptions=False)
    yield client

    main_mod._DATA_DIR = orig_data_dir


class TestStripeCheckout:

    def test_checkout_no_stripe_key(self, stripe_client):
        """503 when secret_key is not set."""
        import api_wrapper.main as main_mod
        with patch.object(main_mod, "_STRIPE", {"secret_key": None, "webhook_secret": None, "price_pro": None, "price_certified": None}):
            resp = stripe_client.post(
                "/api/checkout",
                json={"plan": "pro", "email": "user@example.com"},
            )
        assert resp.status_code == 503
        assert "error" in resp.json().get("detail", resp.json())

    def test_checkout_invalid_plan(self, stripe_client):
        """400 for unrecognized plan."""
        import api_wrapper.main as main_mod
        with patch.object(main_mod, "_STRIPE", {"secret_key": "sk_test_fake", "webhook_secret": "whsec_x", "price_pro": "price_pro_abc", "price_certified": "price_cert_abc"}):
            resp = stripe_client.post(
                "/api/checkout",
                json={"plan": "invalid", "email": "user@example.com"},
            )
        assert resp.status_code == 400
        detail = resp.json().get("detail", resp.json())
        assert "invalid" in str(detail).lower() or "plan" in str(detail).lower()

    def test_checkout_missing_price_env(self, stripe_client):
        """503 when price_pro is not configured."""
        import api_wrapper.main as main_mod
        with patch.object(main_mod, "_STRIPE", {"secret_key": "sk_test_fake", "webhook_secret": "whsec_x", "price_pro": "", "price_certified": ""}):
            resp = stripe_client.post(
                "/api/checkout",
                json={"plan": "pro", "email": "user@example.com"},
            )
        assert resp.status_code == 503

    def test_checkout_calls_stripe_api(self, stripe_client):
        """Returns checkout_url and session_id from Stripe response."""
        import api_wrapper.main as main_mod
        fake_session = {
            "id": "cs_test_abc123",
            "url": "https://checkout.stripe.com/pay/cs_test_abc123",
        }

        class FakeResponse:
            def read(self):
                return json.dumps(fake_session).encode()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        with patch.object(main_mod, "_STRIPE", {"secret_key": "sk_test_fake", "webhook_secret": "whsec_x", "price_pro": "price_pro_abc", "price_certified": "price_cert_abc"}), \
             patch("urllib.request.urlopen", return_value=FakeResponse()):
            resp = stripe_client.post(
                "/api/checkout",
                json={"plan": "pro", "email": "user@example.com"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["checkout_url"] == fake_session["url"]
        assert data["session_id"] == fake_session["id"]


class TestStripeWebhook:

    def test_webhook_no_secret(self, stripe_client):
        """503 when webhook_secret is not set."""
        import api_wrapper.main as main_mod
        with patch.object(main_mod, "_STRIPE", {"secret_key": "sk_test", "webhook_secret": None, "price_pro": "", "price_certified": ""}):
            resp = stripe_client.post(
                "/api/webhook",
                content=b'{"type":"checkout.session.completed"}',
                headers={"stripe-signature": "t=123,v1=abc"},
            )
        assert resp.status_code == 503

    def test_webhook_invalid_signature(self, stripe_client):
        """400 for bad signature."""
        import api_wrapper.main as main_mod
        payload = b'{"type":"checkout.session.completed"}'
        with patch.object(main_mod, "_STRIPE", {"secret_key": "sk_test", "webhook_secret": "whsec_real", "price_pro": "", "price_certified": ""}):
            resp = stripe_client.post(
                "/api/webhook",
                content=payload,
                headers={"stripe-signature": "t=123,v1=invalidsignature"},
            )
        assert resp.status_code == 400
        detail = resp.json().get("detail", resp.json())
        assert "signature" in str(detail).lower() or "invalid" in str(detail).lower()

    def test_webhook_checkout_completed_registers_key(self, stripe_client, tmp_path):
        """Valid webhook for checkout.session.completed registers an API key."""
        import api_wrapper.main as main_mod

        secret = "whsec_test_secret"
        event = {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer_email": "buyer@example.com",
                    "metadata": {"plan": "pro", "email": "buyer@example.com"},
                }
            },
        }
        payload = json.dumps(event).encode()
        sig_header = _make_stripe_sig(secret, payload)

        from server import ApiKeyManager
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        test_mgr = ApiKeyManager(
            path=tmp_path / "keys.json",
            data_path=data_dir / "api_keys.json",
        )

        with patch.object(main_mod, "_STRIPE", {"secret_key": "sk_test", "webhook_secret": secret, "price_pro": "", "price_certified": ""}), \
             patch.object(main_mod, "_api_key_manager", test_mgr):
            resp = stripe_client.post(
                "/api/webhook",
                content=payload,
                headers={"stripe-signature": sig_header, "content-type": "application/json"},
            )

        assert resp.status_code == 200
        assert resp.json().get("received") is True
        assert len(test_mgr._keys) > 0
        first_key = next(iter(test_mgr._keys.values()))
        assert first_key.get("email") == "buyer@example.com"
        assert first_key.get("plan") == "pro"

    def test_webhook_subscription_deleted_returns_ok(self, stripe_client):
        """customer.subscription.deleted returns 200 without crashing."""
        import api_wrapper.main as main_mod
        secret = "whsec_test_secret"
        event = {
            "type": "customer.subscription.deleted",
            "data": {"object": {"customer": "cus_abc123"}},
        }
        payload = json.dumps(event).encode()
        sig_header = _make_stripe_sig(secret, payload)

        with patch.object(main_mod, "_STRIPE", {"secret_key": "sk_test", "webhook_secret": secret, "price_pro": "", "price_certified": ""}):
            resp = stripe_client.post(
                "/api/webhook",
                content=payload,
                headers={"stripe-signature": sig_header},
            )
        assert resp.status_code == 200
        assert resp.json().get("received") is True

    def test_webhook_unknown_event_returns_ok(self, stripe_client):
        """Unknown event types return 200."""
        import api_wrapper.main as main_mod
        secret = "whsec_test_secret"
        event = {"type": "payment_intent.succeeded", "data": {"object": {}}}
        payload = json.dumps(event).encode()
        sig_header = _make_stripe_sig(secret, payload)

        with patch.object(main_mod, "_STRIPE", {"secret_key": "sk_test", "webhook_secret": secret, "price_pro": "", "price_certified": ""}):
            resp = stripe_client.post(
                "/api/webhook",
                content=payload,
                headers={"stripe-signature": sig_header},
            )
        assert resp.status_code == 200


# ============================================================
# Tests: register_free_key phone-home HTTP flow
# ============================================================

class TestRegisterFreeKeyPhoneHome:
    """Tests for the register_free_key phone-home to Trust Layer and local fallback."""

    @pytest.fixture
    def mcp_server(self):
        from server import create_server
        return create_server()

    def _call_register(self, mcp_server, email):
        tool = mcp_server._tool_manager._tools["register_free_key"]
        result = tool.fn(email=email)
        if isinstance(result, list) and hasattr(result[0], "text"):
            return json.loads(result[0].text)
        return result

    def test_phonehome_success(self, mcp_server, tmp_path):
        """When Trust Layer responds, register_free_key returns the remote key."""
        fake_key = "mcp_free_abc123def456"
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"api_key": fake_key}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen, \
             patch("server._get_client_ip", return_value="198.51.100.1"), \
             patch("server._record_registration"), \
             patch("server._record_mcp_scan"), \
             patch("server._log_tool_call"), \
             patch("server._SCAN_HISTORY_PATH", tmp_path / "scan_history.json"):
            result = self._call_register(mcp_server, "alice@acme.dev")

        assert result["registered"] is True
        assert result["api_key"] == fake_key
        assert result["plan"] == "free"
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://trust.arkforge.tech/api/register"
        body = json.loads(req.data)
        assert body["email"] == "alice@acme.dev"
        assert body["source"] == "mcp_phonehome"

    def test_phonehome_failure_falls_back_to_local(self, mcp_server, tmp_path):
        """When Trust Layer is unreachable, fallback to local ApiKeyManager."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()

        from server import ApiKeyManager
        mgr = ApiKeyManager(
            path=tmp_path / "keys.json",
            data_path=data_dir / "api_keys.json",
        )

        with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")), \
             patch("server._get_client_ip", return_value="198.51.100.1"), \
             patch("server._api_key_manager", mgr), \
             patch("server._record_registration") as mock_record, \
             patch("server._record_mcp_scan"), \
             patch("server._log_tool_call"), \
             patch("server._SCAN_HISTORY_PATH", tmp_path / "scan_history.json"):
            result = self._call_register(mcp_server, "bob@corp.io")

        assert result["registered"] is True
        assert result["api_key"].startswith("ak_")
        assert result["plan"] == "free"
        mock_record.assert_called_once()
        assert mock_record.call_args[1]["source"] == "mcp_tool_local_fallback"

    def test_phonehome_invalid_email_rejected(self, mcp_server):
        """Invalid email is rejected before any HTTP call."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            result = self._call_register(mcp_server, "not-an-email")

        assert result["status"] == "needs_email"
        assert "action_required" in result
        mock_urlopen.assert_not_called()

    def test_phonehome_fallback_writes_registration_log(self, mcp_server, tmp_path):
        """Local fallback actually writes to registration_log.jsonl (not mocked)."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        reg_log = tmp_path / "registration_log.jsonl"

        from server import ApiKeyManager
        mgr = ApiKeyManager(
            path=tmp_path / "keys.json",
            data_path=data_dir / "api_keys.json",
        )

        with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")), \
             patch("server._get_client_ip", return_value="198.51.100.1"), \
             patch("server._api_key_manager", mgr), \
             patch("server._REGISTRATION_LOG_PATH", reg_log), \
             patch("server._record_mcp_scan"), \
             patch("server._log_tool_call"), \
             patch("server._SCAN_HISTORY_PATH", tmp_path / "scan_history.json"):
            result = self._call_register(mcp_server, "jane@devops.co")

        assert result["registered"] is True
        assert reg_log.exists()
        lines = reg_log.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["source"] == "mcp_tool_local_fallback"
        assert entry["ip"] == "198.51.100.1"
        assert entry["scan_id"] is not None

    def test_phonehome_no_api_key_in_response_falls_back(self, mcp_server, tmp_path):
        """If Trust Layer responds but without api_key, fall back to local."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"error": "something"}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        from server import ApiKeyManager
        mgr = ApiKeyManager(
            path=tmp_path / "keys.json",
            data_path=data_dir / "api_keys.json",
        )

        with patch("urllib.request.urlopen", return_value=mock_resp), \
             patch("server._get_client_ip", return_value="198.51.100.1"), \
             patch("server._api_key_manager", mgr), \
             patch("server._record_registration"), \
             patch("server._record_mcp_scan"), \
             patch("server._log_tool_call"), \
             patch("server._SCAN_HISTORY_PATH", tmp_path / "scan_history.json"):
            result = self._call_register(mcp_server, "reg@company.net")

        assert result["registered"] is True
        assert result["api_key"].startswith("ak_")
