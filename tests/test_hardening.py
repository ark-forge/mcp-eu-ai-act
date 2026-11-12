"""Hardening tests for the dedicated-user deployment (C3-CODE)."""

import json
import logging
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import server as server_module
from server import ApiKeyManager

STUB_VAULT = '''
import json, os
from pathlib import Path

VAULT_FILE = Path("/nonexistent/vault.json.enc")
seen = []


class _Vault:
    def get_section(self, name):
        seen.append((str(VAULT_FILE), os.environ.get("VAULT_MASTER_KEY")))
        if os.environ.get("VAULT_MASTER_KEY") != "stub-master-key":
            raise RuntimeError("bad master key")
        return json.loads(Path(VAULT_FILE).read_text()).get(name)


vault = _Vault()
'''


def _manager(tmp_path):
    return ApiKeyManager(path=tmp_path / "root_keys.json", data_path=tmp_path / "data" / "api_keys.json")


def test_api_keys_file_is_group_readable_after_write(tmp_path):
    old = os.umask(0o077)
    try:
        mgr = _manager(tmp_path)
        entry = mgr.register_key("a@example.com")
        data_file = tmp_path / "data" / "api_keys.json"
        assert stat.S_IMODE(data_file.stat().st_mode) == 0o660
        data_file.chmod(0o600)
        mgr.increment_scans(entry["key"])
        assert stat.S_IMODE(data_file.stat().st_mode) == 0o660
    finally:
        os.umask(old)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_unreadable_root_api_keys_does_not_crash(tmp_path, caplog):
    root_file = tmp_path / "root_keys.json"
    root_file.write_text(json.dumps({"keys": [{"key": "k1", "active": True}]}))
    root_file.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="server"):
            mgr = _manager(tmp_path)
        assert mgr.verify("k1") is None
        warns = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert warns and str(root_file) in warns[0].getMessage()
        assert "k1" not in caplog.text
    finally:
        root_file.chmod(0o600)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_unreadable_data_api_keys_logs_error(tmp_path, caplog):
    data_file = tmp_path / "data" / "api_keys.json"
    data_file.parent.mkdir()
    data_file.write_text("{}")
    data_file.chmod(0o000)
    try:
        with caplog.at_level(logging.ERROR, logger="server"):
            mgr = _manager(tmp_path)
        assert mgr._keys == {}
        assert [r for r in caplog.records if r.levelno == logging.ERROR]
    finally:
        data_file.chmod(0o600)


def test_missing_api_keys_files_are_silent(tmp_path, caplog):
    with caplog.at_level(logging.DEBUG, logger="server"):
        _manager(tmp_path)
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.fixture
def wrapper(monkeypatch):
    import api_wrapper.main as main_mod
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    for m in [m for m in sys.modules if m == "automation" or m.startswith("automation.")]:
        monkeypatch.delitem(sys.modules, m)
    yield main_mod
    for m in [m for m in sys.modules if m == "automation" or m.startswith("automation.")]:
        sys.modules.pop(m, None)
    sys.path[:] = [p for p in sys.path if "vault_parent" not in p]


def _vault_parent(tmp_path):
    parent = tmp_path / "vault_parent"
    (parent / "automation").mkdir(parents=True)
    (parent / "automation" / "__init__.py").write_text("")
    (parent / "automation" / "vault.py").write_text(STUB_VAULT)
    return parent


def _creds(tmp_path, stripe_section):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "vault.json.enc").write_text(json.dumps({"stripe": stripe_section}))
    (creds / "vault_key").write_text("stub-master-key\n")
    return creds


FULL_SECTION = {
    "mode": "live",
    "live_secret_key": "sk_live_stub",
    "mcp_webhook_secret": "whsec_stub",
    "mcp_pro_price_id": "price_pro_stub",
    "mcp_certified_price_id": "price_cert_stub",
}


def test_stripe_loaded_from_credentials_directory(tmp_path, wrapper, monkeypatch):
    parent = _vault_parent(tmp_path)
    creds = _creds(tmp_path, FULL_SECTION)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_from_env_must_not_win")
    cfg = wrapper._load_stripe_config(vault_parent=str(parent))
    assert cfg == {
        "secret_key": "sk_live_stub",
        "webhook_secret": "whsec_stub",
        "price_pro": "price_pro_stub",
        "price_certified": "price_cert_stub",
    }
    assert "VAULT_MASTER_KEY" not in os.environ
    vault_mod = sys.modules["automation.vault"]
    assert vault_mod.seen == [(str(creds / "vault.json.enc"), "stub-master-key")]


@pytest.mark.parametrize("section", [{}, None, {"mode": "live"}], ids=["empty", "null", "no-secret-key"])
def test_empty_stripe_section_under_credentials_fails_closed(tmp_path, wrapper, monkeypatch, section):
    parent = _vault_parent(tmp_path)
    creds = _creds(tmp_path, section)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_from_env_must_not_win")
    with pytest.raises(RuntimeError) as exc:
        wrapper._load_stripe_config(vault_parent=str(parent))
    assert "sk_from_env_must_not_win" not in str(exc.value)
    assert "VAULT_MASTER_KEY" not in os.environ


def test_unreadable_vault_under_credentials_fails_closed(tmp_path, wrapper, monkeypatch):
    parent = _vault_parent(tmp_path)
    creds = _creds(tmp_path, FULL_SECTION)
    (creds / "vault_key").write_text("wrong-key-value\n")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    with pytest.raises(RuntimeError) as exc:
        wrapper._load_stripe_config(vault_parent=str(parent))
    assert "wrong-key-value" not in str(exc.value)
    assert "VAULT_MASTER_KEY" not in os.environ


def test_without_credentials_behaviour_unchanged(tmp_path, wrapper, monkeypatch):
    # No vault importable -> environment fallback, as before the lot.
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_env")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "wh_env")
    monkeypatch.setenv("STRIPE_PRICE_PRO", "p_env")
    monkeypatch.setenv("STRIPE_PRICE_CERTIFIED", "c_env")
    empty = tmp_path / "empty_parent"
    empty.mkdir()
    assert wrapper._load_stripe_config(vault_parent=str(empty)) == {
        "secret_key": "sk_env",
        "webhook_secret": "wh_env",
        "price_pro": "p_env",
        "price_certified": "c_env",
    }


def test_without_credentials_vault_section_still_used(tmp_path, wrapper, monkeypatch):
    # Vault importable, no CREDENTIALS_DIRECTORY: section read as before, no env key set.
    parent = _vault_parent(tmp_path)
    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps({"stripe": FULL_SECTION}))
    monkeypatch.setenv("VAULT_MASTER_KEY", "stub-master-key")
    sys.path.insert(0, str(parent))
    import importlib
    vault_mod = importlib.import_module("automation.vault")
    vault_mod.VAULT_FILE = plain
    cfg = wrapper._load_stripe_config(vault_parent=str(parent))
    assert cfg["secret_key"] == "sk_live_stub"
    assert os.environ["VAULT_MASTER_KEY"] == "stub-master-key"


def test_load_json_logs_error_on_unreadable_file(tmp_path, wrapper, caplog):
    if os.geteuid() == 0:
        pytest.skip("root ignores file modes")
    f = tmp_path / "k.json"
    f.write_text("{}")
    f.chmod(0o000)
    try:
        with caplog.at_level(logging.ERROR):
            assert wrapper._load_json(f, {"d": 1}) == {"d": 1}
        assert [r for r in caplog.records if r.levelno == logging.ERROR]
    finally:
        f.chmod(0o600)
