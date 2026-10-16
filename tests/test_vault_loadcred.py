"""Stripe config when the API runs under its own system user.

The operator vault files are not readable by that user; systemd hands them over
as credentials (LoadCredential=vault.json.enc, vault_key). The master key must
not stay in the environment once the vault is loaded.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

FAKE_VAULT = '''
import json, os
from pathlib import Path
VAULT_FILE = Path("/nonexistent/vault.json.enc")
class _Vault:
    def get_section(self, name):
        if os.environ.get("VAULT_MASTER_KEY") != "mk-test":
            raise PermissionError("no master key")
        return json.loads(VAULT_FILE.read_text()).get(name, {})
vault = _Vault()
'''


def test_stripe_config_is_read_from_credentials(tmp_path, monkeypatch):
    from api_wrapper import main
    ops = tmp_path / "ops" / "automation"
    ops.mkdir(parents=True)
    (ops / "__init__.py").write_text("")
    (ops / "vault.py").write_text(FAKE_VAULT)
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "vault.json.enc").write_text(json.dumps(
        {"stripe": {"mode": "test", "test_secret_key": "sk_test_ci", "mcp_pro_price_id": "price_ci"}}))
    (creds / "vault_key").write_text("mk-test\n")

    monkeypatch.setenv("VAULT_PATH", str(tmp_path / "ops"))
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
    for m in [m for m in sys.modules if m == "automation" or m.startswith("automation.")]:
        monkeypatch.delitem(sys.modules, m)
    monkeypatch.setattr(sys, "path", list(sys.path))

    cfg = main._load_stripe_config()

    assert cfg["secret_key"] == "sk_test_ci"
    assert cfg["price_pro"] == "price_ci"
    assert "VAULT_MASTER_KEY" not in os.environ
