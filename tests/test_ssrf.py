"""SSRF tests for /api/v1/scan-repo (CWE-918).

Reported 2026-08-31 by Syed Anas Mohiuddin against commit 980e749: repo_url went
straight into `git clone` behind a single startswith("https://") check, and git's
stderr came back to the caller as a service-fingerprinting oracle.
"""

import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import server
from server import _is_public_address, _validate_repo_url, _scan_repo_url


def _fake_resolver(addr: str):
    """getaddrinfo stub that resolves every hostname to addr."""
    def resolve(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port))]
    return resolve


class TestIsPublicAddress:

    @pytest.mark.parametrize("addr", [
        "127.0.0.1", "0.0.0.0", "10.0.0.5", "172.16.3.4", "192.168.1.1",
        "169.254.169.254",           # cloud instance metadata
        "100.64.0.1",                # CGNAT
        "::1", "fe80::1", "fc00::1",
        "::ffff:127.0.0.1",          # IPv4-mapped loopback
        "2002:7f00:1::",             # 6to4 wrapping 127.0.0.1
        "224.0.0.1", "240.0.0.1",
    ])
    def test_non_public_rejected(self, addr):
        assert not _is_public_address(addr)

    @pytest.mark.parametrize("addr", ["140.82.121.4", "1.1.1.1", "2606:4700::1111"])
    def test_public_accepted(self, addr):
        assert _is_public_address(addr)

    def test_garbage_rejected(self):
        assert not _is_public_address("not-an-ip")


class TestValidateRepoUrl:

    def test_public_https_repo_accepted(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("140.82.121.4"))
        safe, msg = _validate_repo_url("https://github.com/ark-forge/mcp-eu-ai-act.git")
        assert safe, msg

    @pytest.mark.parametrize("url", [
        "http://github.com/x/y.git",
        "file:///etc/passwd",
        "ssh://git@github.com/x/y.git",
        "git://github.com/x/y.git",
        "https:/github.com/x",       # single slash: no hostname
    ])
    def test_non_https_rejected(self, url):
        safe, _ = _validate_repo_url(url)
        assert not safe

    def test_loopback_literal_rejected(self):
        """The reported PoC URL: passes startswith('https://'), must not pass now."""
        safe, msg = _validate_repo_url("https://127.0.0.1:8443/x.git")
        assert not safe

    def test_loopback_by_name_rejected(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("127.0.0.1"))
        safe, msg = _validate_repo_url("https://evil.example.com/x.git")
        assert not safe
        assert "public internet address" in msg

    def test_metadata_service_rejected(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("169.254.169.254"))
        safe, _ = _validate_repo_url("https://metadata.example.com/x.git")
        assert not safe

    def test_non_443_port_rejected(self, monkeypatch):
        """Even on a public host, an odd port is a port probe, not a Git remote."""
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("140.82.121.4"))
        safe, msg = _validate_repo_url("https://github.com:22/x.git")
        assert not safe
        assert "port" in msg

    def test_explicit_443_accepted(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("140.82.121.4"))
        safe, _ = _validate_repo_url("https://github.com:443/x/y.git")
        assert safe

    def test_credentials_rejected(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("140.82.121.4"))
        safe, msg = _validate_repo_url("https://user:token@github.com/x/y.git")
        assert not safe
        assert "credentials" in msg

    def test_unresolvable_host_rejected(self, monkeypatch):
        def boom(*args, **kwargs):
            raise socket.gaierror("nope")
        monkeypatch.setattr(socket, "getaddrinfo", boom)
        safe, msg = _validate_repo_url("https://nx.example.invalid/x.git")
        assert not safe
        assert "resolved" in msg

    def test_one_private_answer_rejects_the_whole_url(self, monkeypatch):
        """A host that answers with both a public and a private address is rejected."""
        def mixed(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("140.82.121.4", port)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.7", port)),
            ]
        monkeypatch.setattr(socket, "getaddrinfo", mixed)
        safe, _ = _validate_repo_url("https://split.example.com/x.git")
        assert not safe


class TestScanRepoUrlGate:

    def test_git_is_never_invoked_for_a_blocked_url(self, monkeypatch):
        """The gate is in _scan_repo_url, so no caller can reach clone without it."""
        called = []
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: called.append(a))
        status, body = _scan_repo_url("https://127.0.0.1:8443/x.git")
        assert status == 400
        assert called == []

    def test_git_stderr_is_not_echoed(self, monkeypatch):
        """The error oracle: the caller must not learn why the clone failed."""
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("140.82.121.4"))

        def fail(*args, **kwargs):
            raise subprocess.CalledProcessError(
                128, "git",
                stderr="fatal: unable to access 'https://x/': Failed to connect to port 8443: Connection refused",
            )
        monkeypatch.setattr(subprocess, "run", fail)
        status, body = _scan_repo_url("https://github.com/x/y.git")
        assert status == 400
        assert "Connection refused" not in body["error"]
        assert "8443" not in body["error"]

    def test_clone_disables_redirects_and_pins_protocol(self, monkeypatch):
        """git resolves redirects after our checks, so they must be off."""
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("140.82.121.4"))
        seen = {}

        def capture(cmd, **kwargs):
            seen["cmd"] = cmd
            seen["env"] = kwargs.get("env") or {}
            raise subprocess.CalledProcessError(128, "git", stderr="stop here")
        monkeypatch.setattr(subprocess, "run", capture)
        _scan_repo_url("https://github.com/x/y.git")
        assert "http.followRedirects=false" in seen["cmd"]
        assert seen["env"].get("GIT_ALLOW_PROTOCOL") == "https"
        assert seen["env"].get("GIT_TERMINAL_PROMPT") == "0"

    def test_timeout_still_reported(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("140.82.121.4"))

        def slow(*args, **kwargs):
            raise subprocess.TimeoutExpired("git", 60)
        monkeypatch.setattr(subprocess, "run", slow)
        status, _ = _scan_repo_url("https://github.com/x/y.git")
        assert status == 408
