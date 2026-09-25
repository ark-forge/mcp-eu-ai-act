"""Tests for under-covered helper functions to reach 80% coverage."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import (
    _detect_client_hint,
    _gate_recommendations,
    _ensure_demo_project,
    _store_gated_results,
    _pop_gated_results,
    _validate_project_path,
)


class TestDetectClientHint:
    def test_no_scope(self):
        assert _detect_client_hint(None) == "unknown"

    def test_no_ua_header(self):
        assert _detect_client_hint({"type": "http", "headers": []}) == "unknown"

    def test_claude_desktop(self):
        scope = {"type": "http", "headers": [(b"user-agent", b"Claude-Desktop/1.0")]}
        assert _detect_client_hint(scope) == "claude-desktop"

    def test_anthropic_ua(self):
        scope = {"type": "http", "headers": [(b"user-agent", b"Anthropic-SDK/2.0")]}
        assert _detect_client_hint(scope) == "claude-desktop"

    def test_cursor(self):
        scope = {"type": "http", "headers": [(b"user-agent", b"Cursor/0.44")]}
        assert _detect_client_hint(scope) == "cursor"

    def test_continue(self):
        scope = {"type": "http", "headers": [(b"user-agent", b"Continue-IDE/1.2")]}
        assert _detect_client_hint(scope) == "continue"

    def test_cline(self):
        scope = {"type": "http", "headers": [(b"user-agent", b"Cline/3.0")]}
        assert _detect_client_hint(scope) == "cline"

    def test_browser_mozilla(self):
        scope = {"type": "http", "headers": [(b"user-agent", b"Mozilla/5.0 (X11; Linux)")]}
        assert _detect_client_hint(scope) == "browser"

    def test_browser_chrome(self):
        scope = {"type": "http", "headers": [(b"user-agent", b"Chrome/120.0")]}
        assert _detect_client_hint(scope) == "browser"

    def test_browser_safari(self):
        scope = {"type": "http", "headers": [(b"user-agent", b"Safari/17.0")]}
        assert _detect_client_hint(scope) == "browser"

    def test_unknown_ua(self):
        scope = {"type": "http", "headers": [(b"user-agent", b"custom-bot/1.0")]}
        assert _detect_client_hint(scope) == "unknown"


class TestGateRecommendations:
    def test_empty_list(self):
        assert _gate_recommendations([]) == []

    def test_first_two_ungated(self):
        recs = [
            {"check": "risk_assessment", "status": "FAIL", "eu_article": "Art. 9",
             "how": "Create a risk management doc", "what": "Risk assessment", "why": "Required"},
            {"check": "transparency", "status": "PASS", "eu_article": "Art. 52",
             "how": "Add disclosure", "what": "Transparency", "why": "Mandatory"},
            {"check": "oversight", "status": "FAIL", "eu_article": "Art. 14",
             "how": "Implement review", "what": "Oversight", "why": "Required"},
        ]
        gated = _gate_recommendations(recs)
        assert len(gated) == 3
        assert gated[0]["gated"] is False
        assert "how" in gated[0]
        assert gated[1]["gated"] is False
        assert "how" in gated[1]
        assert gated[2]["gated"] is True
        assert "how" not in gated[2]

    def test_all_ungated_when_two_or_fewer(self):
        recs = [
            {"check": "a", "status": "PASS", "eu_article": "Art. 5"},
            {"check": "b", "status": "FAIL", "eu_article": "Art. 6"},
        ]
        gated = _gate_recommendations(recs)
        assert len(gated) == 2
        assert all(not r["gated"] for r in gated)

    def test_single_rec_ungated(self):
        recs = [{"what": "transparency", "status": "FAIL", "eu_article": "Art. 52", "how": "Add it"}]
        gated = _gate_recommendations(recs)
        assert gated[0]["gated"] is False
        assert "how" in gated[0]


class TestEnsureDemoProject:
    def test_creates_demo_files(self, tmp_path, monkeypatch):
        import server
        monkeypatch.setattr(server, "_DEMO_PROJECT_PATH", tmp_path / "demo")
        path = _ensure_demo_project()
        assert Path(path).exists()
        assert (Path(path) / "app.py").exists()
        assert (Path(path) / "requirements.txt").exists()

    def test_idempotent(self, tmp_path, monkeypatch):
        import server
        monkeypatch.setattr(server, "_DEMO_PROJECT_PATH", tmp_path / "demo")
        _ensure_demo_project()
        content_before = (tmp_path / "demo" / "app.py").read_text()
        _ensure_demo_project()
        content_after = (tmp_path / "demo" / "app.py").read_text()
        assert content_before == content_after


class TestGatedResultsCache:
    def test_cache_and_pop(self):
        _store_gated_results("scan123", {"recommendations": ["fix X"]})
        result = _pop_gated_results("scan123")
        assert result == {"recommendations": ["fix X"]}

    def test_pop_missing(self):
        assert _pop_gated_results("nonexistent") is None

    def test_pop_removes_entry(self):
        _store_gated_results("scan456", ["rec1"])
        _pop_gated_results("scan456")
        assert _pop_gated_results("scan456") is None


class TestValidatePathSecurity:
    def test_valid_path(self, tmp_path):
        safe, err = _validate_project_path(str(tmp_path))
        assert safe is True
        assert err == ""

    def test_blocked_etc(self):
        safe, err = _validate_project_path("/etc")
        assert safe is False

    def test_blocked_proc(self):
        safe, err = _validate_project_path("/proc")
        assert safe is False
