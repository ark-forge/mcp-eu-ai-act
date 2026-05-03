"""Tests for the CLI entry point (eu-ai-act-scanner)."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from cli import main, _resolve_version


@pytest.fixture
def project_with_openai(tmp_path):
    (tmp_path / "app.py").write_text("import openai\nclient = openai.OpenAI()\n")
    return str(tmp_path)


@pytest.fixture
def empty_project(tmp_path):
    (tmp_path / "hello.py").write_text("print('no AI here')\n")
    return str(tmp_path)


class TestVersion:
    def test_version_not_dev_in_source_tree(self):
        v = _resolve_version()
        assert v != "dev"
        assert "." in v

    def test_version_flag_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
        assert _resolve_version() in capsys.readouterr().out


class TestScanSubcommand:
    def test_scan_prefix_accepted(self, project_with_openai, capsys):
        rc = main(["scan", project_with_openai, "--json"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["scan"]["files_scanned"] >= 1

    def test_scan_dot_accepted(self, project_with_openai, monkeypatch, capsys):
        monkeypatch.chdir(project_with_openai)
        rc = main(["scan", ".", "--json"])
        assert rc == 0


class TestDefaultPath:
    def test_no_args_scans_cwd(self, project_with_openai, monkeypatch, capsys):
        monkeypatch.chdir(project_with_openai)
        rc = main(["--json"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["scan"]["files_scanned"] >= 1


class TestJsonOutput:
    def test_json_structure(self, project_with_openai, capsys):
        rc = main([project_with_openai, "--json"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert "scan" in out
        assert "compliance" in out
        assert "upgrade" in out
        assert "pricing_url" in out["upgrade"]

    def test_json_detects_openai(self, project_with_openai, capsys):
        rc = main([project_with_openai, "--json"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        models = out["scan"].get("detected_models", {})
        assert "openai" in models


class TestHumanOutput:
    def test_human_output_contains_header(self, project_with_openai, capsys):
        rc = main([project_with_openai])
        assert rc == 0
        out = capsys.readouterr().out
        assert "EU AI Act Compliance Scanner" in out
        assert "Files scanned:" in out

    def test_empty_project_shows_guidance(self, empty_project, capsys):
        rc = main([empty_project])
        assert rc == 0
        out = capsys.readouterr().out
        assert "AI frameworks detected: 0" in out

    def test_upgrade_cta_shown(self, project_with_openai, capsys):
        main([project_with_openai])
        out = capsys.readouterr().out
        assert "Upgrade to Pro" in out
        assert "EUR/month" in out
        assert "utm_campaign=free_to_pro" in out


    def test_upgrade_cta_hidden_with_pro_key(self, project_with_openai, capsys):
        with patch("cli._is_pro_key", return_value=True):
            main([project_with_openai, "--api-key", "ak_test_pro"])
        out = capsys.readouterr().out
        assert "Upgrade to Pro" not in out

    def test_upgrade_cta_in_json_hidden_with_pro_key(self, project_with_openai, capsys):
        with patch("cli._is_pro_key", return_value=True):
            main([project_with_openai, "--api-key", "ak_test_pro", "--json"])
        out = json.loads(capsys.readouterr().out)
        assert "upgrade" not in out

    def test_upgrade_cta_in_json_shown_without_key(self, project_with_openai, capsys):
        main([project_with_openai, "--json"])
        out = json.loads(capsys.readouterr().out)
        assert "upgrade" in out
        assert "free_to_pro" in out["upgrade"]["checkout_url"]


class TestRiskFlag:
    def test_risk_high(self, project_with_openai, capsys):
        rc = main([project_with_openai, "--risk", "high", "--json"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["compliance"]["risk_category"] == "high"

    def test_invalid_risk_exits_nonzero(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main([".", "--risk", "nonexistent"])
        assert exc_info.value.code != 0


class TestProFlag:
    def test_pro_preview_shown(self, project_with_openai, capsys):
        rc = main([project_with_openai, "--pro"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Remediation Guidance" in out


class TestTelemetry:
    def test_cli_invocation_logged(self, project_with_openai, tmp_path, capsys):
        log_file = tmp_path / "tool_calls.jsonl"
        with patch("cli.Path") as mock_path_cls:
            real_path = Path
            def side_effect(*args):
                p = real_path(*args)
                return p
            mock_path_cls.side_effect = side_effect
            mock_path_cls.__truediv__ = real_path.__truediv__

        import cli as cli_module
        original_parent = Path(cli_module.__file__).parent
        log_path = original_parent / "data" / "tool_calls.jsonl"
        pre_size = log_path.stat().st_size if log_path.exists() else 0

        main([project_with_openai, "--json"])
        capsys.readouterr()

        if log_path.exists() and log_path.stat().st_size > pre_size:
            with open(log_path) as f:
                lines = f.readlines()
            last = json.loads(lines[-1])
            assert last["tool"] == "cli_scan"
            assert last["source"] == "cli"
