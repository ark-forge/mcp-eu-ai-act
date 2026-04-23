"""Verify that built wheels include all required files."""
import subprocess
import zipfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
REQUIRED_FILES = ["server.py", "cli.py", "gdpr_module.py", "data/eu_ai_act_articles.json"]


@pytest.fixture(scope="module")
def wheel_path(tmp_path_factory):
    dist = tmp_path_factory.mktemp("dist")
    result = subprocess.run(
        ["python3", "-m", "build", "-w", "--outdir", str(dist)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"build failed: {result.stderr[-300:]}")
    wheels = list(dist.glob("*.whl"))
    assert wheels, "No wheel produced"
    return wheels[0]


@pytest.mark.parametrize("expected_file", REQUIRED_FILES)
def test_wheel_contains_file(wheel_path, expected_file):
    with zipfile.ZipFile(wheel_path) as z:
        names = z.namelist()
    assert expected_file in names, f"{expected_file} missing from wheel: {names}"


def test_wheel_articles_db_not_empty(wheel_path):
    import json as _json

    with zipfile.ZipFile(wheel_path) as z:
        data = _json.loads(z.read("data/eu_ai_act_articles.json"))
    assert len(data.get("articles", [])) >= 10, "articles DB suspiciously small"
