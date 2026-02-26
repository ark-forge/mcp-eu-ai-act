"""Security tests — path traversal, blocked paths, input validation."""

import os
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from server import _validate_project_path, BLOCKED_PATHS


class TestPathTraversal:
    """Ensure blocked paths cannot be scanned."""

    def test_etc_blocked(self):
        safe, msg = _validate_project_path("/etc")
        assert not safe
        assert "not allowed" in msg

    def test_etc_subdir_blocked(self):
        safe, msg = _validate_project_path("/etc/nginx")
        assert not safe

    def test_proc_blocked(self):
        safe, msg = _validate_project_path("/proc")
        assert not safe

    def test_root_blocked(self):
        safe, msg = _validate_project_path("/root")
        assert not safe

    def test_dev_blocked(self):
        safe, msg = _validate_project_path("/dev")
        assert not safe

    def test_relative_path_traversal(self):
        """Relative path with .. should resolve and check."""
        safe, msg = _validate_project_path("/tmp/../etc")
        assert not safe

    def test_valid_tmp_path(self):
        with tempfile.TemporaryDirectory() as d:
            safe, msg = _validate_project_path(d)
            assert safe

    def test_home_path_allowed(self):
        safe, msg = _validate_project_path("/home/testuser/project")
        assert safe

    def test_empty_path(self):
        safe, msg = _validate_project_path("")
        # Empty resolves to cwd which may or may not be blocked
        # Just ensure it doesn't crash
        assert isinstance(safe, bool)

    def test_nonexistent_path_allowed(self):
        """Non-existent paths pass validation (scanner handles missing dirs)."""
        safe, msg = _validate_project_path("/tmp/does_not_exist_12345")
        assert safe

    def test_all_blocked_paths_rejected(self):
        for blocked in BLOCKED_PATHS:
            safe, msg = _validate_project_path(blocked)
            assert not safe, f"{blocked} should be blocked"
