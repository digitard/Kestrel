"""
Phase 1 — Docker Manager Tests

Tests for DockerManager with all subprocess calls mocked.
No Docker daemon required to run these tests.
"""

import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))


# ─────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────

def _make_proc(returncode: int, stdout: str = "", stderr: str = "") -> MagicMock:
    """Create a mock CompletedProcess."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


# ─────────────────────────────────────────────────────────────────────
#  DockerManager availability
# ─────────────────────────────────────────────────────────────────────

class TestDockerManagerAvailability:
    """is_available() delegates to docker info."""

    def test_available_when_docker_responds(self):
        from kestrel.core.docker_manager import DockerManager
        with patch("shutil.which", return_value="/usr/local/bin/docker"), \
             patch("subprocess.run", return_value=_make_proc(0, stdout="26.1.0")):
            mgr = DockerManager()
            assert mgr.is_available() is True

    def test_not_available_when_docker_cli_missing(self):
        from kestrel.core.docker_manager import DockerManager
        with patch("shutil.which", return_value=None):
            mgr = DockerManager()
            assert mgr.is_available() is False

    def test_not_available_when_daemon_not_running(self):
        from kestrel.core.docker_manager import DockerManager
        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run", return_value=_make_proc(1, stderr="Cannot connect")):
            mgr = DockerManager()
            assert mgr.is_available() is False

    def test_not_available_on_timeout(self):
        import subprocess
        from kestrel.core.docker_manager import DockerManager
        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 10)):
            mgr = DockerManager()
            assert mgr.is_available() is False


# ─────────────────────────────────────────────────────────────────────
#  DockerManager container state
# ─────────────────────────────────────────────────────────────────────

class TestDockerManagerContainerState:
    """is_running / _container_exists / _image_exists."""

    def test_is_running_true(self):
        from kestrel.core.docker_manager import DockerManager
        with patch("subprocess.run", return_value=_make_proc(0, stdout="true\n")):
            mgr = DockerManager()
            assert mgr.is_running() is True

    def test_is_running_false_when_stopped(self):
        from kestrel.core.docker_manager import DockerManager
        with patch("subprocess.run", return_value=_make_proc(0, stdout="false\n")):
            mgr = DockerManager()
            assert mgr.is_running() is False

    def test_is_running_false_when_container_not_found(self):
        from kestrel.core.docker_manager import DockerManager
        with patch("subprocess.run", return_value=_make_proc(1, stderr="No such object")):
            mgr = DockerManager()
            assert mgr.is_running() is False

    def test_image_exists_true(self):
        from kestrel.core.docker_manager import DockerManager
        with patch("subprocess.run", return_value=_make_proc(0, stdout="abc123def456\n")):
            mgr = DockerManager()
            assert mgr._image_exists() is True

    def test_image_exists_false_when_empty(self):
        from kestrel.core.docker_manager import DockerManager
        with patch("subprocess.run", return_value=_make_proc(0, stdout="")):
            mgr = DockerManager()
            assert mgr._image_exists() is False

    def test_container_exists_true(self):
        from kestrel.core.docker_manager import DockerManager
        with patch("subprocess.run", return_value=_make_proc(0, stdout="{}")):
            mgr = DockerManager()
            assert mgr._container_exists() is True

    def test_container_exists_false(self):
        from kestrel.core.docker_manager import DockerManager
        with patch("subprocess.run", return_value=_make_proc(1)):
            mgr = DockerManager()
            assert mgr._container_exists() is False


# ─────────────────────────────────────────────────────────────────────
#  DockerManager ensure_running
# ─────────────────────────────────────────────────────────────────────

class TestDockerManagerEnsureRunning:
    """ensure_running covers: already running, start stopped, create new."""

    def test_already_running_returns_true(self):
        from kestrel.core.docker_manager import DockerManager
        mgr = DockerManager()
        with patch.object(mgr, "is_running", return_value=True):
            assert mgr.ensure_running() is True

    def test_start_stopped_container(self):
        from kestrel.core.docker_manager import DockerManager
        mgr = DockerManager()
        calls = [False, True]  # first is_running False → after start True
        side_effect = iter(calls)

        with patch.object(mgr, "is_running", side_effect=lambda: next(side_effect)), \
             patch.object(mgr, "_container_exists", return_value=True), \
             patch.object(mgr, "_start_existing", return_value=True):
            assert mgr.ensure_running() is True

    def test_create_new_container_when_not_exists(self):
        from kestrel.core.docker_manager import DockerManager
        mgr = DockerManager()

        with patch.object(mgr, "is_running", return_value=False), \
             patch.object(mgr, "_container_exists", return_value=False), \
             patch.object(mgr, "_image_exists", return_value=True), \
             patch.object(mgr, "_create_container", return_value=True):
            assert mgr.ensure_running() is True

    def test_build_image_when_missing(self):
        from kestrel.core.docker_manager import DockerManager
        mgr = DockerManager()

        with patch.object(mgr, "is_running", return_value=False), \
             patch.object(mgr, "_container_exists", return_value=False), \
             patch.object(mgr, "_image_exists", return_value=False), \
             patch.object(mgr, "build_image", return_value=True) as mock_build, \
             patch.object(mgr, "_create_container", return_value=True):
            result = mgr.ensure_running()

        mock_build.assert_called_once()
        assert result is True

    def test_returns_false_when_build_fails(self):
        from kestrel.core.docker_manager import DockerManager
        mgr = DockerManager()

        with patch.object(mgr, "is_running", return_value=False), \
             patch.object(mgr, "_container_exists", return_value=False), \
             patch.object(mgr, "_image_exists", return_value=False), \
             patch.object(mgr, "build_image", return_value=False):
            assert mgr.ensure_running() is False


# ─────────────────────────────────────────────────────────────────────
#  DockerManager exec_command
# ─────────────────────────────────────────────────────────────────────

class TestDockerManagerExecCommand:
    """exec_command correctly wraps docker exec and returns ExecutionResult."""

    def test_successful_command(self):
        from kestrel.core.docker_manager import DockerManager
        from kestrel.core.executor import ExecutionStatus
        mgr = DockerManager()

        with patch.object(mgr, "ensure_running", return_value=True), \
             patch("subprocess.run", return_value=_make_proc(0, stdout="scan results\n")):
            result = mgr.exec_command("nmap -sV target")

        assert result.status == ExecutionStatus.COMPLETED
        assert result.exit_code == 0
        assert "scan results" in result.stdout

    def test_failed_command(self):
        from kestrel.core.docker_manager import DockerManager
        from kestrel.core.executor import ExecutionStatus
        mgr = DockerManager()

        with patch.object(mgr, "ensure_running", return_value=True), \
             patch("subprocess.run", return_value=_make_proc(1, stderr="permission denied")):
            result = mgr.exec_command("some_tool --bad-arg")

        assert result.exit_code == 1
        assert result.success is False

    def test_timeout_wraps_command(self):
        """With timeout=30, exec_command should prefix 'timeout 30 ...'."""
        from kestrel.core.docker_manager import DockerManager
        mgr = DockerManager()
        captured_args = []

        def capture_run(args, **kwargs):
            captured_args.extend(args)
            return _make_proc(0, stdout="ok")

        with patch.object(mgr, "ensure_running", return_value=True), \
             patch("subprocess.run", side_effect=capture_run):
            mgr.exec_command("nmap target", timeout=30)

        shell_cmd = " ".join(captured_args)
        assert "timeout 30" in shell_cmd

    def test_returns_failed_when_container_wont_start(self):
        from kestrel.core.docker_manager import DockerManager
        from kestrel.core.executor import ExecutionStatus
        mgr = DockerManager()

        with patch.object(mgr, "ensure_running", return_value=False):
            result = mgr.exec_command("nmap target")

        assert result.status == ExecutionStatus.FAILED
        assert result.error_message

    def test_timeout_detected_exit_code_124(self):
        from kestrel.core.docker_manager import DockerManager
        from kestrel.core.executor import ExecutionStatus
        mgr = DockerManager()

        with patch.object(mgr, "ensure_running", return_value=True), \
             patch("subprocess.run", return_value=_make_proc(124)):
            result = mgr.exec_command("sleep 9999", timeout=5)

        assert result.status == ExecutionStatus.TIMEOUT

    def test_subprocess_timeout_raises_correctly(self):
        import subprocess
        from kestrel.core.docker_manager import DockerManager
        from kestrel.core.executor import ExecutionStatus
        mgr = DockerManager()

        with patch.object(mgr, "ensure_running", return_value=True), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 5)):
            result = mgr.exec_command("slow_cmd", timeout=5)

        assert result.status == ExecutionStatus.TIMEOUT


# ─────────────────────────────────────────────────────────────────────
#  DockerManager missing tool detection
# ─────────────────────────────────────────────────────────────────────

class TestDockerManagerMissingToolDetection:
    """_detect_missing_tool correctly identifies tool-not-found failures."""

    def _mgr(self):
        from kestrel.core.docker_manager import DockerManager
        return DockerManager()

    def test_exit_127_detected(self):
        mgr = self._mgr()
        tool = mgr._detect_missing_tool("subfinder -d example.com", 127, "")
        assert tool == "subfinder"

    def test_command_not_found_string(self):
        mgr = self._mgr()
        tool = mgr._detect_missing_tool(
            "amass enum -d example.com", 1, "amass: command not found"
        )
        assert tool == "amass"

    def test_chained_command_extracts_non_builtin(self):
        mgr = self._mgr()
        tool = mgr._detect_missing_tool(
            "cd /workspace && nuclei -target example.com", 127, ""
        )
        assert tool == "nuclei"

    def test_builtin_not_reported_as_missing(self):
        mgr = self._mgr()
        tool = mgr._detect_missing_tool("echo hello", 127, "echo: command not found")
        # 'echo' is in _BUILTIN_COMMANDS — should not return it
        # (returns None or a different tool)
        assert tool != "echo"

    def test_no_false_positive_on_success(self):
        mgr = self._mgr()
        tool = mgr._detect_missing_tool("nmap -sV target", 0, "Nmap scan report")
        assert tool is None

    def test_no_false_positive_on_generic_error(self):
        mgr = self._mgr()
        tool = mgr._detect_missing_tool("nmap -sV target", 1, "RTTVAR has grown too large")
        assert tool is None


# ─────────────────────────────────────────────────────────────────────
#  DockerManager status
# ─────────────────────────────────────────────────────────────────────

class TestDockerManagerStatus:
    """status() returns the expected keys."""

    def test_status_keys_present(self):
        from kestrel.core.docker_manager import DockerManager
        mgr = DockerManager()

        with patch.object(mgr, "is_available", return_value=True), \
             patch.object(mgr, "is_running", return_value=False), \
             patch.object(mgr, "_image_exists", return_value=False):
            s = mgr.status()

        for key in ("container_name", "image_tag", "docker_available",
                    "container_running", "image_exists", "workspace"):
            assert key in s

    def test_status_container_name(self):
        from kestrel.core.docker_manager import DockerManager, CONTAINER_NAME
        mgr = DockerManager()

        with patch.object(mgr, "is_available", return_value=True), \
             patch.object(mgr, "is_running", return_value=True), \
             patch.object(mgr, "_image_exists", return_value=True):
            s = mgr.status()

        assert s["container_name"] == CONTAINER_NAME
        assert s["container_running"] is True
        assert s["docker_available"] is True


# ─────────────────────────────────────────────────────────────────────
#  DockerManager check_tool / get_tool_version
# ─────────────────────────────────────────────────────────────────────

class TestDockerManagerToolCheck:
    """check_tool and get_tool_version exec into container."""

    def test_check_tool_found(self):
        from kestrel.core.docker_manager import DockerManager
        from kestrel.core.executor import ExecutionResult, ExecutionStatus
        mgr = DockerManager()

        mock_result = ExecutionResult(
            command="which nmap",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            stdout="/usr/bin/nmap\n",
            stderr="",
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )
        with patch.object(mgr, "is_running", return_value=True), \
             patch.object(mgr, "exec_command", return_value=mock_result):
            assert mgr.check_tool("nmap") is True

    def test_check_tool_not_found(self):
        from kestrel.core.docker_manager import DockerManager
        from kestrel.core.executor import ExecutionResult, ExecutionStatus
        mgr = DockerManager()

        mock_result = ExecutionResult(
            command="which xyz_nonexistent",
            status=ExecutionStatus.COMPLETED,
            exit_code=1,
            stdout="",
            stderr="",
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )
        with patch.object(mgr, "is_running", return_value=True), \
             patch.object(mgr, "exec_command", return_value=mock_result):
            assert mgr.check_tool("xyz_nonexistent") is False

    def test_check_tool_returns_false_when_not_running(self):
        from kestrel.core.docker_manager import DockerManager
        mgr = DockerManager()

        with patch.object(mgr, "is_running", return_value=False):
            assert mgr.check_tool("nmap") is False

    def test_get_tool_version(self):
        from kestrel.core.docker_manager import DockerManager
        from kestrel.core.executor import ExecutionResult, ExecutionStatus
        mgr = DockerManager()

        mock_result = ExecutionResult(
            command="nmap --version",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            stdout="Nmap version 7.94 ( https://nmap.org )\n",
            stderr="",
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )
        with patch.object(mgr, "exec_command", return_value=mock_result):
            version = mgr.get_tool_version("nmap")

        assert version and "Nmap" in version
