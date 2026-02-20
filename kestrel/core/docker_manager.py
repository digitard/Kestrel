"""
Kestrel Docker Manager

Manages the kestrel-tools Kali Linux Docker container.
Used by UnifiedExecutor when running on non-Kali platforms.

Responsibilities:
  - Ensure the kestrel-tools image exists (auto-build if missing)
  - Start / stop / health-check the kestrel-tools container
  - Execute commands inside the container via `docker exec`
  - Detect and log missing tools to docker/tool_manifest.yaml

Uses the Docker CLI directly (no Python docker SDK required).
"""

import logging
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from kestrel.core.executor import ExecutionResult, ExecutionStatus

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────

CONTAINER_NAME = "kestrel-tools"
IMAGE_TAG = "kestrel-tools:latest"
WORKSPACE_DIR = Path.home() / ".kestrel" / "workspace"

# Locate docker/ directory relative to this file:
#   kestrel/core/docker_manager.py → project_root/docker/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DOCKER_DIR = _PROJECT_ROOT / "docker"
_TOOL_MANIFEST = _DOCKER_DIR / "tool_manifest.yaml"

# Shell builtins that are guaranteed present — never log as "missing tools"
_BUILTIN_COMMANDS = frozenset({
    "cd", "echo", "export", "set", "unset", "source", ".", "exec",
    "test", "[", "true", "false", "pwd", "read", "eval", "shift",
    "cat", "ls", "cp", "mv", "rm", "mkdir", "chmod", "chown",
    "grep", "sed", "awk", "head", "tail", "sort", "cut", "wc",
    "find", "xargs", "tee", "tr", "touch", "ln", "basename",
    "dirname", "date", "env", "which", "whoami", "id", "sleep",
    "python3", "pip3", "sh", "bash",
})

# Pattern strings that indicate a "command not found" situation
_NOT_FOUND_PATTERNS = (
    "command not found",
    "not found in PATH",
    "No such file or directory",
)


# ─────────────────────────────────────────────────────────────────────
#  DockerManager
# ─────────────────────────────────────────────────────────────────────

class DockerManager:
    """
    Manages the kestrel-tools Docker container lifecycle and command execution.

    All docker CLI calls are made via subprocess so the Python docker SDK
    is not required. The manager is used exclusively by UnifiedExecutor
    when running on non-Kali Linux platforms.

    Usage:
        mgr = DockerManager()
        result = mgr.exec_command("nmap -sV target.example.com", timeout=300)
    """

    def __init__(self, workspace_dir: Optional[Path] = None) -> None:
        self.workspace_dir = workspace_dir or WORKSPACE_DIR
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

    # ─── Public interface ─────────────────────────────────────────────

    def is_available(self) -> bool:
        """True if the docker CLI is present and daemon is responding."""
        if not shutil.which("docker"):
            return False
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0 and bool(result.stdout.strip())
        except (subprocess.TimeoutExpired, OSError):
            return False

    def is_running(self) -> bool:
        """True if the kestrel-tools container is currently running."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", CONTAINER_NAME],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0 and result.stdout.strip() == "true"
        except (subprocess.TimeoutExpired, OSError):
            return False

    def ensure_running(self) -> bool:
        """
        Ensure kestrel-tools container is running.

        If the container exists but is stopped, restarts it.
        If the container doesn't exist, creates it (building the image first if needed).

        Returns:
            True if container is running after this call.
        """
        if self.is_running():
            return True

        # Check if a stopped container exists
        if self._container_exists():
            logger.info("Container %s exists but is stopped — starting it", CONTAINER_NAME)
            return self._start_existing()

        # Container doesn't exist — need the image first
        if not self._image_exists():
            logger.info("Image %s not found — building from %s", IMAGE_TAG, _DOCKER_DIR)
            if not self.build_image():
                return False

        return self._create_container()

    def exec_command(
        self,
        command: str,
        workdir: str = "/workspace",
        timeout: Optional[int] = None,
    ) -> ExecutionResult:
        """
        Execute a command inside the kestrel-tools container.

        Auto-starts the container if it is not running.

        Args:
            command: Shell command to run inside the container.
            workdir: Working directory inside the container.
            timeout: Timeout in seconds (None = no limit).

        Returns:
            ExecutionResult with stdout, stderr, status, and timing.
        """
        started_at = datetime.now()

        if not self.ensure_running():
            return ExecutionResult(
                command=command,
                status=ExecutionStatus.FAILED,
                error_message=(
                    f"Cannot start {CONTAINER_NAME} container. "
                    "Run 'docker ps' to debug."
                ),
                started_at=started_at,
                completed_at=datetime.now(),
            )

        # Wrap with GNU timeout if requested (timeout returns exit code 124)
        exec_cmd = f"timeout {timeout} {command}" if timeout else command

        docker_args = [
            "docker", "exec",
            "--workdir", workdir,
            CONTAINER_NAME,
            "sh", "-c", exec_cmd,
        ]

        try:
            proc = subprocess.run(
                docker_args,
                capture_output=True,
                text=True,
                timeout=(timeout or 0) + 15 if timeout else None,
            )
            completed_at = datetime.now()

            status = ExecutionStatus.COMPLETED
            error_message = None

            if proc.returncode == 124 and timeout:
                status = ExecutionStatus.TIMEOUT
                error_message = f"Command timed out after {timeout} seconds"
            elif proc.returncode != 0:
                # Check for missing tool — log it for Dockerfile update tracking
                missing = self._detect_missing_tool(command, proc.returncode, proc.stderr + proc.stdout)
                if missing:
                    self._log_missing_tool(missing)

            result = ExecutionResult(
                command=command,
                status=status,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                started_at=started_at,
                completed_at=completed_at,
                error_message=error_message,
            )
            result.duration_seconds = (completed_at - started_at).total_seconds()
            return result

        except subprocess.TimeoutExpired:
            completed_at = datetime.now()
            return ExecutionResult(
                command=command,
                status=ExecutionStatus.TIMEOUT,
                error_message=f"docker exec timed out after {timeout} seconds",
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=(completed_at - started_at).total_seconds(),
            )
        except OSError as e:
            completed_at = datetime.now()
            return ExecutionResult(
                command=command,
                status=ExecutionStatus.FAILED,
                error_message=f"docker exec failed: {e}",
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=(completed_at - started_at).total_seconds(),
            )

    def check_tool(self, tool: str) -> bool:
        """True if `tool` is available inside the container."""
        if not self.is_running():
            return False
        result = self.exec_command(f"which {tool}", timeout=5)
        return result.success

    def get_tool_version(self, tool: str) -> Optional[str]:
        """Return version string for `tool` inside the container, or None."""
        for flag in ("--version", "-V"):
            result = self.exec_command(f"{tool} {flag}", timeout=5)
            if result.success and result.stdout.strip():
                return result.stdout.strip().splitlines()[0]
        return None

    def stop(self) -> bool:
        """Stop (but do not remove) the kestrel-tools container."""
        try:
            result = subprocess.run(
                ["docker", "stop", CONTAINER_NAME],
                capture_output=True, text=True, timeout=20,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def build_image(self, push: bool = False) -> bool:
        """
        Build the kestrel-tools Docker image from docker/Dockerfile.

        Args:
            push: If True, push after build (requires a registry configured).

        Returns:
            True on success.
        """
        dockerfile = _DOCKER_DIR / "Dockerfile"
        if not dockerfile.exists():
            logger.error("Dockerfile not found at %s", dockerfile)
            return False

        cmd = ["docker", "build", "-t", IMAGE_TAG, str(_DOCKER_DIR)]
        logger.info("Building %s from %s …", IMAGE_TAG, _DOCKER_DIR)

        try:
            result = subprocess.run(cmd, timeout=600)
            if result.returncode != 0:
                logger.error("docker build failed (exit %d)", result.returncode)
                return False
        except subprocess.TimeoutExpired:
            logger.error("docker build timed out after 10 minutes")
            return False
        except OSError as e:
            logger.error("docker build failed: %s", e)
            return False

        if push:
            push_result = subprocess.run(
                ["docker", "push", IMAGE_TAG],
                timeout=300,
            )
            if push_result.returncode != 0:
                logger.warning("docker push failed — image built locally but not pushed")

        return True

    def status(self) -> dict:
        """Return a status summary dict (for CLI / health checks)."""
        return {
            "container_name": CONTAINER_NAME,
            "image_tag": IMAGE_TAG,
            "docker_available": self.is_available(),
            "container_running": self.is_running(),
            "image_exists": self._image_exists(),
            "workspace": str(self.workspace_dir),
        }

    # ─── Private helpers ──────────────────────────────────────────────

    def _container_exists(self) -> bool:
        """True if a container named kestrel-tools exists (running or stopped)."""
        try:
            result = subprocess.run(
                ["docker", "inspect", CONTAINER_NAME],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _image_exists(self) -> bool:
        """True if the kestrel-tools:latest image is present locally."""
        try:
            result = subprocess.run(
                ["docker", "images", "-q", IMAGE_TAG],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0 and bool(result.stdout.strip())
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _start_existing(self) -> bool:
        """Start a stopped kestrel-tools container."""
        try:
            result = subprocess.run(
                ["docker", "start", CONTAINER_NAME],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                logger.error("docker start failed: %s", result.stderr.strip())
                return False
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.error("docker start error: %s", e)
            return False

        # Poll until running (up to 10 seconds)
        return self._wait_for_running()

    def _create_container(self) -> bool:
        """Create and start a new kestrel-tools container."""
        cmd = [
            "docker", "run",
            "--detach",
            "--name", CONTAINER_NAME,
            "--volume", f"{self.workspace_dir}:/workspace",
            "--network", "host",
            IMAGE_TAG,
            "tail", "-f", "/dev/null",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                logger.error("docker run failed: %s", result.stderr.strip())
                return False
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.error("docker run error: %s", e)
            return False

        logger.info("Container %s created, workspace: %s", CONTAINER_NAME, self.workspace_dir)
        return self._wait_for_running()

    def _wait_for_running(self, timeout_seconds: int = 10) -> bool:
        """Poll until the container is running or timeout."""
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self.is_running():
                return True
            time.sleep(0.5)
        logger.error("Container %s did not start within %ds", CONTAINER_NAME, timeout_seconds)
        return False

    def _detect_missing_tool(self, command: str, exit_code: int, output: str) -> Optional[str]:
        """Return the tool name if the failure looks like 'command not found'."""
        is_not_found = exit_code == 127 or any(p in output for p in _NOT_FOUND_PATTERNS)
        if not is_not_found:
            return None

        # Extract tool name from possibly-chained command: "cd /workspace && nmap ..."
        import re
        parts = re.split(r"\s*(?:&&|\|\||;)\s*", command.strip())
        for part in reversed(parts):
            words = part.strip().split()
            if words and words[0] not in _BUILTIN_COMMANDS:
                return words[0]

        words = command.strip().split()
        return words[0] if words and words[0] not in _BUILTIN_COMMANDS else None

    def _log_missing_tool(self, tool: str) -> None:
        """Record a missing tool in docker/tool_manifest.yaml for developer review."""
        try:
            manifest = {}
            if _TOOL_MANIFEST.exists():
                with open(_TOOL_MANIFEST) as f:
                    manifest = yaml.safe_load(f) or {}

            missing = manifest.setdefault("missing_tools_log", {})
            if tool not in missing:
                timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                missing[tool] = f"first seen {timestamp}"
                with open(_TOOL_MANIFEST, "w") as f:
                    yaml.dump(manifest, f, default_flow_style=False, sort_keys=False)
                logger.warning("Missing tool logged to manifest: %s", tool)
        except Exception as e:
            logger.debug("Could not update tool manifest: %s", e)
