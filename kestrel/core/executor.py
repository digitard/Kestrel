"""
Kestrel Executor

Provides two executors:

  NativeExecutor   — Direct subprocess on Kali Linux (legacy, kept for
                     backward compat with Phase 1 tests and tool wrappers).

  UnifiedExecutor  — Platform-aware router. Auto-detects runtime environment
                     via PlatformInfo and routes to native subprocess (Kali)
                     or Docker (kestrel-tools container) automatically.

The UnifiedExecutor is the preferred entry point for all new code. Existing
callers of NativeExecutor continue to work unchanged.
"""

import subprocess
import shutil
import time
import os
import signal
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable
from enum import Enum
from pathlib import Path


class ExecutionStatus(Enum):
    """Status of a command execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class ExecutionResult:
    """Result of executing a command."""
    command: str
    status: ExecutionStatus
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    
    @property
    def success(self) -> bool:
        """Check if execution was successful."""
        return self.status == ExecutionStatus.COMPLETED and self.exit_code == 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "command": self.command,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "success": self.success,
            "error_message": self.error_message,
        }


class NativeExecutor:
    """
    Executes commands directly on the native Kali Linux system.
    
    Features:
    - Direct subprocess execution
    - Timeout support
    - Output streaming callbacks
    - Tool availability checking
    """
    
    def __init__(self, working_dir: Optional[Path] = None):
        """
        Initialize the native executor.
        
        Args:
            working_dir: Working directory for command execution
        """
        self.working_dir = working_dir or Path.home()
        self._running_processes: dict[str, subprocess.Popen] = {}
    
    def check_tool(self, tool: str) -> bool:
        """
        Check if a tool is available on the system.
        
        Args:
            tool: Tool name (e.g., "nmap", "gobuster")
            
        Returns:
            True if tool is available
        """
        return shutil.which(tool) is not None
    
    def get_tool_path(self, tool: str) -> Optional[str]:
        """
        Get the full path to a tool.
        
        Args:
            tool: Tool name
            
        Returns:
            Full path or None if not found
        """
        return shutil.which(tool)
    
    def get_tool_version(self, tool: str) -> Optional[str]:
        """
        Get the version of a tool.
        
        Args:
            tool: Tool name
            
        Returns:
            Version string or None
        """
        if not self.check_tool(tool):
            return None
        
        try:
            # Most tools support --version
            result = subprocess.run(
                [tool, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
            
            # Some tools use -V
            result = subprocess.run(
                [tool, "-V"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
                
        except (subprocess.TimeoutExpired, Exception):
            pass
        
        return "version unknown"
    
    def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        env: Optional[dict] = None,
        cwd: Optional[Path] = None,
        on_output: Optional[Callable[[str], None]] = None,
    ) -> ExecutionResult:
        """
        Execute a command and wait for completion.
        
        Args:
            command: Command string to execute
            timeout: Timeout in seconds (None = no timeout)
            env: Additional environment variables
            cwd: Working directory (overrides default)
            on_output: Callback for streaming output lines
            
        Returns:
            ExecutionResult with output and status
        """
        result = ExecutionResult(
            command=command,
            status=ExecutionStatus.PENDING,
            started_at=datetime.now()
        )
        
        # Prepare environment
        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)
        
        # Prepare working directory
        exec_cwd = str(cwd or self.working_dir)
        
        try:
            result.status = ExecutionStatus.RUNNING
            
            if on_output:
                # Streaming mode - capture output line by line
                stdout_lines = []
                stderr_lines = []
                
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=exec_env,
                    cwd=exec_cwd,
                )
                
                # Generate unique ID for tracking
                proc_id = f"{int(time.time() * 1000)}"
                self._running_processes[proc_id] = process
                
                try:
                    # Read output with timeout
                    start_time = time.time()
                    
                    while True:
                        # Check timeout
                        if timeout and (time.time() - start_time) > timeout:
                            process.kill()
                            result.status = ExecutionStatus.TIMEOUT
                            result.error_message = f"Command timed out after {timeout} seconds"
                            break
                        
                        # Check if process finished
                        retcode = process.poll()
                        
                        # Read available output
                        if process.stdout:
                            line = process.stdout.readline()
                            if line:
                                stdout_lines.append(line)
                                on_output(line.rstrip())
                        
                        if retcode is not None:
                            # Process finished - read remaining output
                            remaining_stdout, remaining_stderr = process.communicate()
                            if remaining_stdout:
                                stdout_lines.append(remaining_stdout)
                            if remaining_stderr:
                                stderr_lines.append(remaining_stderr)
                            
                            result.exit_code = retcode
                            result.status = ExecutionStatus.COMPLETED
                            break
                        
                        # Small delay to prevent CPU spin
                        time.sleep(0.01)
                    
                finally:
                    self._running_processes.pop(proc_id, None)
                
                result.stdout = "".join(stdout_lines)
                result.stderr = "".join(stderr_lines)
                
            else:
                # Simple mode - wait for completion
                process = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=exec_env,
                    cwd=exec_cwd,
                )
                
                result.exit_code = process.returncode
                result.stdout = process.stdout
                result.stderr = process.stderr
                result.status = ExecutionStatus.COMPLETED
                
        except subprocess.TimeoutExpired as e:
            result.status = ExecutionStatus.TIMEOUT
            result.error_message = f"Command timed out after {timeout} seconds"
            # Capture partial output if available
            if hasattr(e, 'stdout') and e.stdout:
                result.stdout = e.stdout if isinstance(e.stdout, str) else e.stdout.decode()
            if hasattr(e, 'stderr') and e.stderr:
                result.stderr = e.stderr if isinstance(e.stderr, str) else e.stderr.decode()
                
        except Exception as e:
            result.status = ExecutionStatus.FAILED
            result.error_message = str(e)
        
        # Finalize timing
        result.completed_at = datetime.now()
        result.duration_seconds = (
            result.completed_at - result.started_at
        ).total_seconds()
        
        return result
    
    def execute_tool(
        self,
        tool: str,
        args: list[str],
        timeout: Optional[int] = None,
        env: Optional[dict] = None,
        cwd: Optional[Path] = None,
        on_output: Optional[Callable[[str], None]] = None,
    ) -> ExecutionResult:
        """
        Execute a specific tool with arguments.
        
        Args:
            tool: Tool name (e.g., "nmap")
            args: List of arguments
            timeout: Timeout in seconds
            env: Additional environment variables
            cwd: Working directory
            on_output: Callback for streaming output
            
        Returns:
            ExecutionResult
            
        Raises:
            ValueError: If tool is not available
        """
        if not self.check_tool(tool):
            return ExecutionResult(
                command=f"{tool} {' '.join(args)}",
                status=ExecutionStatus.FAILED,
                error_message=f"Tool not found: {tool}",
                started_at=datetime.now(),
                completed_at=datetime.now(),
            )
        
        # Build command
        command = f"{tool} {' '.join(args)}"
        
        return self.execute(
            command=command,
            timeout=timeout,
            env=env,
            cwd=cwd,
            on_output=on_output,
        )
    
    def cancel_all(self) -> int:
        """
        Cancel all running processes.
        
        Returns:
            Number of processes cancelled
        """
        cancelled = 0
        
        for proc_id, process in list(self._running_processes.items()):
            try:
                process.terminate()
                time.sleep(0.1)
                if process.poll() is None:
                    process.kill()
                cancelled += 1
            except Exception:
                pass
            finally:
                self._running_processes.pop(proc_id, None)
        
        return cancelled


def check_kali_environment() -> dict:
    """
    Check if running on Kali Linux and verify tool availability.

    Returns:
        Dictionary with environment check results
    """
    result = {
        "is_kali": False,
        "os_info": None,
        "tools": {},
        "missing_tools": [],
        "ready": False,
    }

    # Check OS
    try:
        with open("/etc/os-release") as f:
            os_release = f.read()
            result["os_info"] = os_release
            result["is_kali"] = "kali" in os_release.lower()
    except FileNotFoundError:
        pass

    # Check required tools
    executor = NativeExecutor()
    required_tools = [
        "nmap",
        "gobuster",
        "nikto",
        "sqlmap",
        "curl",
        "wget",
    ]

    for tool in required_tools:
        available = executor.check_tool(tool)
        result["tools"][tool] = {
            "available": available,
            "version": executor.get_tool_version(tool) if available else None,
            "path": executor.get_tool_path(tool),
        }
        if not available:
            result["missing_tools"].append(tool)

    # Determine readiness
    # Require at least nmap for basic functionality
    result["ready"] = (
        result["is_kali"] and
        result["tools"].get("nmap", {}).get("available", False)
    )

    return result


# ─────────────────────────────────────────────────────────────────────
#  UnifiedExecutor — platform-aware router
# ─────────────────────────────────────────────────────────────────────

class UnifiedExecutor:
    """
    Platform-aware executor that routes commands to the correct backend.

    On native Kali Linux → uses subprocess directly (NativeExecutor).
    On all other platforms → uses the kestrel-tools Docker container.
    If neither is available → returns FAILED results with clear error messages.

    This is the preferred executor for all new code. It accepts the same
    arguments as NativeExecutor so it is a drop-in replacement.

    Usage:
        executor = UnifiedExecutor()
        result = executor.execute("nmap -sV target.example.com", timeout=300)
        if result.success:
            print(result.stdout)
    """

    def __init__(self, platform_info=None) -> None:
        """
        Initialise the executor.

        Args:
            platform_info: PlatformInfo instance. Auto-detected if None.
        """
        # Lazy import to avoid circular dependency at module level
        from kestrel.core.platform import get_platform, ExecutionMode
        from kestrel.core.docker_manager import DockerManager

        self._platform = platform_info or get_platform()
        self._ExecutionMode = ExecutionMode

        if self._platform.execution_mode == ExecutionMode.NATIVE:
            self._backend = NativeExecutor(
                working_dir=Path("/workspace") if Path("/workspace").exists() else Path.home()
            )
            self._docker: Optional["DockerManager"] = None
        elif self._platform.execution_mode == ExecutionMode.DOCKER:
            self._backend = None
            self._docker = DockerManager()
        else:
            self._backend = None
            self._docker = None

    # ─── Core execution ───────────────────────────────────────────────

    def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        env: Optional[dict] = None,
        cwd: Optional[Path] = None,
        on_output: Optional[Callable[[str], None]] = None,
    ) -> ExecutionResult:
        """
        Execute a command on the appropriate backend.

        Args:
            command:   Shell command string to run.
            timeout:   Timeout in seconds (None = no limit).
            env:       Extra environment variables (native only; Docker ignores).
            cwd:       Working directory override (native: local path;
                       Docker: path inside container, defaults to /workspace).
            on_output: Streaming output callback (native only; Docker buffers).

        Returns:
            ExecutionResult with stdout, stderr, status, and timing.
        """
        from kestrel.core.platform import ExecutionMode

        mode = self._platform.execution_mode

        if mode == ExecutionMode.NATIVE:
            return self._backend.execute(
                command=command,
                timeout=timeout,
                env=env,
                cwd=cwd,
                on_output=on_output,
            )

        if mode == ExecutionMode.DOCKER:
            workdir = str(cwd) if cwd else "/workspace"
            return self._docker.exec_command(
                command=command,
                workdir=workdir,
                timeout=timeout,
            )

        # ExecutionMode.UNAVAILABLE
        started_at = datetime.now()
        return ExecutionResult(
            command=command,
            status=ExecutionStatus.FAILED,
            error_message=(
                "No tool execution environment available. "
                "Install Docker (https://docs.docker.com/get-docker/) "
                "or run Kestrel on native Kali Linux."
            ),
            started_at=started_at,
            completed_at=started_at,
            duration_seconds=0.0,
        )

    def execute_tool(
        self,
        tool: str,
        args: list[str],
        timeout: Optional[int] = None,
        env: Optional[dict] = None,
        cwd: Optional[Path] = None,
        on_output: Optional[Callable[[str], None]] = None,
    ) -> ExecutionResult:
        """
        Execute a specific tool with arguments.

        Checks tool availability before executing. Returns a FAILED result
        if the tool is not found rather than raising an exception.

        Args:
            tool:      Tool binary name (e.g. "nmap").
            args:      Argument list.
            timeout:   Timeout in seconds.
            env:       Extra environment variables.
            cwd:       Working directory.
            on_output: Streaming callback.

        Returns:
            ExecutionResult
        """
        if not self.check_tool(tool):
            started_at = datetime.now()
            return ExecutionResult(
                command=f"{tool} {' '.join(args)}",
                status=ExecutionStatus.FAILED,
                error_message=f"Tool not found: {tool}",
                started_at=started_at,
                completed_at=started_at,
                duration_seconds=0.0,
            )

        command = f"{tool} {' '.join(str(a) for a in args)}"
        return self.execute(
            command=command,
            timeout=timeout,
            env=env,
            cwd=cwd,
            on_output=on_output,
        )

    # ─── Tool inspection ──────────────────────────────────────────────

    def check_tool(self, tool: str) -> bool:
        """True if `tool` is available on the active backend."""
        from kestrel.core.platform import ExecutionMode
        if self._platform.execution_mode == ExecutionMode.NATIVE:
            return self._backend.check_tool(tool)
        if self._platform.execution_mode == ExecutionMode.DOCKER:
            return self._docker.check_tool(tool)
        return False

    def get_tool_version(self, tool: str) -> Optional[str]:
        """Return version string for `tool` on the active backend, or None."""
        from kestrel.core.platform import ExecutionMode
        if self._platform.execution_mode == ExecutionMode.NATIVE:
            return self._backend.get_tool_version(tool)
        if self._platform.execution_mode == ExecutionMode.DOCKER:
            return self._docker.get_tool_version(tool)
        return None

    def cancel_all(self) -> int:
        """Cancel all running processes (native mode only; no-op for Docker)."""
        from kestrel.core.platform import ExecutionMode
        if self._platform.execution_mode == ExecutionMode.NATIVE:
            return self._backend.cancel_all()
        return 0

    # ─── Introspection ────────────────────────────────────────────────

    @property
    def execution_mode(self) -> str:
        """Current execution mode value string ('native', 'docker', 'unavailable')."""
        return self._platform.execution_mode.value

    @property
    def platform(self):
        """The PlatformInfo this executor was configured for."""
        return self._platform

    def status(self) -> dict:
        """Return a status summary for health checks and debugging."""
        from kestrel.core.platform import ExecutionMode
        base = {
            "execution_mode": self._platform.execution_mode.value,
            "llm_backend": self._platform.llm_backend.value,
            "platform_summary": self._platform.summary,
        }
        if self._platform.execution_mode == ExecutionMode.DOCKER and self._docker:
            base["docker"] = self._docker.status()
        return base
