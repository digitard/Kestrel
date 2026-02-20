"""
Phase 1 — Executor Tests

Tests for:
  - PlatformInfo detection (mocked)
  - UnifiedExecutor routing (native / docker / unavailable)
  - DockerManager (subprocess calls mocked)
  - Backward-compat: NativeExecutor, ExecutionResult, ExecutionStatus,
    check_kali_environment still importable from kestrel.core
"""

import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))


# ─────────────────────────────────────────────────────────────────────
#  Backward-compat imports (must not break)
# ─────────────────────────────────────────────────────────────────────

class TestBackwardCompatImports:
    """Legacy Phase 1 exports must remain importable from kestrel.core."""

    def test_import_native_executor(self):
        from kestrel.core import NativeExecutor
        assert NativeExecutor is not None

    def test_import_execution_result(self):
        from kestrel.core import ExecutionResult
        assert ExecutionResult is not None

    def test_import_execution_status(self):
        from kestrel.core import ExecutionStatus
        assert ExecutionStatus is not None

    def test_import_check_kali_environment(self):
        from kestrel.core import check_kali_environment
        assert callable(check_kali_environment)

    def test_import_unified_executor(self):
        from kestrel.core import UnifiedExecutor
        assert UnifiedExecutor is not None

    def test_import_platform_types(self):
        from kestrel.core import PlatformInfo, ExecutionMode, LLMBackendType
        assert PlatformInfo is not None
        assert ExecutionMode is not None
        assert LLMBackendType is not None

    def test_import_docker_manager(self):
        from kestrel.core import DockerManager
        assert DockerManager is not None


# ─────────────────────────────────────────────────────────────────────
#  PlatformInfo
# ─────────────────────────────────────────────────────────────────────

class TestPlatformInfo:
    """PlatformInfo dataclass contracts."""

    def _make_platform(self, execution_mode, llm_backend):
        from kestrel.core.platform import PlatformInfo, ExecutionMode, LLMBackendType
        return PlatformInfo(
            os_name="darwin",
            arch="arm64",
            os_version="Darwin 25.0",
            is_apple_silicon=True,
            is_kali=False,
            has_cuda=False,
            has_vulkan=False,
            has_docker=True,
            ram_gb=32,
            execution_mode=execution_mode,
            llm_backend=llm_backend,
            recommended_model="mlx-community/Qwen2.5-Coder-14B-Instruct-4bit",
            fallback_model="llama3.2:3b",
        )

    def test_can_run_tools_native(self):
        from kestrel.core.platform import ExecutionMode, LLMBackendType
        p = self._make_platform(ExecutionMode.NATIVE, LLMBackendType.MLX)
        assert p.can_run_tools() is True

    def test_can_run_tools_docker(self):
        from kestrel.core.platform import ExecutionMode, LLMBackendType
        p = self._make_platform(ExecutionMode.DOCKER, LLMBackendType.MLX)
        assert p.can_run_tools() is True

    def test_cannot_run_tools_unavailable(self):
        from kestrel.core.platform import ExecutionMode, LLMBackendType
        p = self._make_platform(ExecutionMode.UNAVAILABLE, LLMBackendType.ANTHROPIC_ONLY)
        assert p.can_run_tools() is False

    def test_uses_local_llm(self):
        from kestrel.core.platform import ExecutionMode, LLMBackendType
        p = self._make_platform(ExecutionMode.DOCKER, LLMBackendType.MLX)
        assert p.uses_local_llm() is True

    def test_anthropic_only_no_local_llm(self):
        from kestrel.core.platform import ExecutionMode, LLMBackendType
        p = self._make_platform(ExecutionMode.UNAVAILABLE, LLMBackendType.ANTHROPIC_ONLY)
        assert p.uses_local_llm() is False

    def test_to_dict_has_required_keys(self):
        from kestrel.core.platform import ExecutionMode, LLMBackendType
        p = self._make_platform(ExecutionMode.DOCKER, LLMBackendType.MLX)
        d = p.to_dict()
        for key in ("os_name", "arch", "execution_mode", "llm_backend",
                    "recommended_model", "fallback_model", "ram_gb"):
            assert key in d

    def test_summary_is_populated(self):
        from kestrel.core.platform import ExecutionMode, LLMBackendType, _build_summary
        p = self._make_platform(ExecutionMode.DOCKER, LLMBackendType.MLX)
        p.summary = _build_summary(p.to_dict())
        assert len(p.summary) > 10
        assert "MLX" in p.summary or "Docker" in p.summary


# ─────────────────────────────────────────────────────────────────────
#  Platform detection helpers (unit-level, fully mocked)
# ─────────────────────────────────────────────────────────────────────

class TestPlatformDetection:
    """Unit tests for individual detection helpers."""

    def test_detect_apple_silicon_true(self):
        from kestrel.core.platform import _detect_apple_silicon
        assert _detect_apple_silicon("darwin", "arm64") is True

    def test_detect_apple_silicon_false_intel_mac(self):
        from kestrel.core.platform import _detect_apple_silicon
        assert _detect_apple_silicon("darwin", "x86_64") is False

    def test_detect_apple_silicon_false_linux_arm(self):
        from kestrel.core.platform import _detect_apple_silicon
        assert _detect_apple_silicon("linux", "arm64") is False

    def test_detect_kali_false_on_mac(self):
        from kestrel.core.platform import _detect_kali
        # macOS has no /etc/os-release → returns False
        with patch("kestrel.core.platform.Path") as mock_path:
            mock_path.return_value.read_text.side_effect = FileNotFoundError
            # Patch the module-level Path in _detect_kali
        result = _detect_kali()
        assert result is False  # macOS runner will not have /etc/os-release with kali

    def test_resolve_execution_mode_native_on_kali(self):
        from kestrel.core.platform import _resolve_execution_mode, ExecutionMode
        mode = _resolve_execution_mode(is_kali=True, has_docker=False)
        assert mode == ExecutionMode.NATIVE

    def test_resolve_execution_mode_docker_on_non_kali(self):
        from kestrel.core.platform import _resolve_execution_mode, ExecutionMode
        mode = _resolve_execution_mode(is_kali=False, has_docker=True)
        assert mode == ExecutionMode.DOCKER

    def test_resolve_execution_mode_unavailable(self):
        from kestrel.core.platform import _resolve_execution_mode, ExecutionMode
        mode = _resolve_execution_mode(is_kali=False, has_docker=False)
        assert mode == ExecutionMode.UNAVAILABLE

    def test_resolve_llm_backend_apple_silicon(self):
        from kestrel.core.platform import _resolve_llm_backend, LLMBackendType
        backend = _resolve_llm_backend(is_apple_silicon=True, has_cuda=False, has_vulkan=False)
        assert backend == LLMBackendType.MLX

    def test_resolve_llm_backend_cuda(self):
        from kestrel.core.platform import _resolve_llm_backend, LLMBackendType
        backend = _resolve_llm_backend(is_apple_silicon=False, has_cuda=True, has_vulkan=False)
        assert backend == LLMBackendType.OLLAMA_CUDA

    def test_resolve_llm_backend_vulkan(self):
        from kestrel.core.platform import _resolve_llm_backend, LLMBackendType
        backend = _resolve_llm_backend(is_apple_silicon=False, has_cuda=False, has_vulkan=True)
        assert backend == LLMBackendType.OLLAMA_VULKAN

    def test_resolve_llm_backend_cpu_fallback(self):
        from kestrel.core.platform import _resolve_llm_backend, LLMBackendType
        backend = _resolve_llm_backend(is_apple_silicon=False, has_cuda=False, has_vulkan=False)
        assert backend == LLMBackendType.OLLAMA_CPU

    def test_recommended_models_apple_silicon_32gb(self):
        from kestrel.core.platform import _recommended_models, LLMBackendType
        primary, fallback = _recommended_models(32, LLMBackendType.MLX)
        assert "mlx-community" in primary
        assert fallback  # has a fallback

    def test_recommended_models_ollama_8gb(self):
        from kestrel.core.platform import _recommended_models, LLMBackendType
        primary, fallback = _recommended_models(8, LLMBackendType.OLLAMA_CPU)
        assert "llama" in primary or "mistral" in primary.lower()

    def test_get_platform_singleton(self):
        from kestrel.core.platform import get_platform, reset_platform
        reset_platform()
        p1 = get_platform()
        p2 = get_platform()
        assert p1 is p2
        reset_platform()

    def test_detect_platform_returns_platform_info(self):
        from kestrel.core.platform import detect_platform, PlatformInfo
        info = detect_platform()
        assert isinstance(info, PlatformInfo)
        assert info.os_name in ("darwin", "linux", "windows")
        assert info.ram_gb > 0
        assert info.summary  # non-empty summary


# ─────────────────────────────────────────────────────────────────────
#  UnifiedExecutor — native routing
# ─────────────────────────────────────────────────────────────────────

class TestUnifiedExecutorNative:
    """UnifiedExecutor in NATIVE mode uses NativeExecutor backend."""

    def _make_native_platform(self):
        from kestrel.core.platform import (
            PlatformInfo, ExecutionMode, LLMBackendType, _build_summary
        )
        p = PlatformInfo(
            os_name="linux",
            arch="x86_64",
            os_version="Kali GNU/Linux Rolling",
            is_apple_silicon=False,
            is_kali=True,
            has_cuda=False,
            has_vulkan=False,
            has_docker=False,
            ram_gb=32,
            execution_mode=ExecutionMode.NATIVE,
            llm_backend=LLMBackendType.OLLAMA_CPU,
            recommended_model="qwen2.5-coder:14b",
            fallback_model="llama3.2:3b",
        )
        p.summary = _build_summary(p.to_dict())
        return p

    def test_execution_mode_property(self):
        from kestrel.core.executor import UnifiedExecutor
        platform = self._make_native_platform()
        executor = UnifiedExecutor(platform_info=platform)
        assert executor.execution_mode == "native"

    def test_execute_routes_to_native(self):
        from kestrel.core.executor import UnifiedExecutor, ExecutionStatus
        platform = self._make_native_platform()
        executor = UnifiedExecutor(platform_info=platform)

        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "echo output\n"
            mock_proc.stderr = ""
            mock_run.return_value = mock_proc

            result = executor.execute("echo hello")

        assert result.status == ExecutionStatus.COMPLETED
        assert result.exit_code == 0

    def test_execute_tool_not_found(self):
        from kestrel.core.executor import UnifiedExecutor, ExecutionStatus
        platform = self._make_native_platform()
        executor = UnifiedExecutor(platform_info=platform)

        with patch("shutil.which", return_value=None):
            result = executor.execute_tool("nonexistent_tool_xyz", ["-v"])

        assert result.status == ExecutionStatus.FAILED
        assert "not found" in result.error_message.lower()

    def test_check_tool_native(self):
        from kestrel.core.executor import UnifiedExecutor
        platform = self._make_native_platform()
        executor = UnifiedExecutor(platform_info=platform)

        with patch("shutil.which", return_value="/usr/bin/nmap"):
            assert executor.check_tool("nmap") is True

        with patch("shutil.which", return_value=None):
            assert executor.check_tool("nonexistent_xyz") is False

    def test_status_returns_dict(self):
        from kestrel.core.executor import UnifiedExecutor
        platform = self._make_native_platform()
        executor = UnifiedExecutor(platform_info=platform)
        s = executor.status()
        assert s["execution_mode"] == "native"
        assert "llm_backend" in s


# ─────────────────────────────────────────────────────────────────────
#  UnifiedExecutor — Docker routing
# ─────────────────────────────────────────────────────────────────────

class TestUnifiedExecutorDocker:
    """UnifiedExecutor in DOCKER mode delegates to DockerManager."""

    def _make_docker_platform(self):
        from kestrel.core.platform import (
            PlatformInfo, ExecutionMode, LLMBackendType, _build_summary
        )
        p = PlatformInfo(
            os_name="darwin",
            arch="arm64",
            os_version="Darwin 25.3.0",
            is_apple_silicon=True,
            is_kali=False,
            has_cuda=False,
            has_vulkan=False,
            has_docker=True,
            ram_gb=32,
            execution_mode=ExecutionMode.DOCKER,
            llm_backend=LLMBackendType.MLX,
            recommended_model="mlx-community/Qwen2.5-Coder-14B-Instruct-4bit",
            fallback_model="llama3.2:3b",
        )
        p.summary = _build_summary(p.to_dict())
        return p

    def test_execution_mode_property(self):
        from kestrel.core.executor import UnifiedExecutor
        platform = self._make_docker_platform()
        executor = UnifiedExecutor(platform_info=platform)
        assert executor.execution_mode == "docker"

    def test_execute_delegates_to_docker_manager(self):
        from kestrel.core.executor import UnifiedExecutor, ExecutionStatus
        from kestrel.core.executor import ExecutionResult

        platform = self._make_docker_platform()
        executor = UnifiedExecutor(platform_info=platform)

        mock_result = ExecutionResult(
            command="nmap -sV target",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            stdout="Nmap scan report",
            stderr="",
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )

        with patch.object(executor._docker, "exec_command", return_value=mock_result):
            result = executor.execute("nmap -sV target")

        assert result.success
        assert "Nmap" in result.stdout

    def test_check_tool_delegates_to_docker(self):
        from kestrel.core.executor import UnifiedExecutor
        platform = self._make_docker_platform()
        executor = UnifiedExecutor(platform_info=platform)

        with patch.object(executor._docker, "check_tool", return_value=True):
            assert executor.check_tool("nmap") is True

        with patch.object(executor._docker, "check_tool", return_value=False):
            assert executor.check_tool("nonexistent") is False

    def test_status_includes_docker_info(self):
        from kestrel.core.executor import UnifiedExecutor
        platform = self._make_docker_platform()
        executor = UnifiedExecutor(platform_info=platform)

        with patch.object(executor._docker, "status", return_value={"container_running": False}):
            s = executor.status()

        assert s["execution_mode"] == "docker"
        assert "docker" in s


# ─────────────────────────────────────────────────────────────────────
#  UnifiedExecutor — unavailable mode
# ─────────────────────────────────────────────────────────────────────

class TestUnifiedExecutorUnavailable:
    """UnifiedExecutor returns FAILED results when no backend is available."""

    def _make_unavailable_platform(self):
        from kestrel.core.platform import (
            PlatformInfo, ExecutionMode, LLMBackendType, _build_summary
        )
        p = PlatformInfo(
            os_name="windows",
            arch="x86_64",
            os_version="Windows 11",
            is_apple_silicon=False,
            is_kali=False,
            has_cuda=False,
            has_vulkan=False,
            has_docker=False,
            ram_gb=16,
            execution_mode=ExecutionMode.UNAVAILABLE,
            llm_backend=LLMBackendType.ANTHROPIC_ONLY,
            recommended_model="",
            fallback_model="",
        )
        p.summary = _build_summary(p.to_dict())
        return p

    def test_execute_returns_failed(self):
        from kestrel.core.executor import UnifiedExecutor, ExecutionStatus
        platform = self._make_unavailable_platform()
        executor = UnifiedExecutor(platform_info=platform)
        result = executor.execute("nmap -sV target")
        assert result.status == ExecutionStatus.FAILED
        assert result.error_message

    def test_check_tool_returns_false(self):
        from kestrel.core.executor import UnifiedExecutor
        platform = self._make_unavailable_platform()
        executor = UnifiedExecutor(platform_info=platform)
        assert executor.check_tool("nmap") is False

    def test_cancel_all_returns_zero(self):
        from kestrel.core.executor import UnifiedExecutor
        platform = self._make_unavailable_platform()
        executor = UnifiedExecutor(platform_info=platform)
        assert executor.cancel_all() == 0

    def test_error_message_mentions_docker(self):
        from kestrel.core.executor import UnifiedExecutor
        platform = self._make_unavailable_platform()
        executor = UnifiedExecutor(platform_info=platform)
        result = executor.execute("nmap target")
        assert "docker" in result.error_message.lower() or "kali" in result.error_message.lower()


# ─────────────────────────────────────────────────────────────────────
#  ExecutionResult
# ─────────────────────────────────────────────────────────────────────

class TestExecutionResult:
    """ExecutionResult contracts."""

    def test_success_true_on_zero_exit(self):
        from kestrel.core.executor import ExecutionResult, ExecutionStatus
        r = ExecutionResult(
            command="echo hi",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )
        assert r.success is True

    def test_success_false_on_nonzero_exit(self):
        from kestrel.core.executor import ExecutionResult, ExecutionStatus
        r = ExecutionResult(
            command="false",
            status=ExecutionStatus.COMPLETED,
            exit_code=1,
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )
        assert r.success is False

    def test_success_false_on_timeout(self):
        from kestrel.core.executor import ExecutionResult, ExecutionStatus
        r = ExecutionResult(
            command="sleep 1000",
            status=ExecutionStatus.TIMEOUT,
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )
        assert r.success is False

    def test_to_dict_contains_all_keys(self):
        from kestrel.core.executor import ExecutionResult, ExecutionStatus
        r = ExecutionResult(
            command="nmap -sV target",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            stdout="results here",
            stderr="",
            started_at=datetime.now(),
            completed_at=datetime.now(),
            duration_seconds=1.23,
        )
        d = r.to_dict()
        for key in ("command", "status", "exit_code", "stdout", "stderr",
                    "duration_seconds", "success"):
            assert key in d
