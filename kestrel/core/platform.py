"""
Kestrel Platform Detector

Auto-detects the runtime environment and returns a PlatformInfo dataclass
consumed by the executor and LLM backend factory. No configuration required —
detection is fully automatic.

Detection order:
  LLM backend:
    1. Apple Silicon (arm64 + Darwin) → MLX
    2. CUDA GPU available             → Ollama + CUDA
    3. Vulkan GPU available           → Ollama + Vulkan
    4. Everything else                → Ollama CPU

  Tool execution:
    1. Native Kali Linux              → subprocess (bypass Docker)
    2. Docker available               → Kali container
    3. Neither                        → error with install instructions
"""

import platform
import shutil
import subprocess
import os
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
#  Enums
# ─────────────────────────────────────────────────────────────────────

class ExecutionMode(Enum):
    """How Kestrel executes security tools."""
    NATIVE = "native"    # Direct subprocess on Kali Linux
    DOCKER = "docker"    # Via Kali container
    UNAVAILABLE = "unavailable"  # Neither Kali nor Docker found


class LLMBackendType(Enum):
    """Which local LLM backend to use."""
    MLX = "mlx"              # Apple Silicon — Neural Engine + unified memory
    OLLAMA_CUDA = "ollama_cuda"    # NVIDIA GPU
    OLLAMA_VULKAN = "ollama_vulkan"  # Intel Xe, AMD, other Vulkan GPUs
    OLLAMA_CPU = "ollama_cpu"    # CPU-only fallback
    ANTHROPIC_ONLY = "anthropic_only"  # No local LLM available


# ─────────────────────────────────────────────────────────────────────
#  Model size recommendations by RAM
# ─────────────────────────────────────────────────────────────────────

# (min_ram_gb, mlx_model, ollama_model)
_MODEL_TIERS = [
    (128, "mlx-community/Meta-Llama-3.1-70B-Instruct-4bit", "llama3.1:70b"),
    (64,  "mlx-community/Meta-Llama-3.1-34B-Instruct-4bit", "llama3.1:70b-instruct-q4_K_M"),
    (32,  "mlx-community/Qwen2.5-Coder-14B-Instruct-4bit",  "qwen2.5-coder:14b"),
    (16,  "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit",  "llama3.1:8b"),
    (8,   "mlx-community/Mistral-7B-Instruct-v0.3-4bit",    "llama3.2:3b"),
    (0,   "mlx-community/Mistral-7B-Instruct-v0.3-4bit",    "llama3.2:3b"),
]


def _recommended_models(ram_gb: int, backend: LLMBackendType) -> tuple[str, str]:
    """Return (primary_model, fallback_model) for the given RAM and backend."""
    for min_ram, mlx_model, ollama_model in _MODEL_TIERS:
        if ram_gb >= min_ram:
            if backend == LLMBackendType.MLX:
                return mlx_model, ollama_model
            return ollama_model, "llama3.2:3b"
    return "llama3.2:3b", "llama3.2:3b"


# ─────────────────────────────────────────────────────────────────────
#  PlatformInfo dataclass
# ─────────────────────────────────────────────────────────────────────

@dataclass
class PlatformInfo:
    """
    Describes the runtime environment Kestrel is running in.

    Created once at startup by detect_platform(). Consumed by:
      - UnifiedExecutor  → selects NATIVE or DOCKER mode
      - BackendFactory   → selects MLX, Ollama, or Anthropic
    """
    # OS and arch
    os_name: str              # "darwin", "linux", "windows"
    arch: str                 # "arm64", "x86_64", "amd64"
    os_version: str           # e.g. "Darwin 25.3.0", "Kali GNU/Linux Rolling"

    # Hardware
    is_apple_silicon: bool    # arm64 + Darwin
    is_kali: bool             # Running on native Kali Linux
    has_cuda: bool            # NVIDIA GPU with CUDA
    has_vulkan: bool          # Vulkan-capable GPU (Intel Xe, AMD, etc.)
    has_docker: bool          # Docker daemon is available and responding
    ram_gb: int               # Total system RAM in GB

    # Resolved modes
    execution_mode: ExecutionMode
    llm_backend: LLMBackendType

    # Model recommendations
    recommended_model: str    # Primary local model for this hardware
    fallback_model: str       # Smaller fallback if primary won't fit

    # Human-readable summary
    summary: str = field(default="", repr=False)

    def can_run_tools(self) -> bool:
        """True if tool execution is possible (native or Docker)."""
        return self.execution_mode in (ExecutionMode.NATIVE, ExecutionMode.DOCKER)

    def uses_local_llm(self) -> bool:
        """True if a local LLM backend is available."""
        return self.llm_backend != LLMBackendType.ANTHROPIC_ONLY

    def to_dict(self) -> dict:
        return {
            "os_name": self.os_name,
            "arch": self.arch,
            "os_version": self.os_version,
            "is_apple_silicon": self.is_apple_silicon,
            "is_kali": self.is_kali,
            "has_cuda": self.has_cuda,
            "has_vulkan": self.has_vulkan,
            "has_docker": self.has_docker,
            "ram_gb": self.ram_gb,
            "execution_mode": self.execution_mode.value,
            "llm_backend": self.llm_backend.value,
            "recommended_model": self.recommended_model,
            "fallback_model": self.fallback_model,
        }


# ─────────────────────────────────────────────────────────────────────
#  Individual detectors
# ─────────────────────────────────────────────────────────────────────

def _detect_os() -> tuple[str, str, str]:
    """Return (os_name, arch, os_version)."""
    os_name = platform.system().lower()   # "darwin", "linux", "windows"
    arch = platform.machine().lower()     # "arm64", "x86_64", "amd64"
    # Normalise amd64 → x86_64 for consistency
    if arch == "amd64":
        arch = "x86_64"
    os_version = f"{platform.system()} {platform.release()}"
    return os_name, arch, os_version


def _detect_apple_silicon(os_name: str, arch: str) -> bool:
    """True only on arm64 macOS (M1/M2/M3/M4)."""
    return os_name == "darwin" and arch == "arm64"


def _detect_kali() -> bool:
    """True if /etc/os-release identifies this as Kali Linux."""
    try:
        os_release = Path("/etc/os-release").read_text()
        return "kali" in os_release.lower()
    except (FileNotFoundError, PermissionError):
        return False


def _detect_cuda() -> bool:
    """True if nvidia-smi is available and reports a GPU."""
    if not shutil.which("nvidia-smi"):
        return False
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except (subprocess.TimeoutExpired, OSError):
        return False


def _detect_vulkan() -> bool:
    """True if vulkaninfo is available and reports a device."""
    if not shutil.which("vulkaninfo"):
        return False
    try:
        result = subprocess.run(
            ["vulkaninfo", "--summary"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0 and "GPU" in result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return False


def _detect_docker() -> bool:
    """True if Docker CLI is present and daemon is responding."""
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except (subprocess.TimeoutExpired, OSError):
        return False


def _detect_ram_gb() -> int:
    """Return total system RAM in GB. Uses psutil if available, else /proc/meminfo."""
    try:
        import psutil
        return int(psutil.virtual_memory().total / (1024 ** 3))
    except ImportError:
        pass

    # Fallback: /proc/meminfo (Linux)
    try:
        meminfo = Path("/proc/meminfo").read_text()
        for line in meminfo.splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                return kb // (1024 * 1024)
    except (FileNotFoundError, ValueError, IndexError):
        pass

    # Fallback: sysctl (macOS)
    try:
        result = subprocess.run(
            ["sysctl", "-n", "hw.memsize"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return int(result.stdout.strip()) // (1024 ** 3)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass

    logger.warning("Could not detect RAM size — assuming 8 GB")
    return 8


def _resolve_execution_mode(is_kali: bool, has_docker: bool) -> ExecutionMode:
    """Select execution mode from detected environment."""
    if is_kali:
        return ExecutionMode.NATIVE
    if has_docker:
        return ExecutionMode.DOCKER
    return ExecutionMode.UNAVAILABLE


def _resolve_llm_backend(
    is_apple_silicon: bool,
    has_cuda: bool,
    has_vulkan: bool,
) -> LLMBackendType:
    """Select local LLM backend from detected hardware."""
    if is_apple_silicon:
        return LLMBackendType.MLX
    if has_cuda:
        return LLMBackendType.OLLAMA_CUDA
    if has_vulkan:
        return LLMBackendType.OLLAMA_VULKAN
    return LLMBackendType.OLLAMA_CPU


def _build_summary(info_dict: dict) -> str:
    """Build a human-readable one-liner summary."""
    mode = info_dict["execution_mode"]
    backend = info_dict["llm_backend"]
    ram = info_dict["ram_gb"]
    arch = info_dict["arch"]
    model = info_dict["recommended_model"].split("/")[-1]

    exec_str = {
        "native": "Native Kali",
        "docker": "Docker (Kali container)",
        "unavailable": "UNAVAILABLE — install Docker or run on Kali",
    }.get(mode, mode)

    llm_str = {
        "mlx": "MLX (Apple Silicon)",
        "ollama_cuda": "Ollama + CUDA",
        "ollama_vulkan": "Ollama + Vulkan",
        "ollama_cpu": "Ollama (CPU)",
        "anthropic_only": "Anthropic API only",
    }.get(backend, backend)

    return (
        f"Tools: {exec_str} | "
        f"LLM: {llm_str} | "
        f"RAM: {ram} GB ({arch}) | "
        f"Model: {model}"
    )


# ─────────────────────────────────────────────────────────────────────
#  Main entry point
# ─────────────────────────────────────────────────────────────────────

def detect_platform() -> PlatformInfo:
    """
    Detect the runtime environment and return a PlatformInfo.

    This is the single entry point. Call it once at startup and pass
    the result to the executor and LLM factory.

    Returns:
        PlatformInfo with all detected capabilities and resolved modes.
    """
    os_name, arch, os_version = _detect_os()
    is_apple_silicon = _detect_apple_silicon(os_name, arch)
    is_kali = _detect_kali()
    has_cuda = _detect_cuda()
    has_vulkan = _detect_vulkan()
    has_docker = _detect_docker()
    ram_gb = _detect_ram_gb()

    execution_mode = _resolve_execution_mode(is_kali, has_docker)
    llm_backend = _resolve_llm_backend(is_apple_silicon, has_cuda, has_vulkan)

    recommended_model, fallback_model = _recommended_models(ram_gb, llm_backend)

    info = PlatformInfo(
        os_name=os_name,
        arch=arch,
        os_version=os_version,
        is_apple_silicon=is_apple_silicon,
        is_kali=is_kali,
        has_cuda=has_cuda,
        has_vulkan=has_vulkan,
        has_docker=has_docker,
        ram_gb=ram_gb,
        execution_mode=execution_mode,
        llm_backend=llm_backend,
        recommended_model=recommended_model,
        fallback_model=fallback_model,
    )
    info.summary = _build_summary(info.to_dict())

    if execution_mode == ExecutionMode.UNAVAILABLE:
        logger.warning(
            "No tool execution environment found. "
            "Install Docker (https://docs.docker.com/get-docker/) "
            "or run Kestrel on native Kali Linux."
        )

    return info


# ─────────────────────────────────────────────────────────────────────
#  Singleton cache
# ─────────────────────────────────────────────────────────────────────

_platform_info: Optional[PlatformInfo] = None


def get_platform() -> PlatformInfo:
    """Return the cached PlatformInfo, detecting once on first call."""
    global _platform_info
    if _platform_info is None:
        _platform_info = detect_platform()
    return _platform_info


def reset_platform() -> None:
    """Reset the cached PlatformInfo. Used in tests."""
    global _platform_info
    _platform_info = None
