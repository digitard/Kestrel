# Kestrel — LLM-assisted bug bounty hunting platform
# Copyright (C) 2026 David Kuznicki and Kestrel Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Backend factory — creates the appropriate LLM backend from platform info.

Uses PlatformInfo (detected at startup) instead of ad-hoc platform checks.
Resolution order:

  LLM mode from config:
    "api"    → AnthropicBackend (cloud only)
    "local"  → MLXBackend on Apple Silicon, else OllamaBackend
    "hybrid" → HybridRouter (local + API, complexity-routed)
    "auto"   → same as "hybrid"

  Local backend selection (within "local" or "hybrid"):
    LLMBackendType.MLX         → MLXBackend
    LLMBackendType.OLLAMA_*    → OllamaBackend (Ollama handles CUDA/Vulkan internally)
    LLMBackendType.ANTHROPIC_ONLY → raise — caller must use "api" mode
"""

import logging

from kestrel.core.platform import LLMBackendType, get_platform

logger = logging.getLogger(__name__)


def _create_local_backend(platform_info=None):
    """Create a local backend based on detected hardware.

    Args:
        platform_info: PlatformInfo to use (defaults to get_platform()).

    Returns:
        An object satisfying the LLMBackend protocol.

    Raises:
        RuntimeError: If no local LLM backend is available.
    """
    if platform_info is None:
        platform_info = get_platform()

    backend_type = platform_info.llm_backend

    if backend_type == LLMBackendType.MLX:
        from kestrel.llm.mlx_backend import MLXBackend
        logger.info("Local LLM: MLX (Apple Silicon)")
        return MLXBackend()

    if backend_type in (
        LLMBackendType.OLLAMA_CPU,
        LLMBackendType.OLLAMA_CUDA,
        LLMBackendType.OLLAMA_VULKAN,
    ):
        from kestrel.llm.ollama_backend import OllamaBackend
        logger.info("Local LLM: Ollama (%s)", backend_type.value)
        return OllamaBackend()

    raise RuntimeError(
        "No local LLM backend available on this platform. "
        "Set llm.mode to 'api' in config to use the Anthropic API instead."
    )


def create_backend(mode: str | None = None, platform_info=None):
    """Create an LLM backend for the given mode.

    Args:
        mode: "api", "local", "hybrid", or "auto". If None, defaults to "hybrid".
        platform_info: PlatformInfo to use (defaults to get_platform()).

    Returns:
        An object satisfying the LLMBackend protocol.

    Raises:
        ValueError: If mode is unrecognized.
        RuntimeError: If a required backend is unavailable.
    """
    if platform_info is None:
        platform_info = get_platform()

    resolved_mode = mode or "hybrid"

    if resolved_mode == "api":
        from kestrel.llm.anthropic_backend import AnthropicBackend
        logger.info("LLM mode: API (Anthropic)")
        return AnthropicBackend()

    if resolved_mode == "local":
        logger.info("LLM mode: local")
        return _create_local_backend(platform_info)

    if resolved_mode in ("hybrid", "auto"):
        local = _create_local_backend(platform_info)
        from kestrel.llm.anthropic_backend import AnthropicBackend
        api = AnthropicBackend()
        from kestrel.llm.hybrid_router import HybridRouter
        logger.info("LLM mode: hybrid (local + API)")
        return HybridRouter(local_backend=local, api_backend=api)

    raise ValueError(
        f"Unknown LLM mode: '{resolved_mode}'. "
        "Valid options: 'api', 'local', 'hybrid', 'auto'"
    )
