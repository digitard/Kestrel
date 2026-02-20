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

"""
Kestrel LLM Integration

Phase 2 — LLM Abstraction Layer.

New (Phase 2):
  backend.py          — LLMBackend Protocol, Message, LLMResponse dataclasses
  backend_factory.py  — Platform-aware factory (MLX / Ollama / Anthropic)
  hybrid_router.py    — Complexity-based routing (simple→local, complex→API)
  mlx_backend.py      — Apple Silicon local inference
  ollama_backend.py   — All other platforms (CUDA / Vulkan / CPU)
  anthropic_backend.py — Cloud API backend for complex tasks
  context_trimmer.py  — Token budget management for long sessions
  prompts.py          — BUG_BOUNTY_SYSTEM_PROMPT + builder functions

Legacy (Phase 1, kept for test compatibility):
  anthropic.py        — AnthropicClient (thin wrapper, replaced by anthropic_backend.py)
"""

# Phase 2 — new abstractions
from .backend import LLMBackend, Message, LLMResponse
from .backend_factory import create_backend
from .hybrid_router import HybridRouter
from .context_trimmer import trim_context, estimate_messages_tokens
from .prompts import BUG_BOUNTY_SYSTEM_PROMPT

# Legacy — Phase 1 compatibility (anthropic.py / prompts.py old functions)
from .anthropic import (
    AnthropicClient,
    LLMResponse as _LegacyLLMResponse,  # kept for old test imports
    get_llm_client,
    reset_llm_client,
)
from .prompts import (
    build_translation_prompt,
    build_analysis_prompt,
    build_exploit_planning_prompt,
    build_report_prompt,
    build_cve_correlation_prompt,
)


__all__ = [
    # Phase 2
    "LLMBackend",
    "Message",
    "LLMResponse",
    "create_backend",
    "HybridRouter",
    "trim_context",
    "estimate_messages_tokens",
    "BUG_BOUNTY_SYSTEM_PROMPT",
    # Legacy
    "AnthropicClient",
    "get_llm_client",
    "reset_llm_client",
    "build_translation_prompt",
    "build_analysis_prompt",
    "build_exploit_planning_prompt",
    "build_report_prompt",
    "build_cve_correlation_prompt",
]
