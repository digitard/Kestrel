"""
Kestrel LLM Integration

Provides LLM-assisted capabilities for hunting.
"""

from .anthropic import (
    AnthropicClient,
    LLMResponse,
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
    "AnthropicClient",
    "LLMResponse",
    "get_llm_client",
    "reset_llm_client",
    "build_translation_prompt",
    "build_analysis_prompt",
    "build_exploit_planning_prompt",
    "build_report_prompt",
    "build_cve_correlation_prompt",
]
