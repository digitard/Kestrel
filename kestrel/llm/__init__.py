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
