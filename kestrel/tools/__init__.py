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
Kestrel Tool Wrappers

Provides structured interfaces to security tools and the central
ToolRegistry for discovering and managing all Kali tools.
"""

from .base import (
    ToolWrapper,
    BaseToolWrapper,
    ToolRequest,
    ToolSchema,
    ToolCategory,
    ValidationResult,
)
from .nmap import NmapWrapper
from .gobuster import GobusterWrapper
from .nikto import NiktoWrapper
from .sqlmap import SqlmapWrapper
from .nuclei import NucleiWrapper
from .subfinder import SubfinderWrapper
from .ffuf import FfufWrapper
from .httpx import HttpxWrapper
from .whatweb import WhatwebWrapper
from .registry import (
    ToolRegistry,
    ToolInfo,
    ToolTier,
    ToolCapability,
    KNOWN_TOOLS,
    get_registry,
    reset_registry,
)


# Legacy tool registry (kept for backward compatibility)
# Prefer using ToolRegistry.get() for new code.
TOOLS: dict[str, type[ToolWrapper]] = {
    "nmap": NmapWrapper,
    "gobuster": GobusterWrapper,
    "nikto": NiktoWrapper,
    "sqlmap": SqlmapWrapper,
}


def get_tool(name: str) -> ToolWrapper:
    """
    Get a tool wrapper instance by name.

    Args:
        name: Tool name (e.g., "nmap")

    Returns:
        ToolWrapper instance

    Raises:
        KeyError: If tool not found
    """
    if name not in TOOLS:
        raise KeyError(f"Unknown tool: {name}. Available: {list(TOOLS.keys())}")
    return TOOLS[name]()


def list_tools() -> list[dict]:
    """
    List all available tools with their schemas.

    Returns:
        List of tool schema dictionaries
    """
    tools = []
    for name, wrapper_class in TOOLS.items():
        wrapper = wrapper_class()
        tools.append({
            "name": name,
            "category": wrapper.category.value,
            "description": wrapper.description,
            "schema": wrapper.get_schema().to_dict(),
        })
    return tools


__all__ = [
    # Base
    "ToolWrapper",
    "BaseToolWrapper",
    "ToolRequest",
    "ToolSchema",
    "ToolCategory",
    "ValidationResult",
    # Wrappers
    "NmapWrapper",
    "GobusterWrapper",
    "NiktoWrapper",
    "SqlmapWrapper",
    "NucleiWrapper",
    "SubfinderWrapper",
    "FfufWrapper",
    "HttpxWrapper",
    "WhatwebWrapper",
    # Registry
    "ToolRegistry",
    "ToolInfo",
    "ToolTier",
    "ToolCapability",
    "KNOWN_TOOLS",
    "get_registry",
    "reset_registry",
    # Legacy
    "TOOLS",
    "get_tool",
    "list_tools",
]
