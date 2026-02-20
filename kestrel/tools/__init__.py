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
