"""
Kestrel Output Parsers

Provides parsers for extracting structured data from tool output.
"""

from .base import (
    OutputParser,
    ParsedResult,
    ParsedHost,
    ParsedPort,
    ParsedPath,
    ParsedVulnerability,
    Severity,
)
from .nmap import NmapParser
from .gobuster import GobusterParser
from .nikto import NiktoParser
from .sqlmap import SqlmapParser


# Parser registry
PARSERS: dict[str, type[OutputParser]] = {
    "nmap": NmapParser,
    "gobuster": GobusterParser,
    "nikto": NiktoParser,
    "sqlmap": SqlmapParser,
}


def get_parser(tool: str) -> OutputParser:
    """
    Get a parser instance for a tool.
    
    Args:
        tool: Tool name
        
    Returns:
        OutputParser instance
        
    Raises:
        KeyError: If no parser exists for the tool
    """
    if tool not in PARSERS:
        raise KeyError(f"No parser for tool: {tool}. Available: {list(PARSERS.keys())}")
    return PARSERS[tool]()


def auto_detect_parser(output: str) -> OutputParser | None:
    """
    Auto-detect the appropriate parser for output.
    
    Args:
        output: Raw tool output
        
    Returns:
        Matching parser or None
    """
    for parser_class in PARSERS.values():
        parser = parser_class()
        if parser.can_parse(output):
            return parser
    return None


__all__ = [
    "OutputParser",
    "ParsedResult",
    "ParsedHost",
    "ParsedPort",
    "ParsedPath",
    "ParsedVulnerability",
    "Severity",
    "NmapParser",
    "GobusterParser",
    "NiktoParser",
    "SqlmapParser",
    "PARSERS",
    "get_parser",
    "auto_detect_parser",
]
