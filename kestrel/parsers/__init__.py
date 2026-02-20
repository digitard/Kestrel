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
