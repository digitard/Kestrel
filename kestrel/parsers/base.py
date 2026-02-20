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
Kestrel Output Parsers - Base Classes

Provides the foundation for parsing tool output into structured data.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class Severity(Enum):
    """Severity levels for parsed findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ParsedHost:
    """A discovered host from scanning."""
    ip: str
    hostname: Optional[str] = None
    state: str = "up"
    ports: list["ParsedPort"] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)


@dataclass
class ParsedPort:
    """A discovered port/service."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None


@dataclass
class ParsedPath:
    """A discovered web path."""
    path: str
    status_code: int
    size: Optional[int] = None
    redirect: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class ParsedVulnerability:
    """A discovered vulnerability."""
    title: str
    description: Optional[str] = None
    severity: Severity = Severity.INFO
    uri: Optional[str] = None
    evidence: Optional[str] = None
    cve_id: Optional[str] = None
    osvdb_id: Optional[str] = None
    reference: Optional[str] = None


@dataclass
class ParsedResult:
    """
    Result of parsing tool output.
    
    Contains structured data extracted from raw tool output.
    """
    success: bool = True
    error_message: Optional[str] = None
    
    # Raw data
    raw_output: str = ""
    command: str = ""
    tool: str = ""
    
    # Parsed data (tool-specific fields populated)
    hosts: list[ParsedHost] = field(default_factory=list)
    paths: list[ParsedPath] = field(default_factory=list)
    vulnerabilities: list[ParsedVulnerability] = field(default_factory=list)
    
    # SQL injection specific
    injectable: bool = False
    dbms: Optional[str] = None
    databases: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    
    # Metadata
    target: Optional[str] = None
    scan_time: Optional[float] = None
    
    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return (
            sum(len(h.ports) for h in self.hosts) +
            len(self.paths) +
            len(self.vulnerabilities) +
            (1 if self.injectable else 0)
        )
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "error_message": self.error_message,
            "tool": self.tool,
            "target": self.target,
            "finding_count": self.finding_count,
            "hosts": [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "state": h.state,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "product": p.product,
                            "version": p.version,
                        }
                        for p in h.ports
                    ],
                }
                for h in self.hosts
            ],
            "paths": [
                {
                    "path": p.path,
                    "status_code": p.status_code,
                    "size": p.size,
                }
                for p in self.paths
            ],
            "vulnerabilities": [
                {
                    "title": v.title,
                    "severity": v.severity.value,
                    "uri": v.uri,
                    "cve_id": v.cve_id,
                }
                for v in self.vulnerabilities
            ],
            "injectable": self.injectable,
            "dbms": self.dbms,
        }


class OutputParser(ABC):
    """
    Abstract base class for tool output parsers.
    
    Each parser extracts structured data from tool-specific output.
    """
    
    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of the tool this parser handles."""
        pass
    
    @abstractmethod
    def parse(self, output: str, command: str = "") -> ParsedResult:
        """
        Parse tool output into structured data.
        
        Args:
            output: Raw tool output (stdout)
            command: The command that was executed
            
        Returns:
            ParsedResult with extracted data
        """
        pass
    
    def can_parse(self, output: str) -> bool:
        """
        Check if this parser can handle the given output.
        
        Args:
            output: Raw output to check
            
        Returns:
            True if this parser can handle it
        """
        return True  # Override in subclasses for format detection
