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
Kestrel Gobuster Output Parser

Parses gobuster output into structured data.
"""

import re
from typing import Optional
from .base import (
    OutputParser,
    ParsedResult,
    ParsedPath,
    Severity,
)


class GobusterParser(OutputParser):
    """
    Parser for gobuster output.
    
    Handles dir, dns, and vhost mode output.
    """
    
    @property
    def tool_name(self) -> str:
        return "gobuster"
    
    def parse(self, output: str, command: str = "") -> ParsedResult:
        """Parse gobuster output."""
        result = ParsedResult(
            tool=self.tool_name,
            command=command,
            raw_output=output,
        )
        
        if not output or not output.strip():
            result.success = False
            result.error_message = "Empty output"
            return result
        
        try:
            # Detect mode from command
            mode = self._detect_mode(command)
            
            # Extract target
            result.target = self._extract_target(command)
            
            # Parse based on mode
            if mode == "dir":
                result.paths = self._parse_dir_output(output)
            elif mode == "dns":
                result.hosts = self._parse_dns_output(output)
            elif mode == "vhost":
                result.paths = self._parse_vhost_output(output)
            else:
                # Default to dir mode parsing
                result.paths = self._parse_dir_output(output)
            
        except Exception as e:
            result.success = False
            result.error_message = f"Parse error: {str(e)}"
        
        return result
    
    def _detect_mode(self, command: str) -> str:
        """Detect gobuster mode from command."""
        if " dir " in command or command.startswith("gobuster dir"):
            return "dir"
        elif " dns " in command or command.startswith("gobuster dns"):
            return "dns"
        elif " vhost " in command or command.startswith("gobuster vhost"):
            return "vhost"
        return "dir"  # Default
    
    def _extract_target(self, command: str) -> Optional[str]:
        """Extract target from command."""
        # -u flag for URL
        match = re.search(r"-u\s+(\S+)", command)
        if match:
            return match.group(1)
        
        # -d flag for domain (dns mode)
        match = re.search(r"-d\s+(\S+)", command)
        if match:
            return match.group(1)
        
        return None
    
    def _parse_dir_output(self, output: str) -> list[ParsedPath]:
        """Parse directory enumeration output."""
        paths = []
        
        # Gobuster dir output formats:
        # /path                 (Status: 200) [Size: 1234]
        # /path                 (Status: 301) [Size: 0] [--> /path/]
        
        # Pattern for standard output
        pattern = re.compile(
            r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[--> (\S+)\])?",
            re.MULTILINE
        )
        
        for match in pattern.finditer(output):
            path = ParsedPath(
                path=match.group(1),
                status_code=int(match.group(2)),
                size=int(match.group(3)) if match.group(3) else None,
                redirect=match.group(4),
            )
            paths.append(path)
        
        # Also try simpler format (older gobuster or quiet mode)
        # /path (Status: 200)
        simple_pattern = re.compile(
            r"^(/\S+)\s+\(Status:\s*(\d+)\)",
            re.MULTILINE
        )
        
        found_paths = {p.path for p in paths}
        for match in simple_pattern.finditer(output):
            path_str = match.group(1)
            if path_str not in found_paths:
                path = ParsedPath(
                    path=path_str,
                    status_code=int(match.group(2)),
                )
                paths.append(path)
        
        return paths
    
    def _parse_dns_output(self, output: str) -> list:
        """Parse DNS enumeration output."""
        from .base import ParsedHost
        
        hosts = []
        
        # DNS output format:
        # Found: subdomain.example.com
        
        pattern = re.compile(r"Found:\s+(\S+)", re.MULTILINE)
        
        for match in pattern.finditer(output):
            hostname = match.group(1)
            host = ParsedHost(
                ip="",  # DNS mode doesn't resolve IP by default
                hostname=hostname,
                state="found",
            )
            hosts.append(host)
        
        return hosts
    
    def _parse_vhost_output(self, output: str) -> list[ParsedPath]:
        """Parse virtual host enumeration output."""
        paths = []
        
        # VHost output format:
        # Found: vhost.example.com (Status: 200) [Size: 1234]
        
        pattern = re.compile(
            r"Found:\s+(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?",
            re.MULTILINE
        )
        
        for match in pattern.finditer(output):
            path = ParsedPath(
                path=match.group(1),  # Using path field for vhost
                status_code=int(match.group(2)),
                size=int(match.group(3)) if match.group(3) else None,
            )
            paths.append(path)
        
        return paths
    
    def can_parse(self, output: str) -> bool:
        """Check if output looks like gobuster output."""
        indicators = [
            "Gobuster",
            "(Status:",
            "Found:",
            "===============",
        ]
        return any(ind in output for ind in indicators)
