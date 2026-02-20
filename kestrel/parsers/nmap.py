"""
Kestrel Nmap Output Parser

Parses nmap output into structured data.
"""

import re
from typing import Optional
from .base import (
    OutputParser,
    ParsedResult,
    ParsedHost,
    ParsedPort,
    Severity,
)


class NmapParser(OutputParser):
    """
    Parser for nmap output.
    
    Handles standard nmap text output format.
    """
    
    @property
    def tool_name(self) -> str:
        return "nmap"
    
    def parse(self, output: str, command: str = "") -> ParsedResult:
        """Parse nmap output."""
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
            # Extract target from command or output
            result.target = self._extract_target(output, command)
            
            # Parse hosts and ports
            result.hosts = self._parse_hosts(output)
            
            # Extract scan time
            result.scan_time = self._extract_scan_time(output)
            
        except Exception as e:
            result.success = False
            result.error_message = f"Parse error: {str(e)}"
        
        return result
    
    def _extract_target(self, output: str, command: str) -> Optional[str]:
        """Extract target from output or command."""
        # Try to find in output header
        match = re.search(r"Nmap scan report for (\S+)", output)
        if match:
            return match.group(1)
        
        # Try to find in command
        if command:
            # Target is usually the last argument
            parts = command.split()
            if parts:
                return parts[-1]
        
        return None
    
    def _parse_hosts(self, output: str) -> list[ParsedHost]:
        """Parse host information from output."""
        hosts = []
        
        # Split by host reports
        host_sections = re.split(r"Nmap scan report for ", output)
        
        for section in host_sections[1:]:  # Skip first empty section
            host = self._parse_host_section(section)
            if host:
                hosts.append(host)
        
        return hosts
    
    def _parse_host_section(self, section: str) -> Optional[ParsedHost]:
        """Parse a single host section."""
        lines = section.strip().split("\n")
        if not lines:
            return None
        
        # First line has hostname/IP
        first_line = lines[0]
        
        # Extract hostname and IP
        # Format: "hostname (IP)" or just "IP"
        hostname = None
        ip = None
        
        match = re.match(r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)", first_line)
        if match:
            hostname = match.group(1)
            ip = match.group(2)
        else:
            # Just IP
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)", first_line)
            if match:
                ip = match.group(1)
            else:
                # Use whatever is there as hostname
                hostname = first_line.split()[0] if first_line.split() else None
                ip = hostname or "unknown"
        
        host = ParsedHost(
            ip=ip or "unknown",
            hostname=hostname,
        )
        
        # Check host state
        if "Host is up" in section:
            host.state = "up"
        elif "Host seems down" in section:
            host.state = "down"
        
        # Parse ports
        host.ports = self._parse_ports(section)
        
        # Parse OS detection
        host.os_matches = self._parse_os(section)
        
        return host
    
    def _parse_ports(self, section: str) -> list[ParsedPort]:
        """Parse port information from a host section."""
        ports = []
        
        # Port line format: PORT     STATE SERVICE    VERSION
        # Example: 80/tcp   open  http       Apache httpd 2.4.41
        port_pattern = re.compile(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)?\s*(.*)?$",
            re.MULTILINE
        )
        
        for match in port_pattern.finditer(section):
            port_num = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4) or None
            version_info = match.group(5) or ""
            
            # Parse version info
            product = None
            version = None
            
            if version_info:
                # Try to extract product and version
                # Format varies: "Apache httpd 2.4.41" or "OpenSSH 7.6p1"
                parts = version_info.strip().split()
                if parts:
                    product = parts[0]
                    if len(parts) > 1:
                        version = " ".join(parts[1:])
            
            port = ParsedPort(
                port=port_num,
                protocol=protocol,
                state=state,
                service=service,
                product=product,
                version=version,
            )
            ports.append(port)
        
        return ports
    
    def _parse_os(self, section: str) -> list[str]:
        """Parse OS detection results."""
        os_matches = []
        
        # OS detection line format varies
        # "OS: Linux 2.6.X" or "Running: Linux 2.6.X"
        os_patterns = [
            r"OS:\s+(.+?)(?:\n|$)",
            r"Running:\s+(.+?)(?:\n|$)",
            r"OS details:\s+(.+?)(?:\n|$)",
            r"Aggressive OS guesses:\s+(.+?)(?:\n|$)",
        ]
        
        for pattern in os_patterns:
            matches = re.findall(pattern, section)
            os_matches.extend(matches)
        
        return os_matches
    
    def _extract_scan_time(self, output: str) -> Optional[float]:
        """Extract scan duration from output."""
        # Format: "Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds"
        match = re.search(r"scanned in ([\d.]+) seconds", output)
        if match:
            return float(match.group(1))
        return None
    
    def can_parse(self, output: str) -> bool:
        """Check if output looks like nmap output."""
        indicators = [
            "Nmap scan report",
            "Starting Nmap",
            "PORT     STATE",
            "/tcp",
            "/udp",
        ]
        return any(ind in output for ind in indicators)
