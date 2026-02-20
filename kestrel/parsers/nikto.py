"""
Kestrel Nikto Output Parser

Parses nikto output into structured vulnerability data.
"""

import re
from typing import Optional
from .base import (
    OutputParser,
    ParsedResult,
    ParsedVulnerability,
    Severity,
)


class NiktoParser(OutputParser):
    """
    Parser for nikto output.
    
    Extracts vulnerabilities and server information.
    """
    
    @property
    def tool_name(self) -> str:
        return "nikto"
    
    def parse(self, output: str, command: str = "") -> ParsedResult:
        """Parse nikto output."""
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
            # Extract target
            result.target = self._extract_target(output, command)
            
            # Parse vulnerabilities
            result.vulnerabilities = self._parse_vulnerabilities(output)
            
            # Extract server info as additional findings
            server_vulns = self._parse_server_info(output)
            result.vulnerabilities.extend(server_vulns)
            
        except Exception as e:
            result.success = False
            result.error_message = f"Parse error: {str(e)}"
        
        return result
    
    def _extract_target(self, output: str, command: str) -> Optional[str]:
        """Extract target from output or command."""
        # From output: "+ Target IP: 192.168.1.1"
        match = re.search(r"\+ Target IP:\s+(\S+)", output)
        if match:
            return match.group(1)
        
        # From output: "+ Target Hostname: example.com"
        match = re.search(r"\+ Target Hostname:\s+(\S+)", output)
        if match:
            return match.group(1)
        
        # From command: -h flag
        if command:
            match = re.search(r"-h\s+(\S+)", command)
            if match:
                return match.group(1)
        
        return None
    
    def _parse_vulnerabilities(self, output: str) -> list[ParsedVulnerability]:
        """Parse vulnerability findings from output."""
        vulnerabilities = []
        
        # Nikto finding format:
        # + OSVDB-12345: /path: Description of vulnerability
        # + /path: Description without OSVDB
        
        # Pattern for OSVDB findings
        osvdb_pattern = re.compile(
            r"\+ (OSVDB-\d+):\s+(/\S*):\s+(.+?)(?:\n|$)",
            re.MULTILINE
        )
        
        for match in osvdb_pattern.finditer(output):
            osvdb_id = match.group(1)
            uri = match.group(2)
            description = match.group(3).strip()
            
            severity = self._assess_severity(description, osvdb_id)
            
            vuln = ParsedVulnerability(
                title=description[:100],  # Truncate for title
                description=description,
                severity=severity,
                uri=uri,
                osvdb_id=osvdb_id,
            )
            vulnerabilities.append(vuln)
        
        # Pattern for general findings (no OSVDB)
        general_pattern = re.compile(
            r"^\+ (/\S+):\s+(.+?)(?:\n|$)",
            re.MULTILINE
        )
        
        found_uris = {v.uri for v in vulnerabilities}
        for match in general_pattern.finditer(output):
            uri = match.group(1)
            description = match.group(2).strip()
            
            # Skip if already captured with OSVDB
            if uri in found_uris:
                continue
            
            # Skip informational lines
            if any(skip in description.lower() for skip in [
                "target ip",
                "target hostname",
                "target port",
                "start time",
                "end time",
                "host(s) tested",
            ]):
                continue
            
            severity = self._assess_severity(description)
            
            vuln = ParsedVulnerability(
                title=description[:100],
                description=description,
                severity=severity,
                uri=uri,
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_server_info(self, output: str) -> list[ParsedVulnerability]:
        """Parse server information as findings."""
        findings = []
        
        # Server header
        match = re.search(r"\+ Server:\s+(.+?)(?:\n|$)", output)
        if match:
            server = match.group(1).strip()
            findings.append(ParsedVulnerability(
                title=f"Server Header Disclosure: {server}",
                description=f"Server banner reveals: {server}",
                severity=Severity.INFO,
            ))
        
        # SSL info
        if "SSL Info:" in output:
            match = re.search(r"\+ SSL Info:\s+(.+?)(?:\n\+|$)", output, re.DOTALL)
            if match:
                ssl_info = match.group(1).strip()
                findings.append(ParsedVulnerability(
                    title="SSL Configuration Information",
                    description=ssl_info,
                    severity=Severity.INFO,
                ))
        
        return findings
    
    def _assess_severity(self, description: str, osvdb_id: str = None) -> Severity:
        """Assess severity based on finding description."""
        description_lower = description.lower()
        
        # Critical indicators
        critical_keywords = [
            "remote code execution",
            "rce",
            "command injection",
            "sql injection",
            "arbitrary file",
            "shell upload",
        ]
        if any(kw in description_lower for kw in critical_keywords):
            return Severity.CRITICAL
        
        # High indicators
        high_keywords = [
            "authentication bypass",
            "directory traversal",
            "path traversal",
            "file inclusion",
            "xxe",
            "ssrf",
            "default password",
            "backdoor",
        ]
        if any(kw in description_lower for kw in high_keywords):
            return Severity.HIGH
        
        # Medium indicators
        medium_keywords = [
            "cross-site scripting",
            "xss",
            "csrf",
            "information disclosure",
            "sensitive",
            "backup file",
            "config file",
            "phpinfo",
            "debug",
        ]
        if any(kw in description_lower for kw in medium_keywords):
            return Severity.MEDIUM
        
        # Low indicators
        low_keywords = [
            "outdated",
            "version",
            "header",
            "cookie",
            "missing",
            "deprecated",
        ]
        if any(kw in description_lower for kw in low_keywords):
            return Severity.LOW
        
        return Severity.INFO
    
    def can_parse(self, output: str) -> bool:
        """Check if output looks like nikto output."""
        indicators = [
            "- Nikto",
            "+ Target IP:",
            "+ Target Hostname:",
            "+ Target Port:",
            "OSVDB-",
        ]
        return any(ind in output for ind in indicators)
