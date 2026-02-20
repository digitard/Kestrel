"""
Kestrel SQLmap Output Parser

Parses sqlmap output into structured SQL injection data.
"""

import re
from typing import Optional
from .base import (
    OutputParser,
    ParsedResult,
    ParsedVulnerability,
    Severity,
)


class SqlmapParser(OutputParser):
    """
    Parser for sqlmap output.
    
    Extracts SQL injection findings, database info, and enumeration results.
    """
    
    @property
    def tool_name(self) -> str:
        return "sqlmap"
    
    def parse(self, output: str, command: str = "") -> ParsedResult:
        """Parse sqlmap output."""
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
            
            # Check if injectable
            result.injectable = self._check_injectable(output)
            
            # Extract DBMS
            result.dbms = self._extract_dbms(output)
            
            # Extract databases
            result.databases = self._extract_databases(output)
            
            # Extract tables
            result.tables = self._extract_tables(output)
            
            # Create vulnerability entries
            result.vulnerabilities = self._create_vulnerabilities(result)
            
        except Exception as e:
            result.success = False
            result.error_message = f"Parse error: {str(e)}"
        
        return result
    
    def _extract_target(self, output: str, command: str) -> Optional[str]:
        """Extract target URL from output or command."""
        # From output
        match = re.search(r"URL:\s+(\S+)", output)
        if match:
            return match.group(1)
        
        # From command: -u flag
        if command:
            match = re.search(r"-u\s+['\"]?(\S+?)['\"]?(?:\s|$)", command)
            if match:
                return match.group(1)
        
        return None
    
    def _check_injectable(self, output: str) -> bool:
        """Check if sqlmap found injection points."""
        injectable_indicators = [
            "sqlmap identified the following injection point",
            "is vulnerable",
            "Type: ",  # Injection type indicator
            "Parameter:",  # Parameter being tested
        ]
        
        # Must have injection point identified
        if "sqlmap identified the following injection point" in output:
            return True
        
        # Check for specific injection types found
        injection_types = [
            "boolean-based blind",
            "time-based blind",
            "error-based",
            "UNION query",
            "stacked queries",
        ]
        
        for inj_type in injection_types:
            if f"Type: {inj_type}" in output:
                return True
        
        return False
    
    def _extract_dbms(self, output: str) -> Optional[str]:
        """Extract detected DBMS."""
        # "back-end DBMS: MySQL" or "the back-end DBMS is MySQL"
        match = re.search(r"back-end DBMS[:\s]+(?:is\s+)?(\S+)", output, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # "web application technology: PHP, MySQL"
        match = re.search(r"web application technology:.*?(MySQL|PostgreSQL|Microsoft SQL Server|Oracle|SQLite)", output)
        if match:
            return match.group(1)
        
        return None
    
    def _extract_databases(self, output: str) -> list[str]:
        """Extract enumerated databases."""
        databases = []
        
        # Look for database listing section
        # "available databases [5]:"
        # [*] database1
        # [*] database2
        
        in_db_section = False
        for line in output.split("\n"):
            if "available databases" in line.lower():
                in_db_section = True
                continue
            
            if in_db_section:
                # Database line: "[*] dbname"
                match = re.match(r"\[\*\]\s+(\S+)", line.strip())
                if match:
                    databases.append(match.group(1))
                elif line.strip() and not line.startswith("["):
                    # End of section
                    in_db_section = False
        
        return databases
    
    def _extract_tables(self, output: str) -> list[str]:
        """Extract enumerated tables."""
        tables = []
        
        # Look for table listing
        # "Database: dbname"
        # "[5 tables]"
        # +------------+
        # | tablename  |
        # +------------+
        
        in_table_section = False
        for line in output.split("\n"):
            if "tables]" in line.lower() or "Table:" in line:
                in_table_section = True
                continue
            
            if in_table_section:
                # Skip separator lines
                if line.strip().startswith("+"):
                    continue
                
                # Table line: "| tablename |"
                match = re.match(r"\|\s*(\S+)\s*\|", line.strip())
                if match:
                    table_name = match.group(1)
                    if table_name and not table_name.startswith("-"):
                        tables.append(table_name)
                elif line.strip() and not line.startswith("|"):
                    # End of section if we hit non-table content
                    if tables:  # Only end if we found some tables
                        in_table_section = False
        
        return tables
    
    def _create_vulnerabilities(self, result: ParsedResult) -> list[ParsedVulnerability]:
        """Create vulnerability entries from parsed data."""
        vulnerabilities = []
        
        if result.injectable:
            # Main SQL injection finding
            vuln = ParsedVulnerability(
                title="SQL Injection Vulnerability",
                description=f"SQL injection confirmed. DBMS: {result.dbms or 'Unknown'}",
                severity=Severity.CRITICAL,
                uri=result.target,
            )
            vulnerabilities.append(vuln)
            
            # Add injection type details from raw output
            injection_types = self._extract_injection_types(result.raw_output)
            for inj_type in injection_types:
                vuln = ParsedVulnerability(
                    title=f"SQL Injection: {inj_type}",
                    description=f"{inj_type} SQL injection technique successful",
                    severity=Severity.CRITICAL,
                    uri=result.target,
                )
                vulnerabilities.append(vuln)
        
        # Database enumeration results
        if result.databases:
            vuln = ParsedVulnerability(
                title=f"Database Enumeration: {len(result.databases)} databases found",
                description=f"Databases: {', '.join(result.databases[:10])}",
                severity=Severity.HIGH,
                evidence=", ".join(result.databases),
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_injection_types(self, output: str) -> list[str]:
        """Extract the types of SQL injection found."""
        types = []
        
        injection_patterns = [
            r"Type:\s+(boolean-based blind)",
            r"Type:\s+(time-based blind)",
            r"Type:\s+(error-based)",
            r"Type:\s+(UNION query)",
            r"Type:\s+(stacked queries)",
        ]
        
        for pattern in injection_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            types.extend(matches)
        
        return list(set(types))  # Deduplicate
    
    def can_parse(self, output: str) -> bool:
        """Check if output looks like sqlmap output."""
        indicators = [
            "sqlmap",
            "[INFO]",
            "[WARNING]",
            "injection point",
            "back-end DBMS",
        ]
        return any(ind in output for ind in indicators)
