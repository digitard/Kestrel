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
Kestrel SQLmap Tool Wrapper

Wraps sqlmap for SQL injection detection and exploitation.

NOTE: This tool can be destructive. Always requires authorization.
"""

from typing import Optional
from .base import (
    BaseToolWrapper,
    ToolRequest,
    ToolSchema,
    ToolCategory,
    ValidationResult,
)


class SqlmapWrapper(BaseToolWrapper):
    """
    Wrapper for sqlmap SQL injection tool.
    
    Supports:
    - SQL injection detection
    - Database enumeration
    - Data extraction
    - Various injection techniques
    
    IMPORTANT: This is a potentially destructive tool.
    Always requires explicit authorization before execution.
    """
    
    @property
    def name(self) -> str:
        return "sqlmap"
    
    @property
    def category(self) -> ToolCategory:
        return ToolCategory.EXPLOITATION
    
    @property
    def description(self) -> str:
        return "Automatic SQL injection detection and exploitation tool"
    
    def get_schema(self) -> ToolSchema:
        return ToolSchema(
            name=self.name,
            description=self.description,
            category=self.category,
            requires_target=True,
            target_types=["url"],
            options=[
                {
                    "name": "data",
                    "type": "string",
                    "description": "POST data string",
                    "default": None,
                },
                {
                    "name": "cookie",
                    "type": "string",
                    "description": "HTTP Cookie header value",
                    "default": None,
                },
                {
                    "name": "level",
                    "type": "integer",
                    "description": "Level of tests (1-5, higher = more tests)",
                    "default": 1,
                },
                {
                    "name": "risk",
                    "type": "integer",
                    "description": "Risk of tests (1-3, higher = more risky)",
                    "default": 1,
                },
                {
                    "name": "technique",
                    "type": "string",
                    "description": "SQL injection techniques (BEUSTQ)",
                    "default": None,
                },
                {
                    "name": "dbms",
                    "type": "string",
                    "description": "Target DBMS (mysql, postgresql, mssql, oracle, sqlite)",
                    "default": None,
                },
                {
                    "name": "dbs",
                    "type": "boolean",
                    "description": "Enumerate databases",
                    "default": False,
                },
                {
                    "name": "tables",
                    "type": "boolean",
                    "description": "Enumerate tables",
                    "default": False,
                },
                {
                    "name": "dump",
                    "type": "boolean",
                    "description": "Dump data (REQUIRES EXPLICIT AUTHORIZATION)",
                    "default": False,
                },
                {
                    "name": "batch",
                    "type": "boolean",
                    "description": "Never ask for user input, use defaults",
                    "default": True,
                },
                {
                    "name": "random_agent",
                    "type": "boolean",
                    "description": "Use random User-Agent",
                    "default": True,
                },
            ],
            examples=[
                {
                    "intent": "Test URL parameter for SQL injection",
                    "request": {
                        "tool": "sqlmap",
                        "target": "https://example.com/page?id=1",
                        "options": {"level": 1, "risk": 1},
                    },
                },
                {
                    "intent": "Test POST parameter for SQL injection",
                    "request": {
                        "tool": "sqlmap",
                        "target": "https://example.com/login",
                        "options": {
                            "data": "username=test&password=test",
                            "level": 2,
                        },
                    },
                },
                {
                    "intent": "Enumerate databases after confirming injection",
                    "request": {
                        "tool": "sqlmap",
                        "target": "https://example.com/page?id=1",
                        "options": {"dbs": True},
                    },
                },
            ],
        )
    
    def validate(self, request: ToolRequest) -> ValidationResult:
        """Validate sqlmap request."""
        result = self.validate_target(request.target)
        
        # Target must be a URL
        if not request.target.startswith(("http://", "https://")):
            result.add_error("SQLmap target must be a full URL")
        
        # Validate level
        level = request.options.get("level", 1)
        if not isinstance(level, int) or level < 1 or level > 5:
            result.add_error("Level must be between 1 and 5")
        
        # Validate risk
        risk = request.options.get("risk", 1)
        if not isinstance(risk, int) or risk < 1 or risk > 3:
            result.add_error("Risk must be between 1 and 3")
        
        # Validate technique
        technique = request.options.get("technique")
        if technique:
            valid_techniques = set("BEUSTQ")
            if not all(c.upper() in valid_techniques for c in technique):
                result.add_error(f"Invalid technique: {technique}. Valid: BEUSTQ")
        
        # Validate dbms
        dbms = request.options.get("dbms")
        if dbms:
            valid_dbms = ["mysql", "postgresql", "mssql", "oracle", "sqlite", "access", "firebird", "sybase"]
            if dbms.lower() not in valid_dbms:
                result.add_warning(f"Unknown DBMS: {dbms}")
        
        # Warn about dangerous options
        if request.options.get("dump"):
            result.add_warning("DUMP option requested - requires explicit authorization")
        
        if request.options.get("risk", 1) >= 3:
            result.add_warning("High risk level may cause data modification")
        
        return result
    
    def build_command(self, request: ToolRequest) -> str:
        """Build sqlmap command."""
        args = ["sqlmap"]
        
        # Target URL
        args.extend(["-u", self.escape_arg(request.target)])
        
        # POST data
        data = request.options.get("data")
        if data:
            args.extend(["--data", self.escape_arg(data)])
        
        # Cookie
        cookie = request.options.get("cookie")
        if cookie:
            args.extend(["--cookie", self.escape_arg(cookie)])
        
        # Level and risk
        level = request.options.get("level", 1)
        args.extend(["--level", str(level)])
        
        risk = request.options.get("risk", 1)
        args.extend(["--risk", str(risk)])
        
        # Technique
        technique = request.options.get("technique")
        if technique:
            args.extend(["--technique", technique.upper()])
        
        # DBMS
        dbms = request.options.get("dbms")
        if dbms:
            args.extend(["--dbms", dbms])
        
        # Enumeration options
        if request.options.get("dbs"):
            args.append("--dbs")
        
        if request.options.get("tables"):
            args.append("--tables")
        
        if request.options.get("dump"):
            args.append("--dump")
        
        # Batch mode (no prompts)
        if request.options.get("batch", True):
            args.append("--batch")
        
        # Random agent
        if request.options.get("random_agent", True):
            args.append("--random-agent")
        
        # Output format
        if request.output_format and request.output_file:
            # SQLmap doesn't have direct format control, but we can specify output dir
            args.extend(["--output-dir", request.output_file])
        
        # Threads
        threads = request.options.get("threads", request.threads)
        if threads:
            args.extend(["--threads", str(threads)])
        
        return " ".join(args)
    
    def get_default_timeout(self) -> int:
        """SQLmap can take a very long time."""
        return 900  # 15 minutes
    
    def get_default_options(self) -> dict:
        return {
            "level": 1,
            "risk": 1,
            "batch": True,
            "random_agent": True,
        }
