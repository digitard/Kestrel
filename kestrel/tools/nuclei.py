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
Kestrel Nuclei Tool Wrapper

Wraps nuclei for template-based vulnerability scanning.
Nuclei output feeds directly into the vulnerability findings pipeline.
"""

from .base import (
    BaseToolWrapper,
    ToolRequest,
    ToolSchema,
    ToolCategory,
    ValidationResult,
)


class NucleiWrapper(BaseToolWrapper):
    """
    Wrapper for the nuclei vulnerability scanner.

    Supports:
    - Template-based vulnerability scanning
    - Severity filtering
    - Tag-based template selection
    - JSON output for structured parsing
    """

    @property
    def name(self) -> str:
        return "nuclei"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.VULNERABILITY

    @property
    def description(self) -> str:
        return "Fast template-based vulnerability scanner"

    def get_schema(self) -> ToolSchema:
        return ToolSchema(
            name=self.name,
            description=self.description,
            category=self.category,
            requires_target=True,
            target_types=["url", "host", "ip"],
            options=[
                {
                    "name": "templates",
                    "type": "string",
                    "description": "Template path or tag (e.g., 'cves', 'exposures', 'misconfiguration')",
                    "default": None,
                },
                {
                    "name": "severity",
                    "type": "string",
                    "description": "Filter by severity: critical,high,medium,low,info",
                    "default": None,
                },
                {
                    "name": "tags",
                    "type": "string",
                    "description": "Template tags to filter (e.g., 'sqli,xss')",
                    "default": None,
                },
                {
                    "name": "rate_limit",
                    "type": "integer",
                    "description": "Maximum requests per second",
                    "default": 150,
                },
                {
                    "name": "json_output",
                    "type": "boolean",
                    "description": "Output in JSONL format for parsing",
                    "default": True,
                },
            ],
            examples=[
                {
                    "intent": "Scan for CVEs",
                    "request": {
                        "tool": "nuclei",
                        "target": "https://example.com",
                        "options": {"templates": "cves"},
                    },
                },
                {
                    "intent": "High and critical vulnerabilities only",
                    "request": {
                        "tool": "nuclei",
                        "target": "https://example.com",
                        "options": {"severity": "critical,high"},
                    },
                },
                {
                    "intent": "Misconfiguration check",
                    "request": {
                        "tool": "nuclei",
                        "target": "https://example.com",
                        "options": {"templates": "misconfiguration"},
                    },
                },
            ],
        )

    def validate(self, request: ToolRequest) -> ValidationResult:
        """Validate nuclei request."""
        result = self.validate_target(request.target)

        severity = request.options.get("severity")
        if severity:
            valid = {"critical", "high", "medium", "low", "info"}
            parts = {s.strip().lower() for s in severity.split(",")}
            invalid = parts - valid
            if invalid:
                result.add_error(f"Invalid severity values: {invalid}. Must be: {valid}")

        rate_limit = request.options.get("rate_limit", 150)
        if not isinstance(rate_limit, int) or rate_limit < 1:
            result.add_error("rate_limit must be a positive integer")

        return result

    def build_command(self, request: ToolRequest) -> str:
        """Build nuclei command."""
        args = ["nuclei", "-u", self.escape_arg(request.target)]

        # Templates
        templates = request.options.get("templates")
        if templates:
            args.extend(["-t", templates])

        # Severity filter
        severity = request.options.get("severity")
        if severity:
            args.extend(["-severity", severity])

        # Tags
        tags = request.options.get("tags")
        if tags:
            args.extend(["-tags", tags])

        # Rate limiting
        rate_limit = request.options.get("rate_limit", 150)
        args.extend(["-rl", str(rate_limit)])

        # JSON output for structured parsing (default on)
        if request.options.get("json_output", True):
            args.append("-jsonl")

        # Threads
        if request.threads:
            args.extend(["-c", str(request.threads)])

        # Timeout
        if request.timeout:
            args.extend(["-timeout", str(request.timeout // request.threads if request.threads else request.timeout)])

        # Silent mode — suppress banner but keep findings
        args.append("-silent")

        return " ".join(args)

    def get_default_timeout(self) -> int:
        return 600  # 10 minutes
