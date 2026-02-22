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
Kestrel Subfinder Tool Wrapper

Wraps subfinder for passive subdomain discovery.
Subdomain output feeds the target queue for subsequent scanning phases.
"""

from .base import (
    BaseToolWrapper,
    ToolRequest,
    ToolSchema,
    ToolCategory,
    ValidationResult,
)


class SubfinderWrapper(BaseToolWrapper):
    """
    Wrapper for subfinder passive subdomain discovery tool.

    Supports:
    - Passive subdomain enumeration via multiple sources
    - Output to stdout (one subdomain per line)
    - JSON output for structured parsing
    """

    @property
    def name(self) -> str:
        return "subfinder"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.RECON

    @property
    def description(self) -> str:
        return "Passive subdomain discovery via OSINT sources"

    def get_schema(self) -> ToolSchema:
        return ToolSchema(
            name=self.name,
            description=self.description,
            category=self.category,
            requires_target=True,
            target_types=["domain"],
            options=[
                {
                    "name": "sources",
                    "type": "string",
                    "description": "Comma-separated sources to use (e.g., 'crtsh,hackertarget')",
                    "default": None,
                },
                {
                    "name": "all_sources",
                    "type": "boolean",
                    "description": "Use all available sources",
                    "default": False,
                },
                {
                    "name": "json_output",
                    "type": "boolean",
                    "description": "Output in JSON format for parsing",
                    "default": True,
                },
                {
                    "name": "recursive",
                    "type": "boolean",
                    "description": "Enable recursive subdomain discovery",
                    "default": False,
                },
            ],
            examples=[
                {
                    "intent": "Find subdomains of a domain",
                    "request": {
                        "tool": "subfinder",
                        "target": "example.com",
                        "options": {},
                    },
                },
                {
                    "intent": "Exhaustive subdomain discovery",
                    "request": {
                        "tool": "subfinder",
                        "target": "example.com",
                        "options": {"all_sources": True, "recursive": True},
                    },
                },
            ],
        )

    def validate(self, request: ToolRequest) -> ValidationResult:
        """Validate subfinder request."""
        result = self.validate_target(request.target)

        # Target should be a bare domain, not a URL
        target = request.target
        if target.startswith(("http://", "https://")):
            result.add_warning("subfinder target should be a domain (e.g., example.com), not a URL")

        return result

    def build_command(self, request: ToolRequest) -> str:
        """Build subfinder command."""
        args = ["subfinder", "-d", self.escape_arg(request.target)]

        # Sources
        sources = request.options.get("sources")
        if sources:
            args.extend(["-sources", sources])

        # All sources
        if request.options.get("all_sources", False):
            args.append("-all")

        # Threads
        if request.threads:
            args.extend(["-t", str(request.threads)])

        # Recursive
        if request.options.get("recursive", False):
            args.append("-recursive")

        # JSON output
        if request.options.get("json_output", True):
            args.append("-oJ")
            args.extend(["-o", "-"])  # stdout

        # Silent — suppress banner
        args.append("-silent")

        return " ".join(args)

    def get_default_timeout(self) -> int:
        return 300  # 5 minutes
