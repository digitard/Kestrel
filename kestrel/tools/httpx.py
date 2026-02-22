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
Kestrel Httpx Tool Wrapper

Wraps httpx (projectdiscovery) for fast HTTP service probing and technology
fingerprinting. httpx output feeds the fingerprint/service-detect pipeline.

Note: this wraps 'httpx' from projectdiscovery, not the Python httpx library.
"""

from .base import (
    BaseToolWrapper,
    ToolRequest,
    ToolSchema,
    ToolCategory,
    ValidationResult,
)


class HttpxWrapper(BaseToolWrapper):
    """
    Wrapper for httpx HTTP probing tool (projectdiscovery).

    Supports:
    - HTTP status code probing
    - Title extraction
    - Technology detection
    - TLS info
    - JSON output for structured parsing
    """

    @property
    def name(self) -> str:
        return "httpx"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.FINGERPRINT

    @property
    def description(self) -> str:
        return "Fast HTTP service prober and technology fingerprinter"

    def get_schema(self) -> ToolSchema:
        return ToolSchema(
            name=self.name,
            description=self.description,
            category=self.category,
            requires_target=True,
            target_types=["url", "host", "domain"],
            options=[
                {
                    "name": "status_code",
                    "type": "boolean",
                    "description": "Show HTTP status codes",
                    "default": True,
                },
                {
                    "name": "title",
                    "type": "boolean",
                    "description": "Extract page titles",
                    "default": True,
                },
                {
                    "name": "tech_detect",
                    "type": "boolean",
                    "description": "Detect web technologies (Wappalyzer-based)",
                    "default": True,
                },
                {
                    "name": "tls_info",
                    "type": "boolean",
                    "description": "Extract TLS certificate information",
                    "default": False,
                },
                {
                    "name": "follow_redirects",
                    "type": "boolean",
                    "description": "Follow HTTP redirects",
                    "default": True,
                },
                {
                    "name": "json_output",
                    "type": "boolean",
                    "description": "Output in JSON format for parsing",
                    "default": True,
                },
            ],
            examples=[
                {
                    "intent": "Probe HTTP services on a list of subdomains",
                    "request": {
                        "tool": "httpx",
                        "target": "example.com",
                        "options": {"status_code": True, "title": True, "tech_detect": True},
                    },
                },
                {
                    "intent": "Technology fingerprint a target",
                    "request": {
                        "tool": "httpx",
                        "target": "https://example.com",
                        "options": {"tech_detect": True, "tls_info": True},
                    },
                },
            ],
        )

    def validate(self, request: ToolRequest) -> ValidationResult:
        """Validate httpx request."""
        result = self.validate_target(request.target)
        return result

    def build_command(self, request: ToolRequest) -> str:
        """Build httpx command."""
        args = ["httpx"]

        # Target
        target = request.target
        if target.startswith(("http://", "https://")):
            args.extend(["-u", self.escape_arg(target)])
        else:
            # Bare domain — pipe mode or -u
            args.extend(["-u", self.escape_arg(target)])

        # Probing options
        if request.options.get("status_code", True):
            args.append("-status-code")

        if request.options.get("title", True):
            args.append("-title")

        if request.options.get("tech_detect", True):
            args.append("-tech-detect")

        if request.options.get("tls_info", False):
            args.append("-tls-grab")

        if request.options.get("follow_redirects", True):
            args.append("-follow-redirects")

        # Threads
        if request.threads:
            args.extend(["-threads", str(request.threads)])

        # Timeout
        if request.timeout:
            args.extend(["-timeout", str(request.timeout)])

        # JSON output
        if request.options.get("json_output", True):
            args.append("-json")

        # Suppress banner
        args.append("-silent")

        return " ".join(args)

    def get_default_timeout(self) -> int:
        return 120  # 2 minutes
