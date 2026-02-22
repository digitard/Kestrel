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
Kestrel WhatWeb Tool Wrapper

Wraps whatweb for web technology fingerprinting.
WhatWeb JSON output feeds the fingerprint pipeline for CVE correlation.
"""

from .base import (
    BaseToolWrapper,
    ToolRequest,
    ToolSchema,
    ToolCategory,
    ValidationResult,
)


class WhatwebWrapper(BaseToolWrapper):
    """
    Wrapper for WhatWeb technology fingerprinter.

    Supports:
    - Web technology identification (CMS, frameworks, libraries)
    - Aggression level control
    - JSON output for structured parsing
    """

    @property
    def name(self) -> str:
        return "whatweb"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.FINGERPRINT

    @property
    def description(self) -> str:
        return "Web technology fingerprinter identifying CMS, frameworks, and libraries"

    def get_schema(self) -> ToolSchema:
        return ToolSchema(
            name=self.name,
            description=self.description,
            category=self.category,
            requires_target=True,
            target_types=["url", "host"],
            options=[
                {
                    "name": "aggression",
                    "type": "integer",
                    "description": "Aggression level 1-4 (1=stealthy, 3=aggressive, 4=heavy)",
                    "default": 1,
                },
                {
                    "name": "json_output",
                    "type": "boolean",
                    "description": "Output in JSON format for parsing",
                    "default": True,
                },
                {
                    "name": "follow_redirects",
                    "type": "boolean",
                    "description": "Follow HTTP redirects",
                    "default": True,
                },
            ],
            examples=[
                {
                    "intent": "Identify web technologies",
                    "request": {
                        "tool": "whatweb",
                        "target": "https://example.com",
                        "options": {},
                    },
                },
                {
                    "intent": "Aggressive fingerprinting",
                    "request": {
                        "tool": "whatweb",
                        "target": "https://example.com",
                        "options": {"aggression": 3},
                    },
                },
            ],
        )

    def validate(self, request: ToolRequest) -> ValidationResult:
        """Validate whatweb request."""
        result = self.validate_target(request.target)

        aggression = request.options.get("aggression", 1)
        if not isinstance(aggression, int) or aggression < 1 or aggression > 4:
            result.add_error("Aggression level must be between 1 and 4")

        return result

    def build_command(self, request: ToolRequest) -> str:
        """Build whatweb command."""
        args = ["whatweb"]

        # Aggression
        aggression = request.options.get("aggression", 1)
        args.extend(["-a", str(aggression)])

        # JSON output
        if request.options.get("json_output", True):
            args.extend(["--log-json=-"])

        # Follow redirects
        if not request.options.get("follow_redirects", True):
            args.append("--no-follow")

        # Threads
        if request.threads:
            args.extend(["--max-threads", str(request.threads)])

        # Quiet — suppress progress
        args.append("--quiet")

        # Target (last)
        args.append(self.escape_arg(request.target))

        return " ".join(args)

    def get_default_timeout(self) -> int:
        return 120  # 2 minutes
