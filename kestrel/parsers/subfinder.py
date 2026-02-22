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
Kestrel Subfinder Output Parser

Parses subfinder output (plain-text or JSON) into a list of discovered
subdomains, stored as ParsedHosts for downstream scanning phases.
"""

import json
from .base import OutputParser, ParsedResult, ParsedHost


class SubfinderParser(OutputParser):
    """
    Parser for subfinder output.

    Supports two formats:
      - Plain text (one subdomain per line)
      - JSON (when -oJ flag used): {"host": "sub.example.com", "source": "..."}
    """

    @property
    def tool_name(self) -> str:
        return "subfinder"

    def can_parse(self, output: str) -> bool:
        """Subfinder output is plain subdomains or JSON objects."""
        lines = [l.strip() for l in output.strip().splitlines() if l.strip()]
        if not lines:
            return False
        # Check for JSON objects (subfinder -oJ)
        try:
            obj = json.loads(lines[0])
            return "host" in obj
        except (json.JSONDecodeError, ValueError):
            pass
        # Plain text: looks like domain names
        return "." in lines[0] and " " not in lines[0]

    def parse(self, output: str, command: str = "") -> ParsedResult:
        """Parse subfinder output."""
        result = ParsedResult(
            tool="subfinder",
            command=command,
            raw_output=output,
        )

        if not output.strip():
            result.success = True
            return result

        seen: set[str] = set()

        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            subdomain = None

            # Try JSON format first
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    subdomain = obj.get("host", "").strip()
                except json.JSONDecodeError:
                    pass

            # Fall back to plain-text format
            if not subdomain:
                subdomain = line

            if subdomain and subdomain not in seen:
                seen.add(subdomain)
                result.hosts.append(ParsedHost(ip=subdomain, hostname=subdomain))

        result.success = True
        return result
