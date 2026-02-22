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
Kestrel Httpx Output Parser

Parses httpx (projectdiscovery) JSON output into structured host/service
findings for the fingerprint pipeline.

httpx -json emits one JSON object per line (JSONL).
"""

import json
from .base import OutputParser, ParsedResult, ParsedHost, ParsedPort


class HttpxParser(OutputParser):
    """
    Parser for httpx JSONL output (httpx -json).

    Each line is a JSON object like:
    {
      "url": "https://example.com",
      "status-code": 200,
      "title": "Example Domain",
      "tech": ["Nginx", "Bootstrap"],
      "host": "93.184.216.34",
      ...
    }
    """

    @property
    def tool_name(self) -> str:
        return "httpx"

    def can_parse(self, output: str) -> bool:
        """Check if output looks like httpx JSONL."""
        for line in output.strip().splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    if "url" in obj and ("status-code" in obj or "status_code" in obj):
                        return True
                except json.JSONDecodeError:
                    continue
        return False

    def parse(self, output: str, command: str = "") -> ParsedResult:
        """Parse httpx JSONL output."""
        result = ParsedResult(
            tool="httpx",
            command=command,
            raw_output=output,
        )

        if not output.strip():
            result.success = True
            return result

        for line in output.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = obj.get("url", "")
            host_ip = obj.get("host", "") or obj.get("ip", "")
            status = obj.get("status-code") or obj.get("status_code", 0)
            title = obj.get("title", "")
            tech = obj.get("tech", []) or obj.get("technologies", [])

            # Determine port from URL or default
            port_num = 80
            scheme = ""
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                scheme = parsed.scheme
                if parsed.port:
                    port_num = parsed.port
                elif scheme == "https":
                    port_num = 443
            except Exception:
                pass

            # Build port info with technology fingerprint in extra_info
            extra = f"title={title}" if title else ""
            if tech:
                tech_str = ",".join(tech) if isinstance(tech, list) else str(tech)
                extra = f"{extra} tech={tech_str}".strip()

            port_info = ParsedPort(
                port=port_num,
                protocol="tcp",
                state="open",
                service=scheme or "http",
                product=title or None,
                extra_info=extra or None,
            )

            host = ParsedHost(
                ip=host_ip or url,
                hostname=host_ip or None,
                state="up",
                ports=[port_info],
            )
            result.hosts.append(host)

        result.success = True
        return result
