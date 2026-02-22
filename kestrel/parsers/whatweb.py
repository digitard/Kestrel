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
Kestrel WhatWeb Output Parser

Parses whatweb JSON output (--log-json) into structured technology
fingerprint findings for CVE correlation.

whatweb --log-json=- emits one JSON object per target.
"""

import json
from .base import OutputParser, ParsedResult, ParsedHost, ParsedPort


class WhatwebParser(OutputParser):
    """
    Parser for WhatWeb JSON output (whatweb --log-json=-).

    WhatWeb JSON format is an array of target objects:
    [
      {
        "target": "https://example.com",
        "http_status": 200,
        "plugins": {
          "Nginx": {"version": ["1.18.0"]},
          "WordPress": {"version": ["5.8.1"]},
          ...
        }
      }
    ]
    """

    @property
    def tool_name(self) -> str:
        return "whatweb"

    def can_parse(self, output: str) -> bool:
        """Check if output looks like WhatWeb JSON."""
        stripped = output.strip()
        # WhatWeb outputs an array or individual JSON objects
        if stripped.startswith("[") or stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                if isinstance(data, list) and data:
                    return "target" in data[0] and "plugins" in data[0]
                if isinstance(data, dict):
                    return "target" in data and "plugins" in data
            except json.JSONDecodeError:
                pass
        return False

    def parse(self, output: str, command: str = "") -> ParsedResult:
        """Parse WhatWeb JSON output."""
        result = ParsedResult(
            tool="whatweb",
            command=command,
            raw_output=output,
        )

        stripped = output.strip()
        if not stripped:
            result.success = True
            return result

        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            result.success = False
            result.error_message = f"Failed to parse WhatWeb JSON: {exc}"
            return result

        # Normalize to list
        if isinstance(data, dict):
            data = [data]

        for item in data:
            if not isinstance(item, dict):
                continue

            target = item.get("target", "")
            http_status = item.get("http_status", 0)
            plugins = item.get("plugins", {})

            # Collect technology names with versions
            tech_parts = []
            for plugin_name, plugin_data in plugins.items():
                versions = plugin_data.get("version", []) if isinstance(plugin_data, dict) else []
                if versions:
                    tech_parts.append(f"{plugin_name}/{versions[0]}")
                else:
                    tech_parts.append(plugin_name)

            extra_info = " | ".join(tech_parts) if tech_parts else None

            # Determine port from target URL
            port_num = 80
            scheme = "http"
            try:
                from urllib.parse import urlparse
                parsed = urlparse(target)
                scheme = parsed.scheme or "http"
                if parsed.port:
                    port_num = parsed.port
                elif scheme == "https":
                    port_num = 443
            except Exception:
                pass

            port_info = ParsedPort(
                port=port_num,
                protocol="tcp",
                state="open",
                service=scheme,
                extra_info=extra_info,
            )

            host = ParsedHost(
                ip=target,
                hostname=target,
                state="up",
                ports=[port_info],
            )
            result.hosts.append(host)

        result.success = True
        return result
