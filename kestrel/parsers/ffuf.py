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
Kestrel Ffuf Output Parser

Parses ffuf JSON output into structured path discoveries.
ffuf -of json produces a top-level object with a "results" array.
"""

import json
from .base import OutputParser, ParsedResult, ParsedPath


class FfufParser(OutputParser):
    """
    Parser for ffuf JSON output (ffuf -of json).

    The ffuf JSON format is:
    {
      "commandline": "...",
      "results": [
        {
          "input": {"FUZZ": "admin"},
          "position": 1,
          "status": 200,
          "length": 1234,
          "url": "https://example.com/admin",
          ...
        },
        ...
      ]
    }
    """

    @property
    def tool_name(self) -> str:
        return "ffuf"

    def can_parse(self, output: str) -> bool:
        """Check if output looks like ffuf JSON."""
        stripped = output.strip()
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                return "results" in obj and "commandline" in obj
            except json.JSONDecodeError:
                pass
        return False

    def parse(self, output: str, command: str = "") -> ParsedResult:
        """Parse ffuf JSON output."""
        result = ParsedResult(
            tool="ffuf",
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
            result.error_message = f"Failed to parse ffuf JSON: {exc}"
            return result

        for item in data.get("results", []):
            url = item.get("url", "")
            status = item.get("status", 0)
            length = item.get("length", None)
            redirect = item.get("redirectlocation", None)

            # Extract path from URL
            path = url
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                path = parsed.path or url
            except Exception:
                pass

            result.paths.append(
                ParsedPath(
                    path=path,
                    status_code=status,
                    size=length,
                    redirect=redirect or None,
                )
            )

        result.success = True
        return result
