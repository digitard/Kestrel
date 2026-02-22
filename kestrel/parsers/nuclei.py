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
Kestrel Nuclei Output Parser

Parses nuclei JSONL output into structured vulnerability findings.
Each line is a JSON object representing one template match.
"""

import json
from .base import OutputParser, ParsedResult, ParsedVulnerability, Severity


_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiParser(OutputParser):
    """
    Parser for nuclei JSONL output (nuclei -jsonl).

    Each line of output is a JSON object like:
    {
      "template-id": "cve-2021-41773",
      "info": {"name": "...", "severity": "critical", "description": "..."},
      "matched-at": "https://example.com/cgi-bin/.%2e/.%2e/etc/passwd",
      "extracted-results": [...]
    }
    """

    @property
    def tool_name(self) -> str:
        return "nuclei"

    def can_parse(self, output: str) -> bool:
        """Check if output looks like nuclei JSONL."""
        for line in output.strip().splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    if "template-id" in obj or "templateID" in obj:
                        return True
                except json.JSONDecodeError:
                    continue
        return False

    def parse(self, output: str, command: str = "") -> ParsedResult:
        """Parse nuclei JSONL output."""
        result = ParsedResult(
            tool="nuclei",
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

            info = obj.get("info", {})
            template_id = obj.get("template-id") or obj.get("templateID", "")
            severity_str = info.get("severity", "info").lower()
            severity = _SEVERITY_MAP.get(severity_str, Severity.INFO)

            vuln = ParsedVulnerability(
                title=info.get("name", template_id),
                description=info.get("description", ""),
                severity=severity,
                uri=obj.get("matched-at", ""),
                evidence=str(obj.get("extracted-results", "")),
                reference=template_id,
            )

            # CVE extraction from template ID
            tid_lower = template_id.lower()
            if tid_lower.startswith("cve-"):
                vuln.cve_id = template_id.upper()

            result.vulnerabilities.append(vuln)

        result.success = True
        return result
