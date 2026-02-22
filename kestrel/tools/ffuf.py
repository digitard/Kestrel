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
Kestrel Ffuf Tool Wrapper

Wraps ffuf for fast web fuzzing (directory brute-force, parameter fuzzing,
vhost fuzzing). ffuf JSON output feeds the discovered-paths pipeline.
"""

from .base import (
    BaseToolWrapper,
    ToolRequest,
    ToolSchema,
    ToolCategory,
    ValidationResult,
)


class FfufWrapper(BaseToolWrapper):
    """
    Wrapper for ffuf fast web fuzzer.

    Supports:
    - Directory/file brute-forcing
    - Virtual host fuzzing
    - GET/POST parameter fuzzing
    - JSON output for structured parsing
    """

    # Common wordlists on Kali
    DEFAULT_WORDLISTS = {
        "common": "/usr/share/wordlists/dirb/common.txt",
        "big": "/usr/share/wordlists/dirb/big.txt",
        "directory-list-2.3-small": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "directory-list-2.3-medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "raft-small": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "raft-medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    }

    @property
    def name(self) -> str:
        return "ffuf"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.ENUMERATION

    @property
    def description(self) -> str:
        return "Fast web fuzzer for directory, parameter, and vhost discovery"

    def get_schema(self) -> ToolSchema:
        return ToolSchema(
            name=self.name,
            description=self.description,
            category=self.category,
            requires_target=True,
            target_types=["url"],
            options=[
                {
                    "name": "wordlist",
                    "type": "string",
                    "description": "Wordlist name or path",
                    "default": "common",
                },
                {
                    "name": "extensions",
                    "type": "string",
                    "description": "File extensions to fuzz (e.g., 'php,html,txt')",
                    "default": None,
                },
                {
                    "name": "filter_codes",
                    "type": "string",
                    "description": "HTTP status codes to filter OUT (e.g., '404,400')",
                    "default": "404",
                },
                {
                    "name": "match_codes",
                    "type": "string",
                    "description": "HTTP status codes to match (e.g., '200,301,302')",
                    "default": None,
                },
                {
                    "name": "threads",
                    "type": "integer",
                    "description": "Number of concurrent threads",
                    "default": 40,
                },
                {
                    "name": "follow_redirects",
                    "type": "boolean",
                    "description": "Follow HTTP redirects",
                    "default": False,
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
                    "intent": "Directory brute-force",
                    "request": {
                        "tool": "ffuf",
                        "target": "https://example.com/FUZZ",
                        "options": {"wordlist": "common"},
                    },
                },
                {
                    "intent": "PHP file discovery",
                    "request": {
                        "tool": "ffuf",
                        "target": "https://example.com/FUZZ",
                        "options": {"wordlist": "big", "extensions": "php,bak,old"},
                    },
                },
            ],
        )

    def validate(self, request: ToolRequest) -> ValidationResult:
        """Validate ffuf request."""
        result = self.validate_target(request.target)

        # FUZZ keyword should be present in the URL
        if "FUZZ" not in request.target:
            result.add_warning(
                "ffuf target URL should contain 'FUZZ' keyword (e.g., https://example.com/FUZZ)"
            )

        threads = request.options.get("threads", request.threads or 40)
        if not isinstance(threads, int) or threads < 1 or threads > 500:
            result.add_error("Threads must be between 1 and 500")

        return result

    def _resolve_wordlist(self, wordlist: str) -> str:
        """Resolve wordlist name to path."""
        return self.DEFAULT_WORDLISTS.get(wordlist, wordlist)

    def build_command(self, request: ToolRequest) -> str:
        """Build ffuf command."""
        args = ["ffuf", "-u", self.escape_arg(request.target)]

        # Wordlist
        wordlist = request.options.get("wordlist", "common")
        args.extend(["-w", self._resolve_wordlist(wordlist)])

        # Extensions
        extensions = request.options.get("extensions")
        if extensions:
            args.extend(["-e", extensions])

        # Filter codes
        filter_codes = request.options.get("filter_codes", "404")
        if filter_codes:
            args.extend(["-fc", filter_codes])

        # Match codes
        match_codes = request.options.get("match_codes")
        if match_codes:
            args.extend(["-mc", match_codes])

        # Threads
        threads = request.options.get("threads", request.threads or 40)
        args.extend(["-t", str(threads)])

        # Follow redirects
        if request.options.get("follow_redirects", False):
            args.append("-r")

        # JSON output
        if request.options.get("json_output", True):
            args.extend(["-of", "json", "-o", "-"])

        # Suppress progress / color for clean output
        args.extend(["-s", "-noninteractive"])

        return " ".join(args)

    def get_default_timeout(self) -> int:
        return 300  # 5 minutes
