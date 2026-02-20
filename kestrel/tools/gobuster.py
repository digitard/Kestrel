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
Kestrel Gobuster Tool Wrapper

Wraps gobuster for directory and DNS enumeration.
"""

from typing import Optional
from .base import (
    BaseToolWrapper,
    ToolRequest,
    ToolSchema,
    ToolCategory,
    ValidationResult,
)


class GobusterWrapper(BaseToolWrapper):
    """
    Wrapper for gobuster directory/DNS brute-forcer.
    
    Supports:
    - Directory enumeration (dir mode)
    - DNS subdomain enumeration (dns mode)
    - Virtual host enumeration (vhost mode)
    """
    
    # Common wordlists on Kali
    DEFAULT_WORDLISTS = {
        "small": "/usr/share/wordlists/dirb/small.txt",
        "common": "/usr/share/wordlists/dirb/common.txt",
        "big": "/usr/share/wordlists/dirb/big.txt",
        "directory-list-2.3-small": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "directory-list-2.3-medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "dns": "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
    }
    
    @property
    def name(self) -> str:
        return "gobuster"
    
    @property
    def category(self) -> ToolCategory:
        return ToolCategory.ENUMERATION
    
    @property
    def description(self) -> str:
        return "Directory and DNS brute-forcing tool"
    
    def get_schema(self) -> ToolSchema:
        return ToolSchema(
            name=self.name,
            description=self.description,
            category=self.category,
            requires_target=True,
            target_types=["url", "domain"],
            options=[
                {
                    "name": "mode",
                    "type": "string",
                    "description": "Enumeration mode: dir, dns, vhost",
                    "default": "dir",
                },
                {
                    "name": "wordlist",
                    "type": "string",
                    "description": "Wordlist to use (name or path)",
                    "default": "common",
                },
                {
                    "name": "extensions",
                    "type": "string",
                    "description": "File extensions to search (dir mode), e.g., 'php,html,txt'",
                    "default": None,
                },
                {
                    "name": "status_codes",
                    "type": "string",
                    "description": "Status codes to include, e.g., '200,204,301,302'",
                    "default": "200,204,301,302,307,401,403",
                },
                {
                    "name": "threads",
                    "type": "integer",
                    "description": "Number of concurrent threads",
                    "default": 10,
                },
                {
                    "name": "follow_redirects",
                    "type": "boolean",
                    "description": "Follow redirects",
                    "default": False,
                },
                {
                    "name": "no_tls_validation",
                    "type": "boolean",
                    "description": "Skip TLS certificate verification",
                    "default": True,
                },
            ],
            examples=[
                {
                    "intent": "Find directories on a website",
                    "request": {
                        "tool": "gobuster",
                        "target": "https://example.com",
                        "options": {"mode": "dir", "wordlist": "common"},
                    },
                },
                {
                    "intent": "Find PHP files and directories",
                    "request": {
                        "tool": "gobuster",
                        "target": "https://example.com",
                        "options": {
                            "mode": "dir",
                            "extensions": "php,txt,bak",
                            "wordlist": "directory-list-2.3-medium",
                        },
                    },
                },
                {
                    "intent": "Enumerate subdomains",
                    "request": {
                        "tool": "gobuster",
                        "target": "example.com",
                        "options": {"mode": "dns", "wordlist": "dns"},
                    },
                },
            ],
        )
    
    def validate(self, request: ToolRequest) -> ValidationResult:
        """Validate gobuster request."""
        result = self.validate_target(request.target)
        
        # Validate mode
        mode = request.options.get("mode", "dir")
        if mode not in ["dir", "dns", "vhost"]:
            result.add_error(f"Invalid mode: {mode}. Must be: dir, dns, or vhost")
        
        # For dir mode, target should be a URL
        if mode == "dir" and not request.target.startswith(("http://", "https://")):
            result.add_warning("Dir mode target should be a full URL (e.g., https://example.com)")
        
        # For dns mode, target should be a domain
        if mode == "dns" and request.target.startswith(("http://", "https://")):
            result.add_warning("DNS mode target should be a domain (e.g., example.com), not a URL")
        
        # Validate threads
        threads = request.options.get("threads", request.threads)
        if threads and (not isinstance(threads, int) or threads < 1 or threads > 100):
            result.add_error("Threads must be between 1 and 100")
        
        return result
    
    def _resolve_wordlist(self, wordlist: str) -> str:
        """Resolve wordlist name to path."""
        if wordlist in self.DEFAULT_WORDLISTS:
            return self.DEFAULT_WORDLISTS[wordlist]
        # Assume it's a path
        return wordlist
    
    def build_command(self, request: ToolRequest) -> str:
        """Build gobuster command."""
        mode = request.options.get("mode", "dir")
        args = ["gobuster", mode]
        
        # Target
        if mode == "dir":
            args.extend(["-u", self.escape_arg(request.target)])
        elif mode == "dns":
            args.extend(["-d", self.escape_arg(request.target)])
        elif mode == "vhost":
            args.extend(["-u", self.escape_arg(request.target)])
        
        # Wordlist
        wordlist = request.options.get("wordlist", "common")
        wordlist_path = self._resolve_wordlist(wordlist)
        args.extend(["-w", wordlist_path])
        
        # Mode-specific options
        if mode == "dir":
            # Extensions
            extensions = request.options.get("extensions")
            if extensions:
                args.extend(["-x", extensions])
            
            # Status codes
            status_codes = request.options.get("status_codes", "200,204,301,302,307,401,403")
            args.extend(["-s", status_codes])
            
            # Follow redirects
            if request.options.get("follow_redirects", False):
                args.append("-r")
            
            # Skip TLS validation
            if request.options.get("no_tls_validation", True):
                args.append("-k")
        
        # Threads
        threads = request.options.get("threads", request.threads) or 10
        args.extend(["-t", str(threads)])
        
        # Quiet mode (just results)
        args.append("-q")
        
        # No progress (cleaner output)
        args.append("--no-progress")
        
        return " ".join(args)
    
    def get_default_timeout(self) -> int:
        """Gobuster timeout depends on wordlist size."""
        return 300  # 5 minutes
    
    def get_default_options(self) -> dict:
        return {
            "mode": "dir",
            "wordlist": "common",
            "threads": 10,
            "no_tls_validation": True,
        }
