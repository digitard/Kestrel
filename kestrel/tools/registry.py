"""
Kestrel Tool Registry

Central registry for all security tools available on the system.
Provides two tiers of tool access:

  Tier 1 - Wrapped Tools:  Have dedicated wrappers with validation,
           structured schemas, and output parsers (nmap, gobuster, etc.)

  Tier 2 - Discovered Tools: Auto-discovered Kali tools with basic
           metadata from --help output. Available for direct execution
           through the NativeExecutor with LLM-generated commands.

This enables the LLM to:
  - Know everything installed on the system
  - Use rich schemas for recon tools (Tier 1)
  - Generate arbitrary commands for exploit tools (Tier 2)
  - Filter tools by category/capability for task planning
"""

import shutil
import subprocess
import re
import json
import time
from dataclasses import dataclass, field
from typing import Optional, Any
from pathlib import Path
from enum import Enum

from .base import ToolWrapper, ToolSchema, ToolCategory


class ToolTier(Enum):
    """Tool integration depth."""
    WRAPPED = "wrapped"        # Full wrapper + parser + validation
    DISCOVERED = "discovered"  # Auto-discovered, basic metadata only


class ToolCapability(Enum):
    """What a tool can do - used for LLM task planning."""
    PORT_SCAN = "port_scan"
    SERVICE_DETECT = "service_detect"
    WEB_ENUM = "web_enum"
    DIR_BRUTE = "dir_brute"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    SQL_INJECT = "sql_inject"
    SUBDOMAIN_ENUM = "subdomain_enum"
    FINGERPRINT = "fingerprint"
    FUZZING = "fuzzing"
    PASSWORD_ATTACK = "password_attack"
    PROXY = "proxy"
    NETWORK_SNIFF = "network_sniff"
    WIRELESS = "wireless"
    CRYPTO = "crypto"
    FORENSIC = "forensic"
    OSINT = "osint"
    REPORTING = "reporting"
    UTILITY = "utility"


@dataclass
class ToolInfo:
    """
    Complete information about a tool in the registry.

    This is the unified view that the LLM sees - whether the tool
    has a full wrapper or was auto-discovered.
    """
    name: str
    tier: ToolTier
    available: bool = False
    path: Optional[str] = None
    version: Optional[str] = None

    # Metadata
    description: str = ""
    category: ToolCategory = ToolCategory.UTILITY
    capabilities: list[ToolCapability] = field(default_factory=list)

    # Help text (truncated for LLM context)
    help_text: str = ""
    usage_hint: str = ""

    # For Tier 1 (wrapped) tools
    wrapper_class: Optional[type] = field(default=None, repr=False)
    has_parser: bool = False

    # Common flags discovered from --help
    common_flags: list[dict] = field(default_factory=list)

    # Safety classification
    requires_authorization: bool = False  # True for exploit-class tools
    can_modify_target: bool = False       # True if tool can write/change things
    is_passive: bool = True               # True if tool only reads/observes

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization and LLM context."""
        return {
            "name": self.name,
            "tier": self.tier.value,
            "available": self.available,
            "path": self.path,
            "version": self.version,
            "description": self.description,
            "category": self.category.value,
            "capabilities": [c.value for c in self.capabilities],
            "usage_hint": self.usage_hint,
            "common_flags": self.common_flags,
            "has_wrapper": self.tier == ToolTier.WRAPPED,
            "has_parser": self.has_parser,
            "requires_authorization": self.requires_authorization,
            "can_modify_target": self.can_modify_target,
            "is_passive": self.is_passive,
        }

    def to_llm_context(self, include_help: bool = False) -> str:
        """
        Generate a concise context string for LLM prompts.

        Args:
            include_help: Include truncated help text

        Returns:
            Formatted string for LLM consumption
        """
        lines = [
            f"Tool: {self.name}",
            f"  Type: {self.tier.value} | Category: {self.category.value}",
            f"  Description: {self.description}",
        ]

        if self.capabilities:
            caps = ", ".join(c.value for c in self.capabilities)
            lines.append(f"  Capabilities: {caps}")

        if self.usage_hint:
            lines.append(f"  Usage: {self.usage_hint}")

        if self.common_flags:
            flags = ", ".join(
                f"{f['flag']} ({f.get('description', '?')})"
                for f in self.common_flags[:8]
            )
            lines.append(f"  Key flags: {flags}")

        safety = []
        if self.requires_authorization:
            safety.append("REQUIRES_AUTH")
        if self.can_modify_target:
            safety.append("MODIFIES_TARGET")
        if not self.is_passive:
            safety.append("ACTIVE")
        if safety:
            lines.append(f"  Safety: {', '.join(safety)}")

        if include_help and self.help_text:
            lines.append(f"  Help excerpt:\n    {self.help_text[:500]}")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────
#  Known Kali Tool Definitions
#
#  Pre-defined metadata for common Kali tools. The registry uses these
#  when a tool is discovered on the system. Tools NOT in this list
#  still get registered via auto-discovery with basic metadata.
# ─────────────────────────────────────────────────────────────────────

KNOWN_TOOLS: dict[str, dict] = {
    # === RECONNAISSANCE ===
    "nmap": {
        "description": "Network port scanner and service detector",
        "category": ToolCategory.RECON,
        "capabilities": [ToolCapability.PORT_SCAN, ToolCapability.SERVICE_DETECT, ToolCapability.VULN_SCAN],
        "usage_hint": "nmap [scan_type] [options] <target>",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "masscan": {
        "description": "Fast TCP port scanner, can scan entire internet in minutes",
        "category": ToolCategory.RECON,
        "capabilities": [ToolCapability.PORT_SCAN],
        "usage_hint": "masscan <target> -p <ports> --rate <pps>",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "subfinder": {
        "description": "Passive subdomain discovery tool",
        "category": ToolCategory.RECON,
        "capabilities": [ToolCapability.SUBDOMAIN_ENUM, ToolCapability.OSINT],
        "usage_hint": "subfinder -d <domain> -o <output>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "amass": {
        "description": "In-depth attack surface mapping and asset discovery",
        "category": ToolCategory.RECON,
        "capabilities": [ToolCapability.SUBDOMAIN_ENUM, ToolCapability.OSINT],
        "usage_hint": "amass enum -d <domain>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "dnsx": {
        "description": "Fast DNS toolkit for running multiple probes",
        "category": ToolCategory.RECON,
        "capabilities": [ToolCapability.SUBDOMAIN_ENUM],
        "usage_hint": "echo <domain> | dnsx -resp",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "httpx": {
        "description": "Fast HTTP toolkit for probing web services",
        "category": ToolCategory.RECON,
        "capabilities": [ToolCapability.FINGERPRINT, ToolCapability.SERVICE_DETECT],
        "usage_hint": "echo <url> | httpx -status-code -title -tech-detect",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },

    # === WEB ENUMERATION ===
    "gobuster": {
        "description": "Directory/file brute-forcer and DNS subdomain enumerator",
        "category": ToolCategory.ENUMERATION,
        "capabilities": [ToolCapability.DIR_BRUTE, ToolCapability.WEB_ENUM, ToolCapability.SUBDOMAIN_ENUM],
        "usage_hint": "gobuster dir -u <url> -w <wordlist>",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "feroxbuster": {
        "description": "Fast, recursive content discovery tool written in Rust",
        "category": ToolCategory.ENUMERATION,
        "capabilities": [ToolCapability.DIR_BRUTE, ToolCapability.WEB_ENUM],
        "usage_hint": "feroxbuster -u <url> -w <wordlist>",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "ffuf": {
        "description": "Fast web fuzzer written in Go",
        "category": ToolCategory.ENUMERATION,
        "capabilities": [ToolCapability.DIR_BRUTE, ToolCapability.FUZZING, ToolCapability.WEB_ENUM],
        "usage_hint": "ffuf -u <url>/FUZZ -w <wordlist>",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "dirb": {
        "description": "Web content scanner and directory brute-forcer",
        "category": ToolCategory.ENUMERATION,
        "capabilities": [ToolCapability.DIR_BRUTE, ToolCapability.WEB_ENUM],
        "usage_hint": "dirb <url> <wordlist>",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "wfuzz": {
        "description": "Web application fuzzer for brute forcing parameters",
        "category": ToolCategory.ENUMERATION,
        "capabilities": [ToolCapability.FUZZING, ToolCapability.WEB_ENUM],
        "usage_hint": "wfuzz -z file,<wordlist> --hc 404 <url>/FUZZ",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": False,
    },

    # === VULNERABILITY SCANNING ===
    "nikto": {
        "description": "Web server vulnerability scanner",
        "category": ToolCategory.VULNERABILITY,
        "capabilities": [ToolCapability.VULN_SCAN, ToolCapability.WEB_ENUM, ToolCapability.FINGERPRINT],
        "usage_hint": "nikto -h <target>",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "nuclei": {
        "description": "Fast vulnerability scanner based on templates",
        "category": ToolCategory.VULNERABILITY,
        "capabilities": [ToolCapability.VULN_SCAN, ToolCapability.FINGERPRINT],
        "usage_hint": "nuclei -u <target> -t <templates>",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "searchsploit": {
        "description": "Command line search tool for Exploit-DB",
        "category": ToolCategory.VULNERABILITY,
        "capabilities": [ToolCapability.VULN_SCAN, ToolCapability.OSINT],
        "usage_hint": "searchsploit <product> <version>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },

    # === EXPLOITATION (REQUIRES AUTHORIZATION) ===
    "sqlmap": {
        "description": "Automatic SQL injection detection and exploitation",
        "category": ToolCategory.EXPLOITATION,
        "capabilities": [ToolCapability.SQL_INJECT, ToolCapability.EXPLOIT],
        "usage_hint": "sqlmap -u <url> --batch",
        "is_passive": False,
        "can_modify_target": True,
        "requires_authorization": True,
    },
    "metasploit-framework": {
        "description": "Advanced exploitation framework (msfconsole)",
        "category": ToolCategory.EXPLOITATION,
        "capabilities": [ToolCapability.EXPLOIT],
        "usage_hint": "msfconsole -q -x '<commands>'",
        "is_passive": False,
        "can_modify_target": True,
        "requires_authorization": True,
    },
    "commix": {
        "description": "Automated command injection exploiter",
        "category": ToolCategory.EXPLOITATION,
        "capabilities": [ToolCapability.EXPLOIT],
        "usage_hint": "commix --url=<url> --data=<data>",
        "is_passive": False,
        "can_modify_target": True,
        "requires_authorization": True,
    },
    "xsstrike": {
        "description": "Advanced XSS detection and exploitation",
        "category": ToolCategory.EXPLOITATION,
        "capabilities": [ToolCapability.EXPLOIT, ToolCapability.FUZZING],
        "usage_hint": "xsstrike -u <url>",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": True,
    },

    # === FINGERPRINTING ===
    "whatweb": {
        "description": "Web technology fingerprinter",
        "category": ToolCategory.FINGERPRINT,
        "capabilities": [ToolCapability.FINGERPRINT, ToolCapability.SERVICE_DETECT],
        "usage_hint": "whatweb <url>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "wafw00f": {
        "description": "Web application firewall detection tool",
        "category": ToolCategory.FINGERPRINT,
        "capabilities": [ToolCapability.FINGERPRINT],
        "usage_hint": "wafw00f <url>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "wpscan": {
        "description": "WordPress security scanner",
        "category": ToolCategory.VULNERABILITY,
        "capabilities": [ToolCapability.VULN_SCAN, ToolCapability.FINGERPRINT, ToolCapability.WEB_ENUM],
        "usage_hint": "wpscan --url <url> --enumerate",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": False,
    },

    # === PASSWORD ATTACKS ===
    "hydra": {
        "description": "Fast network logon cracker supporting many protocols",
        "category": ToolCategory.EXPLOITATION,
        "capabilities": [ToolCapability.PASSWORD_ATTACK, ToolCapability.EXPLOIT],
        "usage_hint": "hydra -l <user> -P <wordlist> <target> <service>",
        "is_passive": False,
        "can_modify_target": False,
        "requires_authorization": True,
    },
    "john": {
        "description": "John the Ripper password cracker",
        "category": ToolCategory.EXPLOITATION,
        "capabilities": [ToolCapability.PASSWORD_ATTACK],
        "usage_hint": "john --wordlist=<wordlist> <hashfile>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "hashcat": {
        "description": "Advanced password recovery utility",
        "category": ToolCategory.EXPLOITATION,
        "capabilities": [ToolCapability.PASSWORD_ATTACK],
        "usage_hint": "hashcat -m <mode> <hashfile> <wordlist>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },

    # === UTILITIES ===
    "curl": {
        "description": "Command line URL transfer tool",
        "category": ToolCategory.UTILITY,
        "capabilities": [ToolCapability.UTILITY, ToolCapability.WEB_ENUM],
        "usage_hint": "curl -v <url>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "wget": {
        "description": "Non-interactive network downloader",
        "category": ToolCategory.UTILITY,
        "capabilities": [ToolCapability.UTILITY],
        "usage_hint": "wget <url>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "jq": {
        "description": "Command-line JSON processor",
        "category": ToolCategory.UTILITY,
        "capabilities": [ToolCapability.UTILITY],
        "usage_hint": "jq '<expression>' <file>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "openssl": {
        "description": "TLS/SSL toolkit for certificate and crypto operations",
        "category": ToolCategory.UTILITY,
        "capabilities": [ToolCapability.CRYPTO, ToolCapability.UTILITY],
        "usage_hint": "openssl s_client -connect <host>:<port>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "testssl.sh": {
        "description": "Testing TLS/SSL encryption on servers",
        "category": ToolCategory.VULNERABILITY,
        "capabilities": [ToolCapability.VULN_SCAN, ToolCapability.CRYPTO],
        "usage_hint": "testssl.sh <host>:<port>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
    "sslscan": {
        "description": "Fast SSL/TLS scanner",
        "category": ToolCategory.VULNERABILITY,
        "capabilities": [ToolCapability.VULN_SCAN, ToolCapability.CRYPTO],
        "usage_hint": "sslscan <host>:<port>",
        "is_passive": True,
        "can_modify_target": False,
        "requires_authorization": False,
    },
}


# ─────────────────────────────────────────────────────────────────────
#  Help Text Parser
# ─────────────────────────────────────────────────────────────────────

def _extract_help_text(tool: str, timeout: int = 5) -> Optional[str]:
    """
    Try to get help text from a tool.

    Attempts --help, -h, and help in order.

    Args:
        tool: Tool binary name
        timeout: Timeout in seconds

    Returns:
        Help text or None
    """
    for flag in ["--help", "-h", "help"]:
        try:
            result = subprocess.run(
                [tool, flag],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = result.stdout + result.stderr
            if len(output.strip()) > 20:
                return output.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            continue
    return None


def _extract_version(tool: str, timeout: int = 5) -> Optional[str]:
    """
    Try to get version string from a tool.

    Args:
        tool: Tool binary name
        timeout: Timeout in seconds

    Returns:
        Version string or None
    """
    for flag in ["--version", "-V", "-v", "version"]:
        try:
            result = subprocess.run(
                [tool, flag],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = (result.stdout + result.stderr).strip()
            if output and len(output) < 500:
                # Extract first line as version
                first_line = output.split("\n")[0].strip()
                if first_line:
                    return first_line
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            continue
    return None


def _parse_common_flags(help_text: str, max_flags: int = 15) -> list[dict]:
    """
    Extract common flags/options from help text.

    Args:
        help_text: Raw help output
        max_flags: Maximum flags to extract

    Returns:
        List of flag dicts with 'flag' and 'description'
    """
    flags = []

    # Match patterns like:
    #   -p, --ports    Ports to scan
    #   --rate         Packets per second
    #   -o FILE        Output file
    patterns = [
        # -x, --long-flag ARG   Description  (with optional argument placeholder)
        re.compile(r"^\s+(-\w(?:,\s*--[\w-]+)?(?:\s+[A-Z_]+)?)\s{2,}(.+?)$", re.MULTILINE),
        # --long-flag ARG   Description
        re.compile(r"^\s+(--[\w-]+(?:\s+[A-Za-z_]+)?)\s{2,}(.+?)$", re.MULTILINE),
        # -x ARG   Description
        re.compile(r"^\s+(-\w(?:\s+[A-Za-z_]+)?)\s{2,}(.+?)$", re.MULTILINE),
    ]

    seen = set()
    for pattern in patterns:
        for match in pattern.finditer(help_text):
            flag = match.group(1).strip()
            desc = match.group(2).strip()[:100]

            if flag not in seen and len(flags) < max_flags:
                seen.add(flag)
                flags.append({
                    "flag": flag,
                    "description": desc,
                })

    return flags


def _extract_usage_hint(help_text: str) -> str:
    """
    Extract usage pattern from help text.

    Args:
        help_text: Raw help output

    Returns:
        Usage hint string
    """
    # Look for "Usage: ..." or "usage: ..."
    match = re.search(r"[Uu]sage:\s*(.+?)(?:\n|$)", help_text)
    if match:
        usage = match.group(1).strip()
        if len(usage) < 200:
            return usage
    return ""


# ─────────────────────────────────────────────────────────────────────
#  Tool Registry
# ─────────────────────────────────────────────────────────────────────

class ToolRegistry:
    """
    Central registry for all security tools.

    Two-tier architecture:
      Tier 1 (Wrapped):     Full wrapper + parser + validation
      Tier 2 (Discovered):  Auto-discovered, metadata from --help

    The registry enables the LLM to:
      - Query all available tools by category/capability
      - Get structured schemas for wrapped tools
      - Get basic metadata + help for discovered tools
      - Plan multi-tool attack chains
      - Know which tools need authorization

    Usage:
        registry = ToolRegistry()
        registry.discover()  # Scan system for tools

        # Get all recon tools
        recon = registry.get_by_category(ToolCategory.RECON)

        # Get LLM context for available tools
        context = registry.build_llm_context()

        # Check if tool needs authorization
        info = registry.get("sqlmap")
        if info and info.requires_authorization:
            # Route through authorization gate
            ...
    """

    def __init__(self):
        self._tools: dict[str, ToolInfo] = {}
        self._discovered: bool = False
        self._discovery_time: float = 0.0

    @property
    def discovered(self) -> bool:
        """Whether discovery has been run."""
        return self._discovered

    @property
    def tool_count(self) -> int:
        """Total number of registered tools."""
        return len(self._tools)

    @property
    def available_count(self) -> int:
        """Number of tools available on the system."""
        return sum(1 for t in self._tools.values() if t.available)

    def register_wrapped_tool(
        self,
        wrapper: ToolWrapper,
        has_parser: bool = False,
    ) -> ToolInfo:
        """
        Register a Tier 1 wrapped tool.

        Called during initialization for tools that have full
        wrappers (nmap, gobuster, nikto, sqlmap).

        Args:
            wrapper: The tool wrapper instance
            has_parser: Whether a parser exists for this tool

        Returns:
            The registered ToolInfo
        """
        name = wrapper.name
        known = KNOWN_TOOLS.get(name, {})

        info = ToolInfo(
            name=name,
            tier=ToolTier.WRAPPED,
            available=shutil.which(name) is not None,
            path=shutil.which(name),
            description=wrapper.description,
            category=known.get("category", wrapper.category),
            capabilities=known.get("capabilities", []),
            usage_hint=known.get("usage_hint", ""),
            wrapper_class=type(wrapper),
            has_parser=has_parser,
            requires_authorization=known.get("requires_authorization", False),
            can_modify_target=known.get("can_modify_target", False),
            is_passive=known.get("is_passive", True),
        )

        # Get version if available
        if info.available:
            info.version = _extract_version(name)

        self._tools[name] = info
        return info

    def register_discovered_tool(
        self,
        name: str,
        probe_help: bool = True,
    ) -> ToolInfo:
        """
        Register a Tier 2 discovered tool.

        Called during system discovery for tools found on the system
        that don't have dedicated wrappers.

        Args:
            name: Tool binary name
            probe_help: Whether to extract help text (slower but richer)

        Returns:
            The registered ToolInfo
        """
        known = KNOWN_TOOLS.get(name, {})

        info = ToolInfo(
            name=name,
            tier=ToolTier.DISCOVERED,
            available=True,
            path=shutil.which(name),
            description=known.get("description", f"{name} security tool"),
            category=known.get("category", ToolCategory.UTILITY),
            capabilities=known.get("capabilities", []),
            usage_hint=known.get("usage_hint", ""),
            requires_authorization=known.get("requires_authorization", False),
            can_modify_target=known.get("can_modify_target", False),
            is_passive=known.get("is_passive", True),
        )

        # Probe for version and help if requested
        if probe_help:
            info.version = _extract_version(name)

            help_text = _extract_help_text(name)
            if help_text:
                info.help_text = help_text[:2000]  # Cap for memory
                info.common_flags = _parse_common_flags(help_text)

                # Extract usage if not in known tools
                if not info.usage_hint:
                    info.usage_hint = _extract_usage_hint(help_text)

                # Try to extract description from help if not known
                if name not in KNOWN_TOOLS:
                    first_line = help_text.split("\n")[0].strip()
                    if first_line and len(first_line) < 200:
                        info.description = first_line

        self._tools[name] = info
        return info

    def discover(
        self,
        probe_help: bool = True,
        extra_tools: Optional[list[str]] = None,
    ) -> dict:
        """
        Discover all available security tools on the system.

        Scans for known Kali tools and optionally probes their
        help text for LLM context.

        Args:
            probe_help: Extract help text from discovered tools
            extra_tools: Additional tool names to check

        Returns:
            Discovery summary dict
        """
        start = time.time()

        # Start with all known tool names
        tools_to_check = set(KNOWN_TOOLS.keys())

        # Add any extra tools
        if extra_tools:
            tools_to_check.update(extra_tools)

        # Discover which are available
        found = 0
        not_found = 0

        for name in sorted(tools_to_check):
            # Skip if already registered as wrapped
            if name in self._tools and self._tools[name].tier == ToolTier.WRAPPED:
                if shutil.which(name):
                    found += 1
                continue

            if shutil.which(name):
                self.register_discovered_tool(name, probe_help=probe_help)
                found += 1
            else:
                not_found += 1

        self._discovered = True
        self._discovery_time = time.time() - start

        return {
            "found": found,
            "not_found": not_found,
            "total_registered": self.tool_count,
            "available": self.available_count,
            "wrapped": sum(1 for t in self._tools.values() if t.tier == ToolTier.WRAPPED),
            "discovered": sum(1 for t in self._tools.values() if t.tier == ToolTier.DISCOVERED),
            "discovery_time_seconds": round(self._discovery_time, 2),
        }

    # ── Lookup Methods ──────────────────────────────────────────────

    def get(self, name: str) -> Optional[ToolInfo]:
        """Get tool info by name."""
        return self._tools.get(name)

    def get_all(self) -> list[ToolInfo]:
        """Get all registered tools."""
        return list(self._tools.values())

    def get_available(self) -> list[ToolInfo]:
        """Get all available (installed) tools."""
        return [t for t in self._tools.values() if t.available]

    def get_by_tier(self, tier: ToolTier) -> list[ToolInfo]:
        """Get tools by integration tier."""
        return [t for t in self._tools.values() if t.tier == tier and t.available]

    def get_by_category(self, category: ToolCategory) -> list[ToolInfo]:
        """Get available tools by category."""
        return [
            t for t in self._tools.values()
            if t.category == category and t.available
        ]

    def get_by_capability(self, capability: ToolCapability) -> list[ToolInfo]:
        """Get available tools that have a specific capability."""
        return [
            t for t in self._tools.values()
            if capability in t.capabilities and t.available
        ]

    def get_passive_tools(self) -> list[ToolInfo]:
        """Get tools that are passive (read-only, no target modification)."""
        return [t for t in self._tools.values() if t.is_passive and t.available]

    def get_exploit_tools(self) -> list[ToolInfo]:
        """Get tools that require authorization (exploit-class)."""
        return [
            t for t in self._tools.values()
            if t.requires_authorization and t.available
        ]

    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered and available."""
        info = self._tools.get(name)
        return info is not None and info.available

    def requires_auth(self, name: str) -> bool:
        """Check if a tool requires authorization before execution."""
        info = self._tools.get(name)
        if info is None:
            # Unknown tools always require authorization (fail-closed)
            return True
        return info.requires_authorization

    # ── LLM Context Generation ──────────────────────────────────────

    def build_llm_context(
        self,
        categories: Optional[list[ToolCategory]] = None,
        capabilities: Optional[list[ToolCapability]] = None,
        include_unavailable: bool = False,
        include_help: bool = False,
        max_tools: int = 50,
    ) -> str:
        """
        Build a context string for LLM prompts describing available tools.

        This is the primary interface between the registry and the LLM.
        It generates a formatted description of tools that helps the LLM
        choose the right tool and generate correct commands.

        Args:
            categories: Filter to specific categories
            capabilities: Filter to specific capabilities
            include_unavailable: Include tools not installed
            include_help: Include help text excerpts (verbose)
            max_tools: Maximum tools to include

        Returns:
            Formatted context string for LLM system/user prompts
        """
        tools = list(self._tools.values())

        # Apply filters
        if not include_unavailable:
            tools = [t for t in tools if t.available]

        if categories:
            tools = [t for t in tools if t.category in categories]

        if capabilities:
            tools = [
                t for t in tools
                if any(c in t.capabilities for c in capabilities)
            ]

        # Sort: wrapped first, then by category, then name
        tools.sort(key=lambda t: (
            0 if t.tier == ToolTier.WRAPPED else 1,
            t.category.value,
            t.name,
        ))

        # Cap
        tools = tools[:max_tools]

        if not tools:
            return "No matching tools available."

        lines = [
            f"# Available Security Tools ({len(tools)} tools)",
            "",
        ]

        # Group by category
        current_category = None
        for tool in tools:
            if tool.category != current_category:
                current_category = tool.category
                lines.append(f"\n## {current_category.value.upper()}")

            tier_marker = "★" if tool.tier == ToolTier.WRAPPED else "○"
            lines.append(f"\n{tier_marker} {tool.to_llm_context(include_help=include_help)}")

        lines.extend([
            "",
            "Legend: ★ = Full wrapper (structured I/O) | ○ = Direct execution",
            "Tools marked REQUIRES_AUTH need user approval before running.",
        ])

        return "\n".join(lines)

    def build_tool_selection_prompt(
        self,
        task_description: str,
    ) -> str:
        """
        Build a prompt specifically for tool selection.

        Given a task, generates context that helps the LLM
        choose the best tool(s).

        Args:
            task_description: What the user wants to accomplish

        Returns:
            Formatted prompt string
        """
        context = self.build_llm_context(include_help=False)

        return f"""Given the following task, select the best tool(s) to accomplish it.

Task: {task_description}

{context}

For each selected tool, specify:
1. Tool name
2. Why it's the best choice
3. Key flags/options to use
4. Whether it needs authorization

Prefer ★ (wrapped) tools when available - they have structured output parsing.
Use ○ (direct) tools when no wrapped alternative exists for the task.
"""

    # ── Serialization ───────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialize the full registry to a dictionary."""
        return {
            "discovered": self._discovered,
            "discovery_time_seconds": round(self._discovery_time, 2),
            "total": self.tool_count,
            "available": self.available_count,
            "tools": {
                name: info.to_dict()
                for name, info in sorted(self._tools.items())
            },
        }

    def summary(self) -> dict:
        """Get a compact summary of the registry state."""
        by_category = {}
        by_tier = {"wrapped": 0, "discovered": 0}

        for tool in self._tools.values():
            if not tool.available:
                continue

            cat = tool.category.value
            by_category[cat] = by_category.get(cat, 0) + 1
            by_tier[tool.tier.value] += 1

        return {
            "total_registered": self.tool_count,
            "available": self.available_count,
            "by_tier": by_tier,
            "by_category": by_category,
            "requires_auth_count": len(self.get_exploit_tools()),
            "discovery_time_seconds": round(self._discovery_time, 2),
        }


# ─────────────────────────────────────────────────────────────────────
#  Global Registry Instance
# ─────────────────────────────────────────────────────────────────────

_registry: Optional[ToolRegistry] = None


def get_registry() -> ToolRegistry:
    """
    Get the global tool registry instance.

    Lazily creates and initializes the registry on first call.
    Registers wrapped tools and runs system discovery.
    """
    global _registry

    if _registry is None:
        _registry = ToolRegistry()
        _initialize_registry(_registry)

    return _registry


def reset_registry() -> None:
    """Reset the global registry (for testing)."""
    global _registry
    _registry = None


def _initialize_registry(registry: ToolRegistry) -> None:
    """
    Initialize the registry with wrapped tools and run discovery.

    This is called once on first access to the global registry.
    """
    # Import here to avoid circular imports
    from .nmap import NmapWrapper
    from .gobuster import GobusterWrapper
    from .nikto import NiktoWrapper
    from .sqlmap import SqlmapWrapper
    from ..parsers import PARSERS

    # Register Tier 1 wrapped tools
    wrapped_tools = [
        NmapWrapper(),
        GobusterWrapper(),
        NiktoWrapper(),
        SqlmapWrapper(),
    ]

    for wrapper in wrapped_tools:
        registry.register_wrapped_tool(
            wrapper,
            has_parser=wrapper.name in PARSERS,
        )

    # Run system discovery for Tier 2 tools
    registry.discover(probe_help=True)
