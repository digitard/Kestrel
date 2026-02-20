"""
Kestrel Nmap Tool Wrapper

Wraps nmap for network reconnaissance and port scanning.
"""

from typing import Optional
from .base import (
    ToolWrapper,
    BaseToolWrapper,
    ToolRequest,
    ToolSchema,
    ToolCategory,
    ValidationResult,
)


class NmapWrapper(BaseToolWrapper):
    """
    Wrapper for nmap network scanner.
    
    Supports:
    - Port scanning (TCP, UDP)
    - Service detection
    - OS detection
    - Script scanning
    - Various scan types
    """
    
    @property
    def name(self) -> str:
        return "nmap"
    
    @property
    def category(self) -> ToolCategory:
        return ToolCategory.RECON
    
    @property
    def description(self) -> str:
        return "Network port scanner for discovering hosts and services"
    
    def get_schema(self) -> ToolSchema:
        return ToolSchema(
            name=self.name,
            description=self.description,
            category=self.category,
            requires_target=True,
            target_types=["host", "ip", "cidr", "range"],
            options=[
                {
                    "name": "scan_type",
                    "type": "string",
                    "description": "Type of scan: quick, default, full, stealth, udp",
                    "default": "default",
                },
                {
                    "name": "ports",
                    "type": "string",
                    "description": "Ports to scan (e.g., '80,443', '1-1000', 'top100')",
                    "default": None,
                },
                {
                    "name": "service_detection",
                    "type": "boolean",
                    "description": "Enable service/version detection (-sV)",
                    "default": True,
                },
                {
                    "name": "os_detection",
                    "type": "boolean",
                    "description": "Enable OS detection (-O)",
                    "default": False,
                },
                {
                    "name": "scripts",
                    "type": "string",
                    "description": "NSE scripts to run (e.g., 'default', 'vuln', 'safe')",
                    "default": None,
                },
                {
                    "name": "timing",
                    "type": "integer",
                    "description": "Timing template 0-5 (higher = faster, louder)",
                    "default": 3,
                },
            ],
            examples=[
                {
                    "intent": "Quick scan of common ports",
                    "request": {
                        "tool": "nmap",
                        "target": "example.com",
                        "options": {"scan_type": "quick"},
                    },
                },
                {
                    "intent": "Full port scan with service detection",
                    "request": {
                        "tool": "nmap",
                        "target": "192.168.1.1",
                        "ports": "1-65535",
                        "options": {
                            "service_detection": True,
                            "timing": 4,
                        },
                    },
                },
                {
                    "intent": "Vulnerability scan",
                    "request": {
                        "tool": "nmap",
                        "target": "example.com",
                        "options": {
                            "scripts": "vuln",
                            "service_detection": True,
                        },
                    },
                },
            ],
        )
    
    def validate(self, request: ToolRequest) -> ValidationResult:
        """Validate nmap request."""
        result = self.validate_target(request.target)
        
        # Validate scan type
        scan_type = request.options.get("scan_type", "default")
        valid_scan_types = ["quick", "default", "full", "stealth", "udp", "aggressive"]
        if scan_type not in valid_scan_types:
            result.add_error(f"Invalid scan_type: {scan_type}. Must be one of: {valid_scan_types}")
        
        # Validate timing
        timing = request.options.get("timing", 3)
        if not isinstance(timing, int) or timing < 0 or timing > 5:
            result.add_error("Timing must be an integer between 0 and 5")
        
        # Validate ports format
        if request.ports:
            if not self._validate_ports(request.ports):
                result.add_error(f"Invalid ports format: {request.ports}")
        
        return result
    
    def _validate_ports(self, ports: str) -> bool:
        """Validate ports specification."""
        # Allow special keywords
        if ports.lower() in ["top100", "top1000", "-"]:
            return True
        
        # Check format: comma-separated, ranges allowed
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                # Range format
                try:
                    start, end = part.split("-")
                    if start:  # Allow "-1000" for "1-1000"
                        int(start)
                    int(end)
                except ValueError:
                    return False
            else:
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        return False
                except ValueError:
                    return False
        
        return True
    
    def build_command(self, request: ToolRequest) -> str:
        """Build nmap command."""
        args = ["nmap"]
        
        # Scan type presets
        scan_type = request.options.get("scan_type", "default")
        
        if scan_type == "quick":
            args.extend(["-T4", "-F"])  # Fast scan, top 100 ports
        elif scan_type == "stealth":
            args.extend(["-sS", "-T2"])  # SYN scan, slower timing
        elif scan_type == "udp":
            args.extend(["-sU"])  # UDP scan
        elif scan_type == "full":
            args.extend(["-p-", "-T4"])  # All ports
        elif scan_type == "aggressive":
            args.extend(["-A", "-T4"])  # Aggressive scan
        # default: no special flags
        
        # Ports
        if request.ports:
            if request.ports.lower() == "top100":
                args.append("-F")
            elif request.ports.lower() == "top1000":
                pass  # Default nmap behavior
            else:
                args.extend(["-p", request.ports])
        
        # Service detection
        if request.options.get("service_detection", True):
            args.append("-sV")
        
        # OS detection
        if request.options.get("os_detection", False):
            args.append("-O")
        
        # Scripts
        scripts = request.options.get("scripts")
        if scripts:
            args.extend(["--script", scripts])
        
        # Timing (if not set by scan_type)
        timing = request.options.get("timing")
        if timing is not None and scan_type == "default":
            args.append(f"-T{timing}")
        
        # Verbose
        if request.verbose:
            args.append("-v")
        
        # Output format
        if request.output_format:
            format_map = {
                "xml": "-oX",
                "grep": "-oG",
                "normal": "-oN",
            }
            if request.output_format in format_map:
                output_file = request.output_file or "-"
                args.extend([format_map[request.output_format], output_file])
        
        # Target (must be last)
        args.append(self.escape_arg(request.target))
        
        return " ".join(args)
    
    def get_default_timeout(self) -> int:
        """Nmap can take a while, especially for full scans."""
        return 600  # 10 minutes
    
    def supports_output_format(self, format: str) -> bool:
        return format in ["xml", "grep", "normal"]
