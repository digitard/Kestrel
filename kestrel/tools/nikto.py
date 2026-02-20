"""
Kestrel Nikto Tool Wrapper

Wraps nikto for web server vulnerability scanning.
"""

from typing import Optional
from .base import (
    BaseToolWrapper,
    ToolRequest,
    ToolSchema,
    ToolCategory,
    ValidationResult,
)


class NiktoWrapper(BaseToolWrapper):
    """
    Wrapper for nikto web vulnerability scanner.
    
    Supports:
    - Web server scanning
    - CGI vulnerability detection
    - Server configuration issues
    - Default file detection
    """
    
    @property
    def name(self) -> str:
        return "nikto"
    
    @property
    def category(self) -> ToolCategory:
        return ToolCategory.VULNERABILITY
    
    @property
    def description(self) -> str:
        return "Web server vulnerability scanner"
    
    def get_schema(self) -> ToolSchema:
        return ToolSchema(
            name=self.name,
            description=self.description,
            category=self.category,
            requires_target=True,
            target_types=["url", "host"],
            options=[
                {
                    "name": "port",
                    "type": "integer",
                    "description": "Port to scan (default: 80)",
                    "default": None,
                },
                {
                    "name": "ssl",
                    "type": "boolean",
                    "description": "Use SSL/HTTPS",
                    "default": None,
                },
                {
                    "name": "tuning",
                    "type": "string",
                    "description": "Scan tuning options (1-9, a-c, x)",
                    "default": None,
                },
                {
                    "name": "plugins",
                    "type": "string",
                    "description": "Specific plugins to run",
                    "default": None,
                },
                {
                    "name": "max_time",
                    "type": "integer",
                    "description": "Maximum scan time in seconds",
                    "default": None,
                },
                {
                    "name": "no_cache",
                    "type": "boolean",
                    "description": "Disable response caching",
                    "default": False,
                },
                {
                    "name": "evasion",
                    "type": "string",
                    "description": "IDS evasion technique (1-8)",
                    "default": None,
                },
            ],
            examples=[
                {
                    "intent": "Scan web server for vulnerabilities",
                    "request": {
                        "tool": "nikto",
                        "target": "https://example.com",
                    },
                },
                {
                    "intent": "Quick scan focusing on interesting files",
                    "request": {
                        "tool": "nikto",
                        "target": "example.com",
                        "options": {
                            "port": 443,
                            "ssl": True,
                            "tuning": "1",
                        },
                    },
                },
                {
                    "intent": "Thorough vulnerability scan",
                    "request": {
                        "tool": "nikto",
                        "target": "example.com",
                        "options": {
                            "tuning": "x",
                            "max_time": 3600,
                        },
                    },
                },
            ],
        )
    
    def validate(self, request: ToolRequest) -> ValidationResult:
        """Validate nikto request."""
        result = self.validate_target(request.target)
        
        # Validate port
        port = request.options.get("port")
        if port is not None:
            if not isinstance(port, int) or port < 1 or port > 65535:
                result.add_error("Port must be between 1 and 65535")
        
        # Validate tuning
        tuning = request.options.get("tuning")
        if tuning:
            valid_tuning = set("0123456789abcx")
            if not all(c in valid_tuning for c in tuning):
                result.add_error(f"Invalid tuning option: {tuning}")
        
        # Validate evasion
        evasion = request.options.get("evasion")
        if evasion:
            valid_evasion = set("12345678ABCDE")
            if not all(c in valid_evasion for c in evasion):
                result.add_error(f"Invalid evasion option: {evasion}")
        
        return result
    
    def build_command(self, request: ToolRequest) -> str:
        """Build nikto command."""
        args = ["nikto"]
        
        # Parse target
        target = request.target
        ssl_detected = target.startswith("https://")
        
        # Clean target for -h flag
        if target.startswith("http://"):
            target = target[7:]
        elif target.startswith("https://"):
            target = target[8:]
        
        # Remove trailing slashes and paths for host
        host = target.split("/")[0]
        
        args.extend(["-h", self.escape_arg(host)])
        
        # Port
        port = request.options.get("port")
        if port:
            args.extend(["-p", str(port)])
        elif ssl_detected:
            args.extend(["-p", "443"])
        
        # SSL
        ssl = request.options.get("ssl", ssl_detected)
        if ssl:
            args.append("-ssl")
        
        # Tuning
        tuning = request.options.get("tuning")
        if tuning:
            args.extend(["-Tuning", tuning])
        
        # Plugins
        plugins = request.options.get("plugins")
        if plugins:
            args.extend(["-Plugins", plugins])
        
        # Max time
        max_time = request.options.get("max_time")
        if max_time:
            args.extend(["-maxtime", str(max_time)])
        
        # No cache
        if request.options.get("no_cache", False):
            args.append("-nocache")
        
        # Evasion
        evasion = request.options.get("evasion")
        if evasion:
            args.extend(["-evasion", evasion])
        
        # Output format
        if request.output_format:
            format_map = {
                "csv": "csv",
                "html": "htm",
                "xml": "xml",
                "json": "json",
            }
            if request.output_format in format_map:
                args.extend(["-Format", format_map[request.output_format]])
                if request.output_file:
                    args.extend(["-o", request.output_file])
        
        # Disable interactive prompts
        args.append("-ask=no")
        
        return " ".join(args)
    
    def get_default_timeout(self) -> int:
        """Nikto can take a long time."""
        return 600  # 10 minutes
    
    def supports_output_format(self, format: str) -> bool:
        return format in ["csv", "html", "xml", "json"]
