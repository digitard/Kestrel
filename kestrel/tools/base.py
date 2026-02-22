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
Kestrel Tool Wrappers - Base Classes

Provides the foundation for wrapping security tools with
structured input/output handling.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Any, TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    from kestrel.core.executor import UnifiedExecutor, ExecutionResult


class ToolCategory(Enum):
    """Categories of security tools."""
    RECON = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    FINGERPRINT = "fingerprinting"
    UTILITY = "utility"


@dataclass
class ToolRequest:
    """
    Request to execute a security tool.
    
    This is the standardized input format that gets translated
    to actual command-line arguments.
    """
    tool: str
    target: str
    
    # Common options
    ports: Optional[str] = None  # e.g., "80,443" or "1-1000"
    threads: Optional[int] = None
    timeout: Optional[int] = None
    
    # Tool-specific options
    options: dict[str, Any] = field(default_factory=dict)
    
    # Execution modifiers
    verbose: bool = False
    output_format: Optional[str] = None  # e.g., "xml", "json", "grep"
    output_file: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "tool": self.tool,
            "target": self.target,
            "ports": self.ports,
            "threads": self.threads,
            "timeout": self.timeout,
            "options": self.options,
            "verbose": self.verbose,
            "output_format": self.output_format,
            "output_file": self.output_file,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ToolRequest":
        """Create from dictionary."""
        return cls(
            tool=data.get("tool", ""),
            target=data.get("target", ""),
            ports=data.get("ports"),
            threads=data.get("threads"),
            timeout=data.get("timeout"),
            options=data.get("options", {}),
            verbose=data.get("verbose", False),
            output_format=data.get("output_format"),
            output_file=data.get("output_file"),
        )


@dataclass
class ValidationResult:
    """Result of validating a tool request."""
    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    
    def add_error(self, error: str) -> None:
        """Add an error (makes result invalid)."""
        self.errors.append(error)
        self.valid = False
    
    def add_warning(self, warning: str) -> None:
        """Add a warning (result still valid)."""
        self.warnings.append(warning)


@dataclass
class ToolSchema:
    """
    Schema describing a tool's capabilities and options.
    
    Used for LLM prompting and validation.
    """
    name: str
    description: str
    category: ToolCategory
    
    # Required inputs
    requires_target: bool = True
    target_types: list[str] = field(default_factory=lambda: ["host", "ip", "url"])
    
    # Supported options
    options: list[dict] = field(default_factory=list)
    
    # Examples for LLM
    examples: list[dict] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for LLM context."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "requires_target": self.requires_target,
            "target_types": self.target_types,
            "options": self.options,
            "examples": self.examples,
        }


class ToolWrapper(ABC):
    """
    Abstract base class for tool wrappers.
    
    Each tool wrapper:
    1. Defines the tool's schema (for LLM understanding)
    2. Validates requests
    3. Builds command-line arguments
    4. Provides default configurations
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name (e.g., 'nmap')."""
        pass
    
    @property
    @abstractmethod
    def category(self) -> ToolCategory:
        """Tool category."""
        pass
    
    @property
    def description(self) -> str:
        """Tool description for LLM context."""
        return f"{self.name} security tool"
    
    @abstractmethod
    def get_schema(self) -> ToolSchema:
        """
        Get the tool's schema.
        
        Returns:
            ToolSchema describing the tool
        """
        pass
    
    @abstractmethod
    def validate(self, request: ToolRequest) -> ValidationResult:
        """
        Validate a tool request.
        
        Args:
            request: The request to validate
            
        Returns:
            ValidationResult with any errors/warnings
        """
        pass
    
    @abstractmethod
    def build_command(self, request: ToolRequest) -> str:
        """
        Build the command-line string for execution.
        
        Args:
            request: Validated tool request
            
        Returns:
            Command string ready for execution
        """
        pass
    
    def get_default_timeout(self) -> int:
        """Get default timeout for this tool (seconds)."""
        return 300  # 5 minutes default
    
    def get_default_options(self) -> dict:
        """Get default options for this tool."""
        return {}
    
    def supports_output_format(self, format: str) -> bool:
        """Check if tool supports a specific output format."""
        return False


class BaseToolWrapper(ToolWrapper):
    """
    Base implementation with common functionality.

    Concrete tool wrappers should inherit from this.
    """

    def __init__(self, executor: Optional[Any] = None) -> None:
        """
        Initialize the wrapper.

        Args:
            executor: UnifiedExecutor instance. Auto-created on first execute()
                      call if not provided.
        """
        self._executor = executor

    def _get_executor(self) -> "UnifiedExecutor":
        """Return stored executor, creating UnifiedExecutor if needed."""
        if self._executor is None:
            from kestrel.core.executor import UnifiedExecutor
            self._executor = UnifiedExecutor()
        return self._executor

    def execute(self, request: "ToolRequest") -> "ExecutionResult":
        """
        Validate, build, and execute a tool request.

        Args:
            request: ToolRequest to execute

        Returns:
            ExecutionResult from UnifiedExecutor

        Raises:
            ValueError: If the request fails validation
        """
        from kestrel.core.executor import ExecutionResult, ExecutionStatus
        from datetime import datetime

        # Validate first
        validation = self.validate(request)
        if not validation.valid:
            now = datetime.now()
            return ExecutionResult(
                command=f"{self.name} [invalid request]",
                status=ExecutionStatus.FAILED,
                error_message=f"Validation failed: {'; '.join(validation.errors)}",
                started_at=now,
                completed_at=now,
                duration_seconds=0.0,
            )

        # Build command
        command = self.build_command(request)

        # Determine timeout
        timeout = request.timeout or self.get_default_timeout()

        # Execute via UnifiedExecutor
        return self._get_executor().execute(command=command, timeout=timeout)

    def validate_target(self, target: str) -> ValidationResult:
        """
        Basic target validation.
        
        Args:
            target: Target string to validate
            
        Returns:
            ValidationResult
        """
        result = ValidationResult()
        
        if not target:
            result.add_error("Target is required")
            return result
        
        if not target.strip():
            result.add_error("Target cannot be empty")
            return result
        
        # Block obviously dangerous targets
        dangerous = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
        ]
        
        target_lower = target.lower()
        for d in dangerous:
            if target_lower == d or target_lower.startswith(f"{d}:"):
                result.add_warning(f"Target '{target}' may be localhost")
        
        return result
    
    def escape_arg(self, arg: str) -> str:
        """
        Safely escape a command-line argument.
        
        Args:
            arg: Argument to escape
            
        Returns:
            Escaped argument
        """
        # Basic shell escaping
        if not arg:
            return '""'
        
        # If no special characters, return as-is
        if arg.isalnum() or all(c in ".-_/:@" for c in arg if not c.isalnum()):
            return arg
        
        # Quote the argument
        return f'"{arg}"'
