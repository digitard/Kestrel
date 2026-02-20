"""
Kestrel Core Module

Provides core functionality: configuration, execution, and session management.
"""

from .config import (
    Config,
    ServerConfig,
    DatabaseConfig,
    LLMConfig,
    ScopeConfig,
    AuthorizationConfig,
    AuditConfig,
    HuntingConfig,
    load_config,
    get_config,
    reset_config,
)
from .executor import (
    NativeExecutor,
    UnifiedExecutor,
    ExecutionResult,
    ExecutionStatus,
    check_kali_environment,
)
from .platform import (
    PlatformInfo,
    ExecutionMode,
    LLMBackendType,
    detect_platform,
    get_platform,
    reset_platform,
)
from .docker_manager import DockerManager
from .session import (
    HuntSession,
    SessionState,
    SessionManager,
    Finding,
    FindingSeverity,
    ExecutionRecord,
)


__all__ = [
    # Config
    "Config",
    "ServerConfig",
    "DatabaseConfig",
    "LLMConfig",
    "ScopeConfig",
    "AuthorizationConfig",
    "AuditConfig",
    "HuntingConfig",
    "load_config",
    "get_config",
    "reset_config",
    # Executor (legacy + new)
    "NativeExecutor",
    "UnifiedExecutor",
    "ExecutionResult",
    "ExecutionStatus",
    "check_kali_environment",
    # Platform detection
    "PlatformInfo",
    "ExecutionMode",
    "LLMBackendType",
    "detect_platform",
    "get_platform",
    "reset_platform",
    # Docker manager
    "DockerManager",
    # Session
    "HuntSession",
    "SessionState",
    "SessionManager",
    "Finding",
    "FindingSeverity",
    "ExecutionRecord",
]
