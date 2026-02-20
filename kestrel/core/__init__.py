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
    ExecutionResult,
    ExecutionStatus,
    check_kali_environment,
)
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
    # Executor
    "NativeExecutor",
    "ExecutionResult",
    "ExecutionStatus",
    "check_kali_environment",
    # Session
    "HuntSession",
    "SessionState",
    "SessionManager",
    "Finding",
    "FindingSeverity",
    "ExecutionRecord",
]
