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
