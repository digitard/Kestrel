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
Kestrel Platform Integration

Provides API clients for bug bounty platforms, program data models,
scope validation, and local caching.

Platform Clients:
  - HackerOneClient: HackerOne Hacker API v1
  - BugcrowdClient:  Bugcrowd REST API

Core Components:
  - Program/ScopeEntry: Platform-agnostic data models
  - ScopeValidator: CRITICAL safety gate for target authorization
  - ProgramCache: SQLite-backed local program storage
"""

from .models import (
    Platform,
    ProgramState,
    AssetType,
    ScopeStatus,
    ScopeEntry,
    Program,
    ScopeValidationResult,
    ScopeValidator,
)
from .base import (
    BasePlatformClient,
    ClientConfig,
    RateLimiter,
    PlatformAPIError,
    AuthenticationError,
    RateLimitError,
    NotFoundError,
)
from .hackerone import HackerOneClient
from .bugcrowd import BugcrowdClient
from .cache import ProgramCache
from .credentials import CredentialManager, get_credentials, reset_credentials


__all__ = [
    # Models
    "Platform",
    "ProgramState",
    "AssetType",
    "ScopeStatus",
    "ScopeEntry",
    "Program",
    "ScopeValidationResult",
    "ScopeValidator",
    # Base
    "BasePlatformClient",
    "ClientConfig",
    "RateLimiter",
    "PlatformAPIError",
    "AuthenticationError",
    "RateLimitError",
    "NotFoundError",
    # Clients
    "HackerOneClient",
    "BugcrowdClient",
    # Cache
    "ProgramCache",
    # Credentials
    "CredentialManager",
    "get_credentials",
    "reset_credentials",
]
