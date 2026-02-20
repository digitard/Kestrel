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
