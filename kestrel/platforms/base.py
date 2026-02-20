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
Kestrel Platform Client - Base

Shared HTTP client infrastructure for all platform API integrations.
Provides authentication management, rate limiting, error handling,
and retry logic.
"""

import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import Program, Platform


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
#  Rate Limiter
# ─────────────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Token bucket rate limiter for API calls.

    Enforces a maximum number of requests per time window.
    Automatically sleeps when the limit is reached.
    """

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: list[float] = []

    def acquire(self) -> float:
        """
        Acquire a rate limit token. Blocks if necessary.

        Returns:
            Wait time in seconds (0.0 if no wait needed)
        """
        now = time.time()

        # Purge timestamps outside the window
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]

        if len(self._timestamps) >= self.max_requests:
            # Need to wait until the oldest timestamp expires
            wait_until = self._timestamps[0] + self.window_seconds
            wait_time = wait_until - now
            if wait_time > 0:
                logger.debug(f"Rate limit reached, waiting {wait_time:.1f}s")
                time.sleep(wait_time)
                # Re-purge after sleeping
                now = time.time()
                cutoff = now - self.window_seconds
                self._timestamps = [t for t in self._timestamps if t > cutoff]
                self._timestamps.append(now)
                return wait_time

        self._timestamps.append(now)
        return 0.0

    @property
    def remaining(self) -> int:
        """Approximate remaining requests in current window."""
        now = time.time()
        cutoff = now - self.window_seconds
        active = sum(1 for t in self._timestamps if t > cutoff)
        return max(0, self.max_requests - active)

    def reset(self):
        """Clear all timestamps."""
        self._timestamps.clear()


# ─────────────────────────────────────────────────────────────────────
#  API Error Types
# ─────────────────────────────────────────────────────────────────────

class PlatformAPIError(Exception):
    """Base exception for platform API errors."""

    def __init__(self, message: str, status_code: int = 0, response: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class AuthenticationError(PlatformAPIError):
    """Invalid or expired credentials."""
    pass


class RateLimitError(PlatformAPIError):
    """API rate limit exceeded."""

    def __init__(self, message: str, retry_after: float = 60.0, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class NotFoundError(PlatformAPIError):
    """Resource not found."""
    pass


# ─────────────────────────────────────────────────────────────────────
#  Base Platform Client
# ─────────────────────────────────────────────────────────────────────

@dataclass
class ClientConfig:
    """Configuration for a platform API client."""
    api_key: str = ""
    api_secret: str = ""           # For basic auth (HackerOne)
    session_token: str = ""        # For session-based auth (Bugcrowd)
    base_url: str = ""
    timeout: int = 30
    max_retries: int = 3
    rate_limit_requests: int = 60
    rate_limit_window: float = 60.0
    verify_ssl: bool = True


class BasePlatformClient(ABC):
    """
    Abstract base class for bug bounty platform API clients.

    Provides:
      - Authenticated HTTP session with retry logic
      - Rate limiting
      - Error classification
      - Common request/response handling

    Subclasses implement platform-specific endpoints and
    data normalization.
    """

    PLATFORM: Platform = Platform.MANUAL

    def __init__(self, config: ClientConfig):
        self.config = config
        self._session: Optional[requests.Session] = None
        self._rate_limiter = RateLimiter(
            max_requests=config.rate_limit_requests,
            window_seconds=config.rate_limit_window,
        )
        self._request_count = 0
        self._last_error: Optional[PlatformAPIError] = None

    @property
    def session(self) -> requests.Session:
        """Lazy-initialized HTTP session with retry logic."""
        if self._session is None:
            self._session = self._build_session()
        return self._session

    def _build_session(self) -> requests.Session:
        """Build a requests session with retry and auth."""
        session = requests.Session()

        # Retry strategy for transient failures
        retry = Retry(
            total=self.config.max_retries,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # SSL verification
        session.verify = self.config.verify_ssl

        # Subclasses configure auth headers
        self._configure_auth(session)

        return session

    @abstractmethod
    def _configure_auth(self, session: requests.Session) -> None:
        """Configure authentication on the session. Implemented by subclasses."""
        pass

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> dict:
        """
        Make an authenticated, rate-limited API request.

        Args:
            method: HTTP method
            endpoint: API endpoint path (appended to base_url)
            params: Query parameters
            json_data: JSON request body

        Returns:
            Parsed JSON response

        Raises:
            PlatformAPIError subclass on failure
        """
        # Rate limiting
        self._rate_limiter.acquire()

        url = f"{self.config.base_url.rstrip('/')}/{endpoint.lstrip('/')}"

        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                timeout=self.config.timeout,
            )
            self._request_count += 1

            # Classify errors
            if response.status_code == 401:
                raise AuthenticationError(
                    "Authentication failed. Check your API credentials.",
                    status_code=401,
                    response=response,
                )
            elif response.status_code == 403:
                raise AuthenticationError(
                    "Insufficient permissions for this endpoint.",
                    status_code=403,
                    response=response,
                )
            elif response.status_code == 404:
                raise NotFoundError(
                    f"Resource not found: {endpoint}",
                    status_code=404,
                    response=response,
                )
            elif response.status_code == 429:
                retry_after = float(response.headers.get("Retry-After", 60))
                raise RateLimitError(
                    "Rate limit exceeded.",
                    retry_after=retry_after,
                    status_code=429,
                    response=response,
                )
            elif response.status_code >= 400:
                raise PlatformAPIError(
                    f"API error {response.status_code}: {response.text[:200]}",
                    status_code=response.status_code,
                    response=response,
                )

            return response.json() if response.text else {}

        except requests.ConnectionError as e:
            raise PlatformAPIError(f"Connection error: {e}")
        except requests.Timeout as e:
            raise PlatformAPIError(f"Request timed out after {self.config.timeout}s")

    def get(self, endpoint: str, params: Optional[dict] = None) -> dict:
        """Make a GET request."""
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint: str, json_data: Optional[dict] = None) -> dict:
        """Make a POST request."""
        return self._request("POST", endpoint, json_data=json_data)

    # ── Abstract methods for subclasses ─────────────────────────────

    @abstractmethod
    def test_auth(self) -> bool:
        """Test if credentials are valid. Returns True if authenticated."""
        pass

    @abstractmethod
    def get_programs(self, **filters) -> list[Program]:
        """Fetch programs from the platform."""
        pass

    @abstractmethod
    def get_program(self, handle: str) -> Program:
        """Fetch a single program by handle."""
        pass

    @abstractmethod
    def get_scope(self, program_handle: str) -> list:
        """Fetch scope entries for a program."""
        pass

    # ── Common properties ───────────────────────────────────────────

    @property
    def is_configured(self) -> bool:
        """Check if client has credentials configured."""
        return bool(self.config.api_key or self.config.session_token)

    @property
    def request_count(self) -> int:
        """Total requests made by this client."""
        return self._request_count

    @property
    def rate_limit_remaining(self) -> int:
        """Approximate remaining rate limit."""
        return self._rate_limiter.remaining

    def close(self):
        """Close the HTTP session."""
        if self._session:
            self._session.close()
            self._session = None
