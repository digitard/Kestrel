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
Kestrel - YesWeHack API Client (Stub)

Stub client for YesWeHack bug bounty platform.
Authentication uses email + password to obtain a JWT, then Bearer token auth.

API Reference: https://api.yeswehack.com/
Status: STUB — full implementation planned for a future phase.

Endpoints (planned):
  POST /auth/login               - Authenticate (email + password → JWT)
  GET  /programs                 - List programs
  GET  /programs/{slug}          - Program details
"""

import logging
from typing import Optional

from .base import (
    BasePlatformClient,
    ClientConfig,
    PlatformAPIError,
    AuthenticationError,
    NotFoundError,
)
from .models import Platform, Program


logger = logging.getLogger(__name__)

# YesWeHack API base URL
YESWEHACK_API_URL = "https://api.yeswehack.com"


class YesWeHackClient(BasePlatformClient):
    """
    YesWeHack API client.

    Status: STUB — returns empty results. Full implementation
    requires YesWeHack credentials and will be completed in a
    future phase.

    Authentication note: YesWeHack uses a two-step auth flow:
      1. POST /auth/login with {email, password} → receive JWT
      2. Use JWT as Bearer token for subsequent requests

    Usage:
        config = ClientConfig(api_key="email@example.com", api_secret="password")
        client = YesWeHackClient(config)
        programs = client.list_programs()  # Returns [] until implemented
    """

    platform = Platform.YESWEHACK

    def __init__(self, config: ClientConfig) -> None:
        super().__init__(config)
        self._api_url = config.base_url or YESWEHACK_API_URL
        self._email = config.api_key
        self._password = config.api_secret
        self._jwt: Optional[str] = None
        logger.debug("YesWeHackClient initialized (stub mode)")

    def _configure_auth(self, session) -> None:
        """Configure auth on the requests session. JWT set after login()."""
        session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Kestrel/0.6.0.0",
        })
        if self._jwt:
            session.headers["Authorization"] = f"Bearer {self._jwt}"

    def _get_headers(self) -> dict:
        """Return Authorization headers (requires prior login)."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Kestrel/0.6.0.0",
        }
        if self._jwt:
            headers["Authorization"] = f"Bearer {self._jwt}"
        return headers

    def login(self) -> bool:
        """
        Authenticate with YesWeHack and obtain JWT token.

        STUB: Returns False until full implementation.

        Returns:
            False (stub — cannot authenticate without real API call)
        """
        logger.warning(
            "YesWeHackClient.login() is a stub — returning False. "
            "Full implementation is planned for a future phase."
        )
        return False

    def list_programs(self, page: int = 1, per_page: int = 25) -> list[Program]:
        """
        List YesWeHack programs.

        STUB: Returns empty list until full implementation.

        Args:
            page: Page number (1-indexed)
            per_page: Results per page

        Returns:
            List of Program objects
        """
        logger.warning(
            "YesWeHackClient.list_programs() is a stub — no data returned. "
            "Full implementation is planned for a future phase."
        )
        return []

    def get_programs(self, **filters) -> list[Program]:
        """STUB: Returns empty list until full implementation."""
        return self.list_programs()

    def get_scope(self, program_handle: str) -> list:
        """STUB: Returns empty list until full implementation."""
        return []

    def get_program(self, slug: str) -> Program:
        """
        Get a specific YesWeHack program by slug.

        STUB: Raises NotFoundError until full implementation.

        Args:
            slug: Program slug/handle

        Returns:
            Program object

        Raises:
            NotFoundError: Always (stub)
        """
        logger.warning(
            "YesWeHackClient.get_program() is a stub — no data returned. "
            "Full implementation is planned for a future phase."
        )
        raise NotFoundError(f"YesWeHack program '{slug}' not found (stub client)")

    def test_auth(self) -> bool:
        """
        Test if credentials are valid.

        STUB: Returns False until full implementation.

        Returns:
            False (stub — cannot authenticate without real API call)
        """
        logger.warning(
            "YesWeHackClient.test_auth() is a stub — returning False. "
            "Set YWH_EMAIL and YWH_PASSWORD env vars and implement full client."
        )
        return False

    @property
    def is_stub(self) -> bool:
        """Returns True — this client is a stub pending full implementation."""
        return True
