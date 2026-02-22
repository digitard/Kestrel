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
Kestrel - IntiGriti API Client (Stub)

Stub client for IntiGriti bug bounty platform.
Authentication uses a personal API token passed as a Bearer token.

API Reference: https://api.intigriti.com/docs
Status: STUB — full implementation planned for a future phase.

Endpoints (planned):
  GET /api/core/researcher/program  - List programs
  GET /api/core/researcher/program/{handle} - Program details
"""

import logging
from typing import Optional

from .base import (
    BasePlatformClient,
    ClientConfig,
    PlatformAPIError,
    NotFoundError,
)
from .models import Platform, Program


logger = logging.getLogger(__name__)

# IntiGriti API base URL
INTIGRITI_API_URL = "https://api.intigriti.com"


class IntiGritiClient(BasePlatformClient):
    """
    IntiGriti API client.

    Status: STUB — returns empty results. Full implementation
    requires IntiGriti API credentials and will be completed
    in a future phase.

    Usage:
        config = ClientConfig(api_key="your_intigriti_token")
        client = IntiGritiClient(config)
        programs = client.list_programs()  # Returns [] until implemented
    """

    platform = Platform.INTIGRITI

    def __init__(self, config: ClientConfig) -> None:
        super().__init__(config)
        self._api_url = config.base_url or INTIGRITI_API_URL
        self._token = config.api_key
        logger.debug("IntiGritiClient initialized (stub mode)")

    def _configure_auth(self, session) -> None:
        """Configure Bearer token auth on the requests session."""
        session.headers.update({
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": "Kestrel/0.6.0.0",
        })

    def _get_headers(self) -> dict:
        """Return Authorization headers for IntiGriti Bearer token auth."""
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": "Kestrel/0.6.0.0",
        }

    def list_programs(self, page: int = 1, per_page: int = 25) -> list[Program]:
        """
        List IntiGriti programs.

        STUB: Returns empty list until full implementation.

        Args:
            page: Page number (1-indexed)
            per_page: Results per page

        Returns:
            List of Program objects
        """
        logger.warning(
            "IntiGritiClient.list_programs() is a stub — no data returned. "
            "Full implementation is planned for a future phase."
        )
        return []

    def get_programs(self, **filters) -> list[Program]:
        """STUB: Returns empty list until full implementation."""
        return self.list_programs()

    def get_program(self, handle: str) -> Program:
        """
        Get a specific IntiGriti program by handle.

        STUB: Raises NotFoundError until full implementation.

        Args:
            handle: Program handle/slug

        Returns:
            Program object

        Raises:
            NotFoundError: Always (stub)
        """
        logger.warning(
            "IntiGritiClient.get_program() is a stub — no data returned. "
            "Full implementation is planned for a future phase."
        )
        raise NotFoundError(f"IntiGriti program '{handle}' not found (stub client)")

    def get_scope(self, program_handle: str) -> list:
        """STUB: Returns empty list until full implementation."""
        return []

    def test_auth(self) -> bool:
        """
        Test if credentials are valid.

        STUB: Returns False until full implementation.

        Returns:
            False (stub — cannot authenticate without real API call)
        """
        logger.warning(
            "IntiGritiClient.test_auth() is a stub — returning False. "
            "Set INTIGRITI_TOKEN env var and implement full client to authenticate."
        )
        return False

    @property
    def is_stub(self) -> bool:
        """Returns True — this client is a stub pending full implementation."""
        return True
