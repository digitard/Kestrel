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
Kestrel - HackerOne API Client

Thin client for the HackerOne Hacker API v1.
Uses HTTP Basic Auth with API username + token.

API Reference: https://api.hackerone.com/hacker-resources/
Endpoints used:
  GET /hackers/programs          - List programs
  GET /hackers/programs/{handle} - Get program details
  GET /hackers/programs/{handle}/structured_scopes - Get scope
"""

import logging
from datetime import datetime
from typing import Optional

import requests

from .base import (
    BasePlatformClient,
    ClientConfig,
    PlatformAPIError,
    NotFoundError,
)
from .models import (
    Program,
    Platform,
    ProgramState,
    ScopeEntry,
    AssetType,
    ScopeStatus,
)


logger = logging.getLogger(__name__)


# HackerOne asset type → our AssetType mapping
H1_ASSET_TYPE_MAP = {
    "URL": AssetType.URL,
    "CIDR": AssetType.CIDR,
    "DOMAIN": AssetType.DOMAIN,
    "WILDCARD": AssetType.WILDCARD,
    "IP_ADDRESS": AssetType.IP_ADDRESS,
    "APPLE_STORE_APP_ID": AssetType.MOBILE_APP,
    "GOOGLE_PLAY_APP_ID": AssetType.MOBILE_APP,
    "TESTFLIGHT": AssetType.MOBILE_APP,
    "OTHER_IPA": AssetType.MOBILE_APP,
    "OTHER_APK": AssetType.MOBILE_APP,
    "WINDOWS_APP_STORE_APP_ID": AssetType.EXECUTABLE,
    "SOURCE_CODE": AssetType.SOURCE_CODE,
    "DOWNLOADABLE_EXECUTABLES": AssetType.EXECUTABLE,
    "HARDWARE": AssetType.HARDWARE,
    "AI_MODEL": AssetType.OTHER,
    "SMART_CONTRACT": AssetType.OTHER,
    "OTHER": AssetType.OTHER,
}

# HackerOne program state → our ProgramState
H1_STATE_MAP = {
    "public_mode": ProgramState.OPEN,
    "soft_launched": ProgramState.OPEN,
    "open": ProgramState.OPEN,
    "paused": ProgramState.PAUSED,
    "disabled": ProgramState.CLOSED,
}


class HackerOneClient(BasePlatformClient):
    """
    HackerOne Hacker API v1 client.

    Authentication: HTTP Basic Auth
      - Username: API identifier
      - Password: API token

    Generate at: https://hackerone.com/settings/api_token/edit

    Usage:
        config = ClientConfig(
            api_key="your_api_username",
            api_secret="your_api_token",
        )
        client = HackerOneClient(config)

        if client.test_auth():
            programs = client.get_programs()
    """

    PLATFORM = Platform.HACKERONE
    DEFAULT_BASE_URL = "https://api.hackerone.com/v1"

    def __init__(self, config: Optional[ClientConfig] = None):
        if config is None:
            config = ClientConfig()
        if not config.base_url:
            config.base_url = self.DEFAULT_BASE_URL
        super().__init__(config)

    def _configure_auth(self, session: requests.Session) -> None:
        """Configure HTTP Basic Auth."""
        if self.config.api_key and self.config.api_secret:
            session.auth = (self.config.api_key, self.config.api_secret)
        session.headers.update({
            "Accept": "application/json",
        })

    @property
    def is_configured(self) -> bool:
        """HackerOne requires both username and token."""
        return bool(self.config.api_key and self.config.api_secret)

    def test_auth(self) -> bool:
        """
        Test authentication by fetching the first program.

        Returns:
            True if credentials are valid
        """
        if not self.is_configured:
            return False
        try:
            self.get("hackers/programs", params={"page[size]": "1"})
            return True
        except PlatformAPIError:
            return False

    def get_programs(
        self,
        page_size: int = 25,
        max_pages: int = 10,
    ) -> list[Program]:
        """
        Fetch all accessible programs.

        Args:
            page_size: Results per page (max 100)
            max_pages: Maximum pages to fetch

        Returns:
            List of normalized Program objects
        """
        programs = []
        page = 1

        while page <= max_pages:
            data = self.get("hackers/programs", params={
                "page[size]": str(min(page_size, 100)),
                "page[number]": str(page),
            })

            items = data.get("data", [])
            if not items:
                break

            for item in items:
                try:
                    program = self._normalize_program(item)
                    programs.append(program)
                except Exception as e:
                    logger.warning(f"Failed to parse H1 program: {e}")

            # Check for next page
            links = data.get("links", {})
            if not links.get("next"):
                break
            page += 1

        return programs

    def get_program(self, handle: str) -> Program:
        """
        Fetch a single program by handle.

        Args:
            handle: Program handle (e.g., "security")

        Returns:
            Normalized Program object

        Raises:
            NotFoundError: If program doesn't exist
        """
        data = self.get(f"hackers/programs/{handle}")
        item = data.get("data", data)
        program = self._normalize_program(item)

        # Also fetch structured scopes
        program.scope = self.get_scope(handle)

        return program

    def get_scope(self, program_handle: str) -> list[ScopeEntry]:
        """
        Fetch structured scope entries for a program.

        Args:
            program_handle: Program handle

        Returns:
            List of ScopeEntry objects
        """
        entries = []
        page = 1

        while page <= 10:
            data = self.get(
                f"hackers/programs/{program_handle}/structured_scopes",
                params={
                    "page[size]": "100",
                    "page[number]": str(page),
                },
            )

            items = data.get("data", [])
            if not items:
                break

            for item in items:
                try:
                    entry = self._normalize_scope_entry(item)
                    entries.append(entry)
                except Exception as e:
                    logger.warning(f"Failed to parse H1 scope entry: {e}")

            links = data.get("links", {})
            if not links.get("next"):
                break
            page += 1

        return entries

    # ── Normalization ───────────────────────────────────────────────

    def _normalize_program(self, data: dict) -> Program:
        """Convert HackerOne API program data to our Program model."""
        attrs = data.get("attributes", {})
        program_id = str(data.get("id", ""))
        handle = attrs.get("handle", "")

        # Parse structured scopes from relationships if included
        scope = []
        rels = data.get("relationships", {})
        scope_data = rels.get("structured_scopes", {}).get("data", [])
        for s in scope_data:
            try:
                scope.append(self._normalize_scope_entry(s))
            except Exception:
                pass

        return Program(
            id=program_id,
            handle=handle,
            name=attrs.get("name", handle),
            platform=Platform.HACKERONE,
            state=H1_STATE_MAP.get(attrs.get("state", ""), ProgramState.UNKNOWN),
            offers_bounties=bool(attrs.get("offers_bounties", False)),
            managed=bool(attrs.get("triage_active", False)),
            scope=scope,
            url=f"https://hackerone.com/{handle}",
            policy=attrs.get("policy", ""),
            min_bounty=0.0,
            max_bounty=0.0,
            currency=attrs.get("currency", "usd"),
            raw_data=data,
        )

    def _normalize_scope_entry(self, data: dict) -> ScopeEntry:
        """Convert HackerOne structured scope to our ScopeEntry model."""
        attrs = data.get("attributes", {})

        # Map asset type
        h1_type = attrs.get("asset_type", "OTHER")
        asset_type = H1_ASSET_TYPE_MAP.get(h1_type, AssetType.OTHER)

        # Determine scope status
        eligible = attrs.get("eligible_for_submission", True)
        scope_status = ScopeStatus.IN_SCOPE if eligible else ScopeStatus.OUT_OF_SCOPE

        return ScopeEntry(
            asset_identifier=attrs.get("asset_identifier", ""),
            asset_type=asset_type,
            scope_status=scope_status,
            instruction=attrs.get("instruction", "") or "",
            eligible_for_bounty=attrs.get("eligible_for_bounty", False),
            max_severity=attrs.get("max_severity", "") or "",
        )
