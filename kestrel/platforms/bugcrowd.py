"""
Kestrel - Bugcrowd API Client

Thin client for the Bugcrowd REST API.
Uses Token authentication with username:password format.

API Reference: https://docs.bugcrowd.com/api/
Specification: JSON:API (https://jsonapi.org/)

Endpoints used:
  GET /programs                  - List programs
  GET /programs/{uuid}           - Get program details
  GET /targets                   - Get scope targets
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


# Bugcrowd target category → our AssetType mapping
BC_ASSET_TYPE_MAP = {
    "website": AssetType.URL,
    "url": AssetType.URL,
    "api": AssetType.API,
    "android": AssetType.MOBILE_APP,
    "apple": AssetType.MOBILE_APP,
    "mobile": AssetType.MOBILE_APP,
    "hardware": AssetType.HARDWARE,
    "other": AssetType.OTHER,
    "iot": AssetType.HARDWARE,
}


class BugcrowdClient(BasePlatformClient):
    """
    Bugcrowd API client.

    Authentication: Token-based
      - Format: "Token username:password"

    API tokens are provisioned per-user in Bugcrowd's organization settings.

    Usage:
        config = ClientConfig(
            api_key="your_token_username",
            api_secret="your_token_password",
        )
        client = BugcrowdClient(config)

        if client.test_auth():
            programs = client.get_programs()
    """

    PLATFORM = Platform.BUGCROWD
    DEFAULT_BASE_URL = "https://api.bugcrowd.com"

    def __init__(self, config: Optional[ClientConfig] = None):
        if config is None:
            config = ClientConfig()
        if not config.base_url:
            config.base_url = self.DEFAULT_BASE_URL
        super().__init__(config)

    def _configure_auth(self, session: requests.Session) -> None:
        """Configure Token authentication."""
        session.headers.update({
            "Accept": "application/vnd.bugcrowd+json",
        })
        if self.config.api_key and self.config.api_secret:
            token = f"{self.config.api_key}:{self.config.api_secret}"
            session.headers["Authorization"] = f"Token {token}"

    @property
    def is_configured(self) -> bool:
        """Bugcrowd requires token username and password."""
        return bool(self.config.api_key and self.config.api_secret)

    def test_auth(self) -> bool:
        """
        Test authentication by fetching programs.

        Returns:
            True if credentials are valid
        """
        if not self.is_configured:
            return False
        try:
            self.get("programs", params={"page[limit]": "1"})
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

        Uses JSON:API include to fetch scope in same request.

        Args:
            page_size: Results per page (max 100)
            max_pages: Maximum pages to fetch

        Returns:
            List of normalized Program objects
        """
        programs = []
        offset = 0

        for _ in range(max_pages):
            data = self.get("programs", params={
                "page[limit]": str(min(page_size, 100)),
                "page[offset]": str(offset),
                "include": "current_brief.target_groups.targets",
                "fields[program]": "code,name,current_brief",
                "fields[target_group]": "name,targets,in_scope",
                "fields[target]": "name,category,uri",
            })

            items = data.get("data", [])
            if not items:
                break

            # Build included resources lookup
            included = self._build_included_map(data.get("included", []))

            for item in items:
                try:
                    program = self._normalize_program(item, included)
                    programs.append(program)
                except Exception as e:
                    logger.warning(f"Failed to parse Bugcrowd program: {e}")

            offset += len(items)
            if len(items) < page_size:
                break

        return programs

    def get_program(self, program_uuid: str) -> Program:
        """
        Fetch a single program by UUID.

        Args:
            program_uuid: Program UUID

        Returns:
            Normalized Program object
        """
        data = self.get(f"programs/{program_uuid}", params={
            "include": "current_brief.target_groups.targets",
            "fields[program]": "code,name,current_brief",
            "fields[target_group]": "name,targets,in_scope",
            "fields[target]": "name,category,uri",
        })

        item = data.get("data", data)
        included = self._build_included_map(data.get("included", []))
        return self._normalize_program(item, included)

    def get_scope(self, program_uuid: str) -> list[ScopeEntry]:
        """
        Fetch scope targets for a program.

        Uses the /targets endpoint with program filter.

        Args:
            program_uuid: Program UUID

        Returns:
            List of ScopeEntry objects
        """
        entries = []
        offset = 0

        for _ in range(10):
            data = self.get("targets", params={
                "filter[program_id]": program_uuid,
                "page[limit]": "100",
                "page[offset]": str(offset),
            })

            items = data.get("data", [])
            if not items:
                break

            for item in items:
                try:
                    entry = self._normalize_target(item)
                    entries.append(entry)
                except Exception as e:
                    logger.warning(f"Failed to parse Bugcrowd target: {e}")

            offset += len(items)
            if len(items) < 100:
                break

        return entries

    # ── JSON:API Helpers ────────────────────────────────────────────

    @staticmethod
    def _build_included_map(included: list) -> dict:
        """
        Build a lookup map from JSON:API included resources.

        Key: "type:id" → resource dict
        """
        result = {}
        for item in included:
            key = f"{item.get('type', '')}:{item.get('id', '')}"
            result[key] = item
        return result

    @staticmethod
    def _resolve_relationship(data: dict, rel_name: str, included: dict) -> list:
        """Resolve a JSON:API relationship to its included resources."""
        rels = data.get("relationships", {})
        rel_data = rels.get(rel_name, {}).get("data", [])

        if isinstance(rel_data, dict):
            rel_data = [rel_data]

        resolved = []
        for ref in rel_data:
            key = f"{ref.get('type', '')}:{ref.get('id', '')}"
            resource = included.get(key)
            if resource:
                resolved.append(resource)

        return resolved

    # ── Normalization ───────────────────────────────────────────────

    def _normalize_program(self, data: dict, included: dict) -> Program:
        """Convert Bugcrowd API program data to our Program model."""
        attrs = data.get("attributes", {})
        program_id = str(data.get("id", ""))
        code = attrs.get("code", "")

        # Extract scope from included target_groups → targets
        scope = self._extract_scope_from_included(data, included)

        return Program(
            id=program_id,
            handle=code,
            name=attrs.get("name", code),
            platform=Platform.BUGCROWD,
            state=ProgramState.OPEN,  # Bugcrowd doesn't expose state the same way
            offers_bounties=True,     # Filtered in query if needed
            scope=scope,
            url=f"https://bugcrowd.com/{code}",
            raw_data=data,
        )

    def _extract_scope_from_included(self, program: dict, included: dict) -> list[ScopeEntry]:
        """Extract scope entries from JSON:API included relationships."""
        entries = []

        # Resolve: program → current_brief → target_groups → targets
        briefs = self._resolve_relationship(program, "current_brief", included)
        for brief in briefs:
            groups = self._resolve_relationship(brief, "target_groups", included)
            for group in groups:
                group_attrs = group.get("attributes", {})
                is_in_scope = group_attrs.get("in_scope", True)

                targets = self._resolve_relationship(group, "targets", included)
                for target in targets:
                    try:
                        entry = self._normalize_target(target, is_in_scope=is_in_scope)
                        entries.append(entry)
                    except Exception as e:
                        logger.warning(f"Failed to parse Bugcrowd target: {e}")

        return entries

    def _normalize_target(self, data: dict, is_in_scope: bool = True) -> ScopeEntry:
        """Convert Bugcrowd target to our ScopeEntry model."""
        attrs = data.get("attributes", {})

        name = attrs.get("name", "") or attrs.get("uri", "")
        category = attrs.get("category", "other").lower()

        asset_type = BC_ASSET_TYPE_MAP.get(category, AssetType.OTHER)

        # Detect domain/wildcard/CIDR from the target name
        asset_type = self._infer_asset_type(name, asset_type)

        return ScopeEntry(
            asset_identifier=name,
            asset_type=asset_type,
            scope_status=ScopeStatus.IN_SCOPE if is_in_scope else ScopeStatus.OUT_OF_SCOPE,
            instruction="",
            eligible_for_bounty=is_in_scope,
        )

    @staticmethod
    def _infer_asset_type(identifier: str, default: AssetType) -> AssetType:
        """
        Infer the asset type from the identifier string.

        Bugcrowd's category field is less precise than HackerOne's,
        so we apply heuristics to classify.
        """
        import re

        cleaned = identifier.strip().lower()
        cleaned = re.sub(r"^https?://", "", cleaned)

        # Wildcard domain
        if cleaned.startswith("*."):
            return AssetType.WILDCARD

        # CIDR notation
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", cleaned):
            return AssetType.CIDR

        # Single IP
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cleaned):
            return AssetType.IP_ADDRESS

        # URL with path
        if "/" in cleaned and "." in cleaned:
            return AssetType.URL

        # Domain
        if "." in cleaned and not "/" in cleaned:
            return AssetType.DOMAIN

        return default
