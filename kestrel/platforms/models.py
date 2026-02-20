"""
Kestrel Platform Models

Data models for bug bounty programs, scope definitions, and targets.
These are platform-agnostic representations that normalize data from
HackerOne, Bugcrowd, and any future platform integrations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any
import re
import fnmatch
import ipaddress


class Platform(Enum):
    """Supported bug bounty platforms."""
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    MANUAL = "manual"  # Manually added programs


class ProgramState(Enum):
    """Program lifecycle states."""
    OPEN = "open"              # Accepting submissions
    PAUSED = "paused"          # Temporarily not accepting
    CLOSED = "closed"          # No longer active
    UNKNOWN = "unknown"


class AssetType(Enum):
    """Types of in-scope assets."""
    DOMAIN = "domain"          # *.example.com, example.com
    URL = "url"                # https://example.com/app
    IP_ADDRESS = "ip_address"  # Single IP
    CIDR = "cidr"              # IP range: 10.0.0.0/24
    WILDCARD = "wildcard"      # *.example.com
    MOBILE_APP = "mobile_app"  # iOS/Android app
    API = "api"                # API endpoint
    SOURCE_CODE = "source_code"  # GitHub repo, etc.
    HARDWARE = "hardware"
    EXECUTABLE = "executable"
    OTHER = "other"


class ScopeStatus(Enum):
    """Whether an asset is in or out of scope."""
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass
class ScopeEntry:
    """
    A single scope entry defining what can/cannot be tested.

    This is the atomic unit of scope - one line item from a
    program's scope table.
    """
    asset_identifier: str       # The actual target: "*.example.com", "10.0.0.0/24"
    asset_type: AssetType
    scope_status: ScopeStatus
    instruction: str = ""       # Additional notes from the program
    eligible_for_bounty: bool = True
    max_severity: str = ""      # "critical", "high", etc.

    # Normalized matching fields (computed)
    _pattern: str = field(default="", init=False, repr=False)

    def __post_init__(self):
        """Compute normalized pattern for matching."""
        self._pattern = self._normalize_pattern(self.asset_identifier)

    @staticmethod
    def _normalize_pattern(identifier: str) -> str:
        """Normalize an asset identifier for matching."""
        # Strip protocol and trailing slashes
        pattern = identifier.strip().lower()
        pattern = re.sub(r"^https?://", "", pattern)
        pattern = pattern.rstrip("/")
        return pattern

    def matches(self, target: str) -> bool:
        """
        Check if a target matches this scope entry.

        Args:
            target: The target to check (domain, IP, URL)

        Returns:
            True if the target matches this entry
        """
        normalized = self._normalize_pattern(target)

        if self.asset_type == AssetType.CIDR:
            return self._matches_cidr(normalized)
        elif self.asset_type == AssetType.IP_ADDRESS:
            return self._matches_ip(normalized)
        elif self.asset_type in (AssetType.DOMAIN, AssetType.WILDCARD):
            return self._matches_domain(normalized)
        elif self.asset_type == AssetType.URL:
            return self._matches_url(normalized)
        else:
            # Exact match for other types
            return normalized == self._pattern

    def _matches_domain(self, target: str) -> bool:
        """Match domain with wildcard support."""
        # Strip port if present
        target_host = target.split("/")[0].split(":")[0]
        pattern_host = self._pattern.split("/")[0].split(":")[0]

        # Exact match
        if target_host == pattern_host:
            return True

        # Wildcard: *.example.com matches sub.example.com
        if pattern_host.startswith("*."):
            base = pattern_host[2:]  # example.com
            if target_host == base:
                return True
            if target_host.endswith("." + base):
                return True

        return False

    def _matches_url(self, target: str) -> bool:
        """Match URL prefix."""
        return target.startswith(self._pattern) or self._pattern.startswith(target)

    def _matches_ip(self, target: str) -> bool:
        """Match single IP address."""
        try:
            return ipaddress.ip_address(target) == ipaddress.ip_address(self._pattern)
        except ValueError:
            return False

    def _matches_cidr(self, target: str) -> bool:
        """Match IP against CIDR range."""
        try:
            network = ipaddress.ip_network(self._pattern, strict=False)
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False

    def to_dict(self) -> dict:
        return {
            "asset_identifier": self.asset_identifier,
            "asset_type": self.asset_type.value,
            "scope_status": self.scope_status.value,
            "instruction": self.instruction,
            "eligible_for_bounty": self.eligible_for_bounty,
            "max_severity": self.max_severity,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScopeEntry":
        return cls(
            asset_identifier=data["asset_identifier"],
            asset_type=AssetType(data["asset_type"]),
            scope_status=ScopeStatus(data["scope_status"]),
            instruction=data.get("instruction", ""),
            eligible_for_bounty=data.get("eligible_for_bounty", True),
            max_severity=data.get("max_severity", ""),
        )


@dataclass
class Program:
    """
    A bug bounty program from any platform.

    This is the core data model that normalizes program data
    from HackerOne, Bugcrowd, and manual entries into a single
    format used throughout Kestrel.
    """
    # Identity
    id: str                     # Platform-specific ID
    handle: str                 # Program handle/slug
    name: str                   # Display name
    platform: Platform

    # State
    state: ProgramState = ProgramState.UNKNOWN
    offers_bounties: bool = False
    managed: bool = False       # Platform-managed triage

    # Scope
    scope: list[ScopeEntry] = field(default_factory=list)

    # Metadata
    url: str = ""               # Program page URL
    policy: str = ""            # Disclosure policy text
    response_efficiency: float = 0.0  # Percentage
    min_bounty: float = 0.0
    max_bounty: float = 0.0
    currency: str = "usd"

    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_synced: Optional[datetime] = None

    # Raw platform data (for debugging)
    raw_data: dict = field(default_factory=dict, repr=False)

    @property
    def in_scope(self) -> list[ScopeEntry]:
        """Get only in-scope entries."""
        return [s for s in self.scope if s.scope_status == ScopeStatus.IN_SCOPE]

    @property
    def out_of_scope(self) -> list[ScopeEntry]:
        """Get only out-of-scope entries."""
        return [s for s in self.scope if s.scope_status == ScopeStatus.OUT_OF_SCOPE]

    @property
    def domains(self) -> list[str]:
        """Get all in-scope domain identifiers."""
        return [
            s.asset_identifier
            for s in self.in_scope
            if s.asset_type in (AssetType.DOMAIN, AssetType.WILDCARD, AssetType.URL)
        ]

    @property
    def ip_ranges(self) -> list[str]:
        """Get all in-scope IP/CIDR identifiers."""
        return [
            s.asset_identifier
            for s in self.in_scope
            if s.asset_type in (AssetType.IP_ADDRESS, AssetType.CIDR)
        ]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "handle": self.handle,
            "name": self.name,
            "platform": self.platform.value,
            "state": self.state.value,
            "offers_bounties": self.offers_bounties,
            "managed": self.managed,
            "scope": [s.to_dict() for s in self.scope],
            "url": self.url,
            "policy": self.policy,
            "response_efficiency": self.response_efficiency,
            "min_bounty": self.min_bounty,
            "max_bounty": self.max_bounty,
            "currency": self.currency,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_synced": self.last_synced.isoformat() if self.last_synced else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Program":
        scope = [ScopeEntry.from_dict(s) for s in data.get("scope", [])]
        return cls(
            id=data["id"],
            handle=data["handle"],
            name=data["name"],
            platform=Platform(data["platform"]),
            state=ProgramState(data.get("state", "unknown")),
            offers_bounties=data.get("offers_bounties", False),
            managed=data.get("managed", False),
            scope=scope,
            url=data.get("url", ""),
            policy=data.get("policy", ""),
            response_efficiency=data.get("response_efficiency", 0.0),
            min_bounty=data.get("min_bounty", 0.0),
            max_bounty=data.get("max_bounty", 0.0),
            currency=data.get("currency", "usd"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            last_synced=datetime.fromisoformat(data["last_synced"]) if data.get("last_synced") else None,
        )


# ─────────────────────────────────────────────────────────────────────
#  Scope Validator
# ─────────────────────────────────────────────────────────────────────

@dataclass
class ScopeValidationResult:
    """Result of a scope validation check."""
    target: str
    is_in_scope: bool
    matched_entry: Optional[ScopeEntry] = None
    reason: str = ""
    checked_at: Optional[datetime] = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "is_in_scope": self.is_in_scope,
            "reason": self.reason,
            "matched_asset": self.matched_entry.asset_identifier if self.matched_entry else None,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


class ScopeValidator:
    """
    Validates targets against program scope.

    This is a CRITICAL SAFETY COMPONENT. It enforces the fundamental
    rule that Kestrel only operates against authorized targets.

    Design principles:
      - Fail CLOSED: if uncertain, target is OUT of scope
      - Out-of-scope rules OVERRIDE in-scope rules
      - Every validation is logged with reason
      - No target passes without explicit in-scope match
    """

    def __init__(self, program: Program):
        self.program = program
        self._validation_log: list[ScopeValidationResult] = []

    @property
    def validation_log(self) -> list[ScopeValidationResult]:
        """Full log of all validation checks."""
        return list(self._validation_log)

    def validate(self, target: str) -> ScopeValidationResult:
        """
        Check if a target is in scope for this program.

        SAFETY: Out-of-scope entries are checked FIRST and override
        any in-scope matches. This ensures explicit exclusions are
        always respected.

        Args:
            target: The target to validate (domain, IP, URL)

        Returns:
            ScopeValidationResult with determination and reason
        """
        # === SAFETY CHECK 1: No scope defined = fail closed ===
        if not self.program.scope:
            result = ScopeValidationResult(
                target=target,
                is_in_scope=False,
                reason="FAIL_CLOSED: No scope entries defined for program",
            )
            self._validation_log.append(result)
            return result

        # === SAFETY CHECK 2: Out-of-scope entries checked FIRST ===
        for entry in self.program.out_of_scope:
            if entry.matches(target):
                result = ScopeValidationResult(
                    target=target,
                    is_in_scope=False,
                    matched_entry=entry,
                    reason=f"EXCLUDED: Matches out-of-scope entry '{entry.asset_identifier}'",
                )
                self._validation_log.append(result)
                return result

        # === CHECK 3: Must match an in-scope entry ===
        for entry in self.program.in_scope:
            if entry.matches(target):
                result = ScopeValidationResult(
                    target=target,
                    is_in_scope=True,
                    matched_entry=entry,
                    reason=f"IN_SCOPE: Matches '{entry.asset_identifier}'",
                )
                self._validation_log.append(result)
                return result

        # === SAFETY CHECK 4: No match = fail closed ===
        result = ScopeValidationResult(
            target=target,
            is_in_scope=False,
            reason="FAIL_CLOSED: No matching in-scope entry found",
        )
        self._validation_log.append(result)
        return result

    def validate_batch(self, targets: list[str]) -> list[ScopeValidationResult]:
        """Validate multiple targets at once."""
        return [self.validate(t) for t in targets]

    def get_in_scope_targets(self, targets: list[str]) -> list[str]:
        """Filter a list of targets to only in-scope ones."""
        results = self.validate_batch(targets)
        return [r.target for r in results if r.is_in_scope]

    def clear_log(self):
        """Clear the validation log."""
        self._validation_log.clear()
