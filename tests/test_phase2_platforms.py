"""
Phase 2 Tests - Platform Integration

Tests for:
- Data models (Program, ScopeEntry, ScopeValidator)
- Scope validation (CRITICAL safety tests)
- Platform client construction and configuration
- Rate limiting
- SQLite program cache
- HackerOne/Bugcrowd data normalization
- Serialization round-trips
"""

import pytest
import sys
import tempfile
import time
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))


# ─────────────────────────────────────────────────────────────────────
#  Data Model Tests
# ─────────────────────────────────────────────────────────────────────

class TestScopeEntry:
    """Test ScopeEntry matching logic."""

    def test_exact_domain_match(self):
        from kestrel.platforms.models import ScopeEntry, AssetType, ScopeStatus

        entry = ScopeEntry("example.com", AssetType.DOMAIN, ScopeStatus.IN_SCOPE)
        assert entry.matches("example.com") is True
        assert entry.matches("notexample.com") is False

    def test_domain_match_strips_protocol(self):
        from kestrel.platforms.models import ScopeEntry, AssetType, ScopeStatus

        entry = ScopeEntry("example.com", AssetType.DOMAIN, ScopeStatus.IN_SCOPE)
        assert entry.matches("https://example.com") is True
        assert entry.matches("http://example.com") is True

    def test_wildcard_domain_match(self):
        from kestrel.platforms.models import ScopeEntry, AssetType, ScopeStatus

        entry = ScopeEntry("*.example.com", AssetType.WILDCARD, ScopeStatus.IN_SCOPE)
        assert entry.matches("sub.example.com") is True
        assert entry.matches("deep.sub.example.com") is True
        assert entry.matches("example.com") is True
        assert entry.matches("notexample.com") is False
        assert entry.matches("evil-example.com") is False

    def test_cidr_match(self):
        from kestrel.platforms.models import ScopeEntry, AssetType, ScopeStatus

        entry = ScopeEntry("10.0.0.0/24", AssetType.CIDR, ScopeStatus.IN_SCOPE)
        assert entry.matches("10.0.0.1") is True
        assert entry.matches("10.0.0.254") is True
        assert entry.matches("10.0.1.1") is False

    def test_single_ip_match(self):
        from kestrel.platforms.models import ScopeEntry, AssetType, ScopeStatus

        entry = ScopeEntry("192.168.1.1", AssetType.IP_ADDRESS, ScopeStatus.IN_SCOPE)
        assert entry.matches("192.168.1.1") is True
        assert entry.matches("192.168.1.2") is False

    def test_url_prefix_match(self):
        from kestrel.platforms.models import ScopeEntry, AssetType, ScopeStatus

        entry = ScopeEntry("https://example.com/app", AssetType.URL, ScopeStatus.IN_SCOPE)
        assert entry.matches("https://example.com/app/login") is True
        assert entry.matches("https://example.com/other") is False

    def test_domain_with_port_stripped(self):
        from kestrel.platforms.models import ScopeEntry, AssetType, ScopeStatus

        entry = ScopeEntry("example.com", AssetType.DOMAIN, ScopeStatus.IN_SCOPE)
        assert entry.matches("example.com:8080") is True

    def test_serialization_roundtrip(self):
        from kestrel.platforms.models import ScopeEntry, AssetType, ScopeStatus

        original = ScopeEntry(
            asset_identifier="*.example.com",
            asset_type=AssetType.WILDCARD,
            scope_status=ScopeStatus.IN_SCOPE,
            instruction="Test all subdomains",
            eligible_for_bounty=True,
            max_severity="critical",
        )

        data = original.to_dict()
        restored = ScopeEntry.from_dict(data)

        assert restored.asset_identifier == original.asset_identifier
        assert restored.asset_type == original.asset_type
        assert restored.scope_status == original.scope_status
        assert restored.instruction == original.instruction
        assert restored.eligible_for_bounty == original.eligible_for_bounty


class TestProgram:
    """Test Program data model."""

    def _make_program(self):
        from kestrel.platforms.models import (
            Program, Platform, ProgramState, ScopeEntry, AssetType, ScopeStatus,
        )

        return Program(
            id="123",
            handle="test-program",
            name="Test Program",
            platform=Platform.HACKERONE,
            state=ProgramState.OPEN,
            offers_bounties=True,
            scope=[
                ScopeEntry("*.example.com", AssetType.WILDCARD, ScopeStatus.IN_SCOPE),
                ScopeEntry("https://app.example.com", AssetType.URL, ScopeStatus.IN_SCOPE),
                ScopeEntry("10.0.0.0/24", AssetType.CIDR, ScopeStatus.IN_SCOPE),
                ScopeEntry("staging.example.com", AssetType.DOMAIN, ScopeStatus.OUT_OF_SCOPE),
            ],
            url="https://hackerone.com/test-program",
        )

    def test_in_scope_filter(self):
        program = self._make_program()
        assert len(program.in_scope) == 3

    def test_out_of_scope_filter(self):
        program = self._make_program()
        assert len(program.out_of_scope) == 1
        assert program.out_of_scope[0].asset_identifier == "staging.example.com"

    def test_domains_property(self):
        program = self._make_program()
        domains = program.domains
        assert "*.example.com" in domains
        assert "https://app.example.com" in domains

    def test_ip_ranges_property(self):
        program = self._make_program()
        assert "10.0.0.0/24" in program.ip_ranges

    def test_serialization_roundtrip(self):
        from kestrel.platforms.models import Program
        program = self._make_program()
        data = program.to_dict()
        restored = Program.from_dict(data)

        assert restored.id == program.id
        assert restored.handle == program.handle
        assert restored.platform == program.platform
        assert len(restored.scope) == len(program.scope)


# ─────────────────────────────────────────────────────────────────────
#  Scope Validator Tests (CRITICAL SAFETY)
# ─────────────────────────────────────────────────────────────────────

class TestScopeValidator:
    """
    CRITICAL SAFETY TESTS.

    These validate the core safety gate that prevents Kestrel
    from operating against unauthorized targets.
    """

    def _make_validator(self):
        from kestrel.platforms.models import (
            Program, Platform, ScopeEntry, AssetType, ScopeStatus, ScopeValidator,
        )

        program = Program(
            id="1", handle="test", name="Test", platform=Platform.HACKERONE,
            scope=[
                ScopeEntry("*.example.com", AssetType.WILDCARD, ScopeStatus.IN_SCOPE),
                ScopeEntry("https://app.example.com/api", AssetType.URL, ScopeStatus.IN_SCOPE),
                ScopeEntry("10.0.0.0/24", AssetType.CIDR, ScopeStatus.IN_SCOPE),
                ScopeEntry("192.168.1.1", AssetType.IP_ADDRESS, ScopeStatus.IN_SCOPE),
                # OUT OF SCOPE
                ScopeEntry("staging.example.com", AssetType.DOMAIN, ScopeStatus.OUT_OF_SCOPE),
                ScopeEntry("*.internal.example.com", AssetType.WILDCARD, ScopeStatus.OUT_OF_SCOPE),
            ],
        )
        return ScopeValidator(program)

    def test_in_scope_domain_passes(self):
        """In-scope wildcard domain should pass."""
        v = self._make_validator()
        result = v.validate("sub.example.com")
        assert result.is_in_scope is True

    def test_out_of_scope_domain_blocked(self):
        """Explicitly out-of-scope domain should be blocked."""
        v = self._make_validator()
        result = v.validate("staging.example.com")
        assert result.is_in_scope is False
        assert "EXCLUDED" in result.reason

    def test_out_of_scope_overrides_in_scope(self):
        """Out-of-scope MUST override in-scope (*.internal.example.com vs *.example.com)."""
        v = self._make_validator()
        result = v.validate("secret.internal.example.com")
        assert result.is_in_scope is False
        assert "EXCLUDED" in result.reason

    def test_unknown_target_fails_closed(self):
        """Target not matching any scope entry should fail closed."""
        v = self._make_validator()
        result = v.validate("totally-different.org")
        assert result.is_in_scope is False
        assert "FAIL_CLOSED" in result.reason

    def test_empty_scope_fails_closed(self):
        """Program with no scope entries should fail closed on everything."""
        from kestrel.platforms.models import Program, Platform, ScopeValidator

        program = Program(id="1", handle="empty", name="Empty", platform=Platform.MANUAL, scope=[])
        v = ScopeValidator(program)
        result = v.validate("anything.com")
        assert result.is_in_scope is False
        assert "FAIL_CLOSED" in result.reason

    def test_cidr_in_scope(self):
        """IP in CIDR range should pass."""
        v = self._make_validator()
        result = v.validate("10.0.0.50")
        assert result.is_in_scope is True

    def test_cidr_out_of_range_blocked(self):
        """IP outside CIDR range should fail closed."""
        v = self._make_validator()
        result = v.validate("10.0.1.50")
        assert result.is_in_scope is False

    def test_exact_ip_match(self):
        """Exact IP match should pass."""
        v = self._make_validator()
        result = v.validate("192.168.1.1")
        assert result.is_in_scope is True

    def test_url_in_scope(self):
        """URL matching in-scope prefix should pass."""
        v = self._make_validator()
        result = v.validate("https://app.example.com/api/users")
        assert result.is_in_scope is True

    def test_validation_logging(self):
        """Every validation should be logged."""
        v = self._make_validator()
        v.validate("test1.example.com")
        v.validate("test2.example.com")
        v.validate("evil.org")

        assert len(v.validation_log) == 3

    def test_batch_validation(self):
        """Batch validation should check all targets."""
        v = self._make_validator()
        results = v.validate_batch([
            "sub.example.com",
            "staging.example.com",
            "evil.org",
        ])
        assert len(results) == 3
        assert results[0].is_in_scope is True
        assert results[1].is_in_scope is False
        assert results[2].is_in_scope is False

    def test_get_in_scope_targets(self):
        """Should filter to only in-scope targets."""
        v = self._make_validator()
        targets = ["sub.example.com", "staging.example.com", "10.0.0.1", "evil.org"]
        filtered = v.get_in_scope_targets(targets)

        assert "sub.example.com" in filtered
        assert "10.0.0.1" in filtered
        assert "staging.example.com" not in filtered
        assert "evil.org" not in filtered

    def test_result_serialization(self):
        """Validation results should serialize."""
        v = self._make_validator()
        result = v.validate("sub.example.com")
        data = result.to_dict()

        assert data["target"] == "sub.example.com"
        assert data["is_in_scope"] is True
        assert "matched_asset" in data


# ─────────────────────────────────────────────────────────────────────
#  Rate Limiter Tests
# ─────────────────────────────────────────────────────────────────────

class TestRateLimiter:
    """Test the token bucket rate limiter."""

    def test_allows_requests_under_limit(self):
        from kestrel.platforms.base import RateLimiter

        limiter = RateLimiter(max_requests=10, window_seconds=60)

        for _ in range(10):
            wait = limiter.acquire()
            assert wait == 0.0

    def test_remaining_decrements(self):
        from kestrel.platforms.base import RateLimiter

        limiter = RateLimiter(max_requests=5, window_seconds=60)
        assert limiter.remaining == 5

        limiter.acquire()
        assert limiter.remaining == 4

    def test_reset_clears_state(self):
        from kestrel.platforms.base import RateLimiter

        limiter = RateLimiter(max_requests=5, window_seconds=60)
        limiter.acquire()
        limiter.acquire()
        limiter.reset()
        assert limiter.remaining == 5


# ─────────────────────────────────────────────────────────────────────
#  Platform Client Tests (no real API calls)
# ─────────────────────────────────────────────────────────────────────

class TestHackerOneClient:
    """Test HackerOne client construction and normalization."""

    def test_client_creation(self):
        from kestrel.platforms.hackerone import HackerOneClient
        from kestrel.platforms.base import ClientConfig

        config = ClientConfig(api_key="user", api_secret="token")
        client = HackerOneClient(config)

        assert client.is_configured is True
        assert client.PLATFORM.value == "hackerone"

    def test_unconfigured_client(self):
        from kestrel.platforms.hackerone import HackerOneClient

        client = HackerOneClient()
        assert client.is_configured is False
        assert client.test_auth() is False

    def test_default_base_url(self):
        from kestrel.platforms.hackerone import HackerOneClient

        client = HackerOneClient()
        assert "api.hackerone.com" in client.config.base_url

    def test_normalize_program(self):
        """Test H1 API response normalization."""
        from kestrel.platforms.hackerone import HackerOneClient
        from kestrel.platforms.base import ClientConfig

        client = HackerOneClient(ClientConfig())

        h1_data = {
            "id": "42",
            "type": "program",
            "attributes": {
                "handle": "acme",
                "name": "ACME Corp",
                "state": "public_mode",
                "offers_bounties": True,
                "triage_active": False,
                "currency": "usd",
                "policy": "Test all the things",
            },
            "relationships": {
                "structured_scopes": {"data": []},
            },
        }

        program = client._normalize_program(h1_data)

        assert program.id == "42"
        assert program.handle == "acme"
        assert program.name == "ACME Corp"
        assert program.platform.value == "hackerone"
        assert program.state.value == "open"
        assert program.offers_bounties is True

    def test_normalize_scope_entry(self):
        """Test H1 scope entry normalization."""
        from kestrel.platforms.hackerone import HackerOneClient
        from kestrel.platforms.base import ClientConfig

        client = HackerOneClient(ClientConfig())

        h1_scope = {
            "id": "99",
            "type": "structured-scope",
            "attributes": {
                "asset_identifier": "*.acme.com",
                "asset_type": "WILDCARD",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
                "instruction": "All subdomains",
                "max_severity": "critical",
            },
        }

        entry = client._normalize_scope_entry(h1_scope)

        assert entry.asset_identifier == "*.acme.com"
        assert entry.asset_type.value == "wildcard"
        assert entry.scope_status.value == "in_scope"
        assert entry.eligible_for_bounty is True

    def test_normalize_out_of_scope_entry(self):
        """H1 entries not eligible for submission should be out-of-scope."""
        from kestrel.platforms.hackerone import HackerOneClient
        from kestrel.platforms.base import ClientConfig

        client = HackerOneClient(ClientConfig())

        h1_scope = {
            "attributes": {
                "asset_identifier": "staging.acme.com",
                "asset_type": "DOMAIN",
                "eligible_for_submission": False,
                "eligible_for_bounty": False,
            },
        }

        entry = client._normalize_scope_entry(h1_scope)
        assert entry.scope_status.value == "out_of_scope"


class TestBugcrowdClient:
    """Test Bugcrowd client construction and normalization."""

    def test_client_creation(self):
        from kestrel.platforms.bugcrowd import BugcrowdClient
        from kestrel.platforms.base import ClientConfig

        config = ClientConfig(api_key="user", api_secret="pass")
        client = BugcrowdClient(config)

        assert client.is_configured is True
        assert client.PLATFORM.value == "bugcrowd"

    def test_unconfigured_client(self):
        from kestrel.platforms.bugcrowd import BugcrowdClient

        client = BugcrowdClient()
        assert client.is_configured is False

    def test_default_base_url(self):
        from kestrel.platforms.bugcrowd import BugcrowdClient

        client = BugcrowdClient()
        assert "api.bugcrowd.com" in client.config.base_url

    def test_infer_asset_type_wildcard(self):
        from kestrel.platforms.bugcrowd import BugcrowdClient
        from kestrel.platforms.models import AssetType

        assert BugcrowdClient._infer_asset_type("*.example.com", AssetType.OTHER) == AssetType.WILDCARD

    def test_infer_asset_type_cidr(self):
        from kestrel.platforms.bugcrowd import BugcrowdClient
        from kestrel.platforms.models import AssetType

        assert BugcrowdClient._infer_asset_type("10.0.0.0/24", AssetType.OTHER) == AssetType.CIDR

    def test_infer_asset_type_ip(self):
        from kestrel.platforms.bugcrowd import BugcrowdClient
        from kestrel.platforms.models import AssetType

        assert BugcrowdClient._infer_asset_type("192.168.1.1", AssetType.OTHER) == AssetType.IP_ADDRESS

    def test_infer_asset_type_domain(self):
        from kestrel.platforms.bugcrowd import BugcrowdClient
        from kestrel.platforms.models import AssetType

        assert BugcrowdClient._infer_asset_type("example.com", AssetType.OTHER) == AssetType.DOMAIN

    def test_infer_asset_type_url(self):
        from kestrel.platforms.bugcrowd import BugcrowdClient
        from kestrel.platforms.models import AssetType

        assert BugcrowdClient._infer_asset_type("https://example.com/app", AssetType.OTHER) == AssetType.URL

    def test_normalize_target(self):
        """Test Bugcrowd target normalization."""
        from kestrel.platforms.bugcrowd import BugcrowdClient
        from kestrel.platforms.base import ClientConfig

        client = BugcrowdClient(ClientConfig())

        bc_target = {
            "id": "uuid-123",
            "type": "target",
            "attributes": {
                "name": "*.acme.com",
                "category": "website",
            },
        }

        entry = client._normalize_target(bc_target)
        assert entry.asset_identifier == "*.acme.com"
        assert entry.asset_type.value == "wildcard"
        assert entry.scope_status.value == "in_scope"

    def test_build_included_map(self):
        """Test JSON:API included resource mapping."""
        from kestrel.platforms.bugcrowd import BugcrowdClient

        included = [
            {"type": "target", "id": "1", "attributes": {"name": "a.com"}},
            {"type": "target", "id": "2", "attributes": {"name": "b.com"}},
        ]

        result = BugcrowdClient._build_included_map(included)
        assert "target:1" in result
        assert "target:2" in result


# ─────────────────────────────────────────────────────────────────────
#  SQLite Cache Tests
# ─────────────────────────────────────────────────────────────────────

class TestProgramCache:
    """Test the SQLite program cache."""

    def _make_cache(self):
        from kestrel.platforms.cache import ProgramCache

        # Use temp file for test isolation
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        return ProgramCache(db_path=Path(tmp.name))

    def _make_program(self, handle="test-prog"):
        from kestrel.platforms.models import (
            Program, Platform, ProgramState, ScopeEntry, AssetType, ScopeStatus,
        )

        return Program(
            id="42",
            handle=handle,
            name="Test Program",
            platform=Platform.HACKERONE,
            state=ProgramState.OPEN,
            offers_bounties=True,
            scope=[
                ScopeEntry("*.example.com", AssetType.WILDCARD, ScopeStatus.IN_SCOPE,
                           instruction="All subs", eligible_for_bounty=True),
                ScopeEntry("staging.example.com", AssetType.DOMAIN, ScopeStatus.OUT_OF_SCOPE),
            ],
            url="https://hackerone.com/test-prog",
        )

    def test_upsert_and_get(self):
        cache = self._make_cache()
        program = self._make_program()
        cache.upsert_program(program)

        cached = cache.get_program("hackerone", "test-prog")
        assert cached is not None
        assert cached.handle == "test-prog"
        assert cached.name == "Test Program"
        assert len(cached.scope) == 2
        cache.close()

    def test_scope_preserved(self):
        cache = self._make_cache()
        program = self._make_program()
        cache.upsert_program(program)

        cached = cache.get_program("hackerone", "test-prog")
        in_scope = [s for s in cached.scope if s.scope_status.value == "in_scope"]
        out_scope = [s for s in cached.scope if s.scope_status.value == "out_of_scope"]

        assert len(in_scope) == 1
        assert len(out_scope) == 1
        assert in_scope[0].asset_identifier == "*.example.com"
        cache.close()

    def test_upsert_replaces_scope(self):
        """Re-upserting should replace scope, not append."""
        from kestrel.platforms.models import ScopeEntry, AssetType, ScopeStatus

        cache = self._make_cache()
        program = self._make_program()
        cache.upsert_program(program)

        # Update with different scope
        program.scope = [
            ScopeEntry("new.example.com", AssetType.DOMAIN, ScopeStatus.IN_SCOPE),
        ]
        cache.upsert_program(program)

        cached = cache.get_program("hackerone", "test-prog")
        assert len(cached.scope) == 1
        assert cached.scope[0].asset_identifier == "new.example.com"
        cache.close()

    def test_get_nonexistent(self):
        cache = self._make_cache()
        assert cache.get_program("hackerone", "nope") is None
        cache.close()

    def test_list_programs(self):
        cache = self._make_cache()
        cache.upsert_program(self._make_program("prog-a"))
        cache.upsert_program(self._make_program("prog-b"))

        programs = cache.get_programs()
        assert len(programs) == 2
        cache.close()

    def test_filter_by_platform(self):
        from kestrel.platforms.models import Program, Platform

        cache = self._make_cache()
        cache.upsert_program(self._make_program("h1-prog"))

        bc_prog = Program(
            id="99", handle="bc-prog", name="BC",
            platform=Platform.BUGCROWD,
        )
        cache.upsert_program(bc_prog)

        h1_only = cache.get_programs(platform="hackerone")
        assert len(h1_only) == 1
        assert h1_only[0].handle == "h1-prog"
        cache.close()

    def test_search_programs(self):
        cache = self._make_cache()
        cache.upsert_program(self._make_program("acme-security"))
        cache.upsert_program(self._make_program("other-prog"))

        results = cache.get_programs(search="acme")
        assert len(results) == 1
        assert results[0].handle == "acme-security"
        cache.close()

    def test_search_scope(self):
        cache = self._make_cache()
        cache.upsert_program(self._make_program())

        results = cache.search_scope("example.com")
        assert len(results) >= 1
        assert results[0]["platform"] == "hackerone"
        cache.close()

    def test_delete_program(self):
        cache = self._make_cache()
        cache.upsert_program(self._make_program())

        deleted = cache.delete_program("hackerone", "test-prog")
        assert deleted is True
        assert cache.get_program("hackerone", "test-prog") is None
        cache.close()

    def test_staleness_check(self):
        cache = self._make_cache()
        cache.upsert_program(self._make_program())

        # Just cached = not stale
        assert cache.is_stale("hackerone", "test-prog", max_age_hours=1) is False

        # Non-existent = stale
        assert cache.is_stale("hackerone", "nope") is True
        cache.close()

    def test_stats(self):
        cache = self._make_cache()
        cache.upsert_program(self._make_program())

        stats = cache.stats()
        assert stats["total_programs"] == 1
        assert stats["total_scope_entries"] == 2
        assert "hackerone" in stats["by_platform"]
        cache.close()

    def test_clear(self):
        cache = self._make_cache()
        cache.upsert_program(self._make_program("a"))
        cache.upsert_program(self._make_program("b"))

        cleared = cache.clear()
        assert cleared == 2
        assert cache.get_programs() == []
        cache.close()

    def test_clear_by_platform(self):
        from kestrel.platforms.models import Program, Platform

        cache = self._make_cache()
        cache.upsert_program(self._make_program("h1"))
        cache.upsert_program(Program(
            id="99", handle="bc", name="BC", platform=Platform.BUGCROWD,
        ))

        cache.clear(platform="hackerone")
        remaining = cache.get_programs()
        assert len(remaining) == 1
        assert remaining[0].platform.value == "bugcrowd"
        cache.close()


# ─────────────────────────────────────────────────────────────────────
#  Error Type Tests
# ─────────────────────────────────────────────────────────────────────

class TestErrorTypes:
    """Test platform API error hierarchy."""

    def test_auth_error(self):
        from kestrel.platforms.base import AuthenticationError, PlatformAPIError

        err = AuthenticationError("Bad creds", status_code=401)
        assert isinstance(err, PlatformAPIError)
        assert err.status_code == 401

    def test_rate_limit_error(self):
        from kestrel.platforms.base import RateLimitError

        err = RateLimitError("Too fast", retry_after=30.0, status_code=429)
        assert err.retry_after == 30.0

    def test_not_found_error(self):
        from kestrel.platforms.base import NotFoundError

        err = NotFoundError("Gone", status_code=404)
        assert err.status_code == 404


# ─────────────────────────────────────────────────────────────────────
#  Import / Integration Tests
# ─────────────────────────────────────────────────────────────────────

class TestPackageImports:
    """Test that all Phase 2 components import cleanly."""

    def test_import_models(self):
        from kestrel.platforms.models import (
            Platform, ProgramState, AssetType, ScopeStatus,
            ScopeEntry, Program, ScopeValidator, ScopeValidationResult,
        )

    def test_import_clients(self):
        from kestrel.platforms import HackerOneClient, BugcrowdClient

    def test_import_cache(self):
        from kestrel.platforms import ProgramCache

    def test_import_base(self):
        from kestrel.platforms import (
            ClientConfig, RateLimiter,
            PlatformAPIError, AuthenticationError, RateLimitError, NotFoundError,
        )

    def test_import_from_top_level(self):
        """All Phase 2 exports should be available from platforms package."""
        from kestrel.platforms import (
            Program, ScopeEntry, ScopeValidator,
            HackerOneClient, BugcrowdClient,
            ProgramCache,
        )


class TestEndToEndFlow:
    """Test the complete flow: create program → cache → validate scope."""

    def test_program_cache_validate_flow(self):
        """Simulate: sync program → cache it → validate targets."""
        from kestrel.platforms.models import (
            Program, Platform, ProgramState, ScopeEntry, AssetType,
            ScopeStatus, ScopeValidator,
        )
        from kestrel.platforms.cache import ProgramCache

        # 1. Create program (simulating API response)
        program = Program(
            id="100",
            handle="acme-security",
            name="ACME Security",
            platform=Platform.HACKERONE,
            state=ProgramState.OPEN,
            offers_bounties=True,
            scope=[
                ScopeEntry("*.acme.com", AssetType.WILDCARD, ScopeStatus.IN_SCOPE),
                ScopeEntry("10.10.0.0/16", AssetType.CIDR, ScopeStatus.IN_SCOPE),
                ScopeEntry("admin.acme.com", AssetType.DOMAIN, ScopeStatus.OUT_OF_SCOPE),
            ],
        )

        # 2. Cache it
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        cache = ProgramCache(db_path=Path(tmp.name))
        cache.upsert_program(program)

        # 3. Retrieve from cache
        cached = cache.get_program("hackerone", "acme-security")
        assert cached is not None
        assert len(cached.scope) == 3

        # 4. Validate targets
        validator = ScopeValidator(cached)

        # Should pass
        assert validator.validate("www.acme.com").is_in_scope is True
        assert validator.validate("10.10.5.50").is_in_scope is True

        # Should fail (out-of-scope override)
        assert validator.validate("admin.acme.com").is_in_scope is False

        # Should fail (not in scope at all)
        assert validator.validate("evil.org").is_in_scope is False

        # 5. Verify audit trail
        assert len(validator.validation_log) == 4

        cache.close()


# ─────────────────────────────────────────────────────────────────────
#  Credential Manager Tests
# ─────────────────────────────────────────────────────────────────────

class TestCredentialManager:
    """Test the credential manager (non-interactive, file-based)."""

    def _make_creds(self):
        from kestrel.platforms.credentials import CredentialManager
        tmp = tempfile.mkdtemp()
        return CredentialManager(credentials_dir=Path(tmp))

    def test_create_manager(self):
        creds = self._make_creds()
        assert creds.credentials_dir.exists()

    def test_set_and_get(self):
        creds = self._make_creds()
        creds.set("anthropic_api_key", "sk-test-12345")

        assert creds.get("anthropic_api_key") == "sk-test-12345"
        assert creds.has("anthropic_api_key") is True

    def test_get_missing_returns_none(self):
        creds = self._make_creds()
        assert creds.get("nonexistent_key") is None
        assert creds.has("nonexistent_key") is False

    def test_delete_credential(self):
        creds = self._make_creds()
        creds.set("h1_username", "testuser")
        assert creds.delete("h1_username") is True
        assert creds.get("h1_username") is None

    def test_delete_nonexistent(self):
        creds = self._make_creds()
        assert creds.delete("nope") is False

    def test_env_var_overrides_file(self):
        """Environment variables should take precedence over file."""
        import os
        creds = self._make_creds()
        creds.set("anthropic_api_key", "file-value")

        # Set env var
        old = os.environ.get("ANTHROPIC_API_KEY", "")
        os.environ["ANTHROPIC_API_KEY"] = "env-value"
        try:
            assert creds.get("anthropic_api_key") == "env-value"
        finally:
            if old:
                os.environ["ANTHROPIC_API_KEY"] = old
            else:
                os.environ.pop("ANTHROPIC_API_KEY", None)

    def test_persistence_across_instances(self):
        """Credentials should persist to file."""
        from kestrel.platforms.credentials import CredentialManager
        tmp = tempfile.mkdtemp()

        creds1 = CredentialManager(credentials_dir=Path(tmp))
        creds1.set("h1_token", "my-secret-token")

        # New instance, same dir
        creds2 = CredentialManager(credentials_dir=Path(tmp))
        assert creds2.get("h1_token") == "my-secret-token"

    def test_file_permissions(self):
        """Credentials file should be owner-only (600)."""
        import stat as stat_mod
        creds = self._make_creds()
        creds.set("test_key", "test_val")

        if sys.platform != "win32":
            mode = creds.credentials_file.stat().st_mode
            assert mode & 0o777 == 0o600, f"Expected 600, got {oct(mode & 0o777)}"

    def test_status(self):
        creds = self._make_creds()
        creds.set("anthropic_api_key", "sk-test")

        status = creds.status()
        assert "anthropic_api_key" in status
        assert status["anthropic_api_key"]["set"] is True

    def test_is_ready_with_required(self):
        creds = self._make_creds()
        assert creds.is_ready() is False  # Anthropic key is required

        creds.set("anthropic_api_key", "sk-test")
        assert creds.is_ready() is True

    def test_missing_required(self):
        creds = self._make_creds()
        missing = creds.missing_required()
        assert "anthropic_api_key" in missing

    def test_get_hackerone_config(self):
        creds = self._make_creds()
        assert creds.get_hackerone_config() is None

        creds.set("h1_username", "user")
        creds.set("h1_token", "token")
        config = creds.get_hackerone_config()
        assert config is not None
        assert config.api_key == "user"
        assert config.api_secret == "token"

    def test_get_bugcrowd_config(self):
        creds = self._make_creds()
        assert creds.get_bugcrowd_config() is None

        creds.set("bc_username", "user")
        creds.set("bc_password", "pass")
        config = creds.get_bugcrowd_config()
        assert config is not None
        assert config.api_key == "user"
        assert config.api_secret == "pass"

    def test_get_anthropic_key(self):
        creds = self._make_creds()
        assert creds.get_anthropic_key() is None

        creds.set("anthropic_api_key", "sk-ant-12345")
        assert creds.get_anthropic_key() == "sk-ant-12345"

    def test_global_singleton(self):
        from kestrel.platforms.credentials import get_credentials, reset_credentials
        reset_credentials()
        c1 = get_credentials()
        c2 = get_credentials()
        assert c1 is c2
        reset_credentials()
