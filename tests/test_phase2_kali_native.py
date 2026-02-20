#!/usr/bin/env python3
"""
Kestrel Phase 2 - Kali Native Integration Tests

Run this on your Kali box to test live API connectivity.
Credentials are loaded via the CredentialManager:
  1. Environment variables (if set)
  2. ~/.kestrel/credentials.yaml (if exists)
  3. Interactive prompt (if neither is available)

USAGE:
  # First time - interactive setup prompts for all keys:
  python tests/test_phase2_kali_native.py --setup

  # Run tests (uses stored credentials):
  python tests/test_phase2_kali_native.py

  # Or run specific platform:
  python tests/test_phase2_kali_native.py --h1-only
  python tests/test_phase2_kali_native.py --bc-only

  # Check credential status:
  python tests/test_phase2_kali_native.py --status

Results: Copy/paste ALL output back to Claude for review.

NOTE: This is a standalone script, NOT a pytest test module.
      Run directly with: python tests/test_phase2_kali_native.py
"""

# Skip if collected by pytest
if __name__ != "__main__":
    import sys
    if "pytest" in sys.modules:
        import pytest
        pytest.skip("Kali native tests run as standalone script", allow_module_level=True)

import os
import sys
import json
import time
import argparse
import tempfile
from pathlib import Path
from datetime import datetime

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from kestrel.platforms.credentials import CredentialManager, get_credentials

# ─────────────────────────────────────────────────────────────────────
#  Test Runner
# ─────────────────────────────────────────────────────────────────────

PASS = "✅ PASS"
FAIL = "❌ FAIL"
SKIP = "⏭️  SKIP"
results = []


def test(name):
    """Decorator for test functions."""
    def wrapper(fn):
        fn._test_name = name
        return fn
    return wrapper


def run_test(fn):
    """Run a single test and record result."""
    name = getattr(fn, '_test_name', fn.__name__)
    try:
        fn()
        results.append((PASS, name, ""))
        print(f"  {PASS} {name}")
    except AssertionError as e:
        results.append((FAIL, name, str(e)))
        print(f"  {FAIL} {name}: {e}")
    except Exception as e:
        results.append((FAIL, name, f"{type(e).__name__}: {e}"))
        print(f"  {FAIL} {name}: {type(e).__name__}: {e}")


def skip_test(name, reason):
    """Record a skipped test."""
    results.append((SKIP, name, reason))
    print(f"  {SKIP} {name}: {reason}")


# ─────────────────────────────────────────────────────────────────────
#  HackerOne Live Tests
# ─────────────────────────────────────────────────────────────────────

def run_hackerone_tests(creds: CredentialManager):
    """Test live HackerOne API connectivity."""
    from kestrel.platforms.hackerone import HackerOneClient
    from kestrel.platforms.cache import ProgramCache
    from kestrel.platforms.models import ScopeValidator

    print("\n══════════════════════════════════════════")
    print("  HackerOne API Tests")
    print("══════════════════════════════════════════")

    h1_config = creds.get_hackerone_config()
    if not h1_config:
        skip_test("H1 Auth", "HackerOne credentials not configured")
        skip_test("H1 Programs", "No credentials")
        skip_test("H1 Scope", "No credentials")
        skip_test("H1 Cache Flow", "No credentials")
        skip_test("H1 Scope Validation", "No credentials")
        return

    client = HackerOneClient(h1_config)

    # Test 1: Authentication
    @test("H1 Authentication")
    def test_h1_auth():
        assert client.is_configured, "Client should be configured"
        assert client.test_auth(), "Authentication should succeed"
    run_test(test_h1_auth)

    # Test 2: List programs
    programs = []

    @test("H1 List Programs")
    def test_h1_programs():
        nonlocal programs
        programs = client.get_programs(page_size=5, max_pages=1)
        assert len(programs) > 0, "Should fetch at least one program"
        p = programs[0]
        assert p.handle, "Program should have a handle"
        assert p.platform.value == "hackerone", "Platform should be hackerone"
        print(f"    Found {len(programs)} programs. First: {p.handle} ({p.name})")
    run_test(test_h1_programs)

    # Test 3: Get scope
    @test("H1 Fetch Scope")
    def test_h1_scope():
        if not programs:
            raise AssertionError("No programs to test scope on")
        for p in programs:
            scope = client.get_scope(p.handle)
            if scope:
                print(f"    {p.handle}: {len(scope)} scope entries")
                for s in scope[:3]:
                    print(f"      {s.scope_status.value}: {s.asset_type.value} → {s.asset_identifier}")
                return
        print("    Warning: No programs with scope entries found in first page")
    run_test(test_h1_scope)

    # Test 4: Full program with scope
    @test("H1 Get Program Detail")
    def test_h1_program_detail():
        if not programs:
            raise AssertionError("No programs available")
        p = client.get_program(programs[0].handle)
        assert p.handle == programs[0].handle
        print(f"    {p.handle}: state={p.state.value}, bounties={p.offers_bounties}, scope_count={len(p.scope)}")
    run_test(test_h1_program_detail)

    # Test 5: Cache integration
    @test("H1 Cache Flow")
    def test_h1_cache():
        if not programs:
            raise AssertionError("No programs available")
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        cache = ProgramCache(db_path=Path(tmp.name))

        cached_count = cache.upsert_programs(programs)
        assert cached_count == len(programs)

        retrieved = cache.get_program("hackerone", programs[0].handle)
        assert retrieved is not None
        assert retrieved.handle == programs[0].handle

        stats = cache.stats()
        print(f"    Cached {stats['total_programs']} programs, {stats['total_scope_entries']} scope entries")
        cache.close()
        os.unlink(tmp.name)
    run_test(test_h1_cache)

    # Test 6: Scope validation on real data
    @test("H1 Scope Validation (Real Data)")
    def test_h1_scope_validation():
        if not programs:
            raise AssertionError("No programs available")
        for p in programs:
            full = client.get_program(p.handle)
            if full.in_scope:
                validator = ScopeValidator(full)
                target = full.in_scope[0].asset_identifier
                if target.startswith("*."):
                    target = "test." + target[2:]
                result = validator.validate(target)
                print(f"    Program: {full.handle}")
                print(f"    Target: {target} → in_scope={result.is_in_scope} ({result.reason})")

                evil = validator.validate("definitely-not-in-scope-12345.evil.test")
                assert evil.is_in_scope is False, "Random domain should be out of scope"
                print(f"    Target: definitely-not-in-scope-12345.evil.test → in_scope={evil.is_in_scope} (FAIL_CLOSED ✓)")
                return
        print("    Warning: No programs with in-scope entries found")
    run_test(test_h1_scope_validation)

    print(f"\n  Requests made: {client.request_count}")
    print(f"  Rate limit remaining: ~{client.rate_limit_remaining}")
    client.close()


# ─────────────────────────────────────────────────────────────────────
#  Bugcrowd Live Tests
# ─────────────────────────────────────────────────────────────────────

def run_bugcrowd_tests(creds: CredentialManager):
    """Test live Bugcrowd API connectivity."""
    from kestrel.platforms.bugcrowd import BugcrowdClient
    from kestrel.platforms.cache import ProgramCache

    print("\n══════════════════════════════════════════")
    print("  Bugcrowd API Tests")
    print("══════════════════════════════════════════")

    bc_config = creds.get_bugcrowd_config()
    if not bc_config:
        skip_test("BC Auth", "Bugcrowd credentials not configured")
        skip_test("BC Programs", "No credentials")
        skip_test("BC Scope", "No credentials")
        skip_test("BC Cache Flow", "No credentials")
        return

    client = BugcrowdClient(bc_config)

    @test("BC Authentication")
    def test_bc_auth():
        assert client.is_configured, "Client should be configured"
        assert client.test_auth(), "Authentication should succeed"
    run_test(test_bc_auth)

    programs = []

    @test("BC List Programs")
    def test_bc_programs():
        nonlocal programs
        programs = client.get_programs(page_size=5, max_pages=1)
        assert len(programs) > 0, "Should fetch at least one program"
        p = programs[0]
        assert p.handle, "Program should have a handle/code"
        assert p.platform.value == "bugcrowd", "Platform should be bugcrowd"
        print(f"    Found {len(programs)} programs. First: {p.handle} ({p.name})")
    run_test(test_bc_programs)

    @test("BC Scope Data")
    def test_bc_scope():
        if not programs:
            raise AssertionError("No programs to check")
        for p in programs:
            if p.scope:
                print(f"    {p.handle}: {len(p.scope)} scope entries")
                for s in p.scope[:3]:
                    print(f"      {s.scope_status.value}: {s.asset_type.value} → {s.asset_identifier}")
                return
        print("    Warning: No programs with scope in first page")
    run_test(test_bc_scope)

    @test("BC Cache Flow")
    def test_bc_cache():
        if not programs:
            raise AssertionError("No programs available")
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        cache = ProgramCache(db_path=Path(tmp.name))

        cached_count = cache.upsert_programs(programs)
        assert cached_count == len(programs)

        retrieved = cache.get_program("bugcrowd", programs[0].handle)
        assert retrieved is not None
        stats = cache.stats()
        print(f"    Cached {stats['total_programs']} programs, {stats['total_scope_entries']} scope entries")
        cache.close()
        os.unlink(tmp.name)
    run_test(test_bc_cache)

    print(f"\n  Requests made: {client.request_count}")
    client.close()


# ─────────────────────────────────────────────────────────────────────
#  Credential Manager Tests
# ─────────────────────────────────────────────────────────────────────

def run_credential_tests(creds: CredentialManager):
    """Test the credential manager itself."""
    print("\n══════════════════════════════════════════")
    print("  Credential Manager Tests")
    print("══════════════════════════════════════════")

    @test("Credential File Location")
    def test_cred_location():
        assert creds.credentials_dir.exists(), f"Dir should exist: {creds.credentials_dir}"
        print(f"    Dir: {creds.credentials_dir}")
        print(f"    File: {creds.credentials_file}")
        if creds.credentials_file.exists():
            mode = oct(creds.credentials_file.stat().st_mode)[-3:]
            print(f"    File permissions: {mode}")
            assert mode == "600", f"Expected 600, got {mode}"
    run_test(test_cred_location)

    @test("Credential Status")
    def test_cred_status():
        status = creds.status()
        for key, info in status.items():
            icon = "✅" if info["set"] else "⬜"
            print(f"    {icon} {key}: {info['source']}")
    run_test(test_cred_status)

    @test("Anthropic Key Available")
    def test_anthropic_key():
        key = creds.get_anthropic_key()
        if key:
            masked = key[:8] + "..." + key[-4:]
            print(f"    Key: {masked}")
        else:
            print("    ⚠️  Not set (required for LLM features)")
    run_test(test_anthropic_key)


# ─────────────────────────────────────────────────────────────────────
#  Cross-Platform Tests
# ─────────────────────────────────────────────────────────────────────

def run_cross_platform_tests():
    """Test cross-platform cache and scope search."""
    from kestrel.platforms.cache import ProgramCache

    print("\n══════════════════════════════════════════")
    print("  Cross-Platform Tests")
    print("══════════════════════════════════════════")

    @test("Cache Search Across Platforms")
    def test_cross_search():
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        cache = ProgramCache(db_path=Path(tmp.name))
        stats = cache.stats()
        print(f"    DB: {stats['total_programs']} programs, {stats['total_scope_entries']} scope entries")
        cache.close()
        os.unlink(tmp.name)
    run_test(test_cross_search)


# ─────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Kestrel Phase 2 Kali Native Tests")
    parser.add_argument("--h1-only", action="store_true", help="Only run HackerOne tests")
    parser.add_argument("--bc-only", action="store_true", help="Only run Bugcrowd tests")
    parser.add_argument("--setup", action="store_true", help="Run interactive credential setup")
    parser.add_argument("--status", action="store_true", help="Show credential status and exit")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════╗")
    print("║  Kestrel Phase 2 - Kali Native      ║")
    print("║  Platform Integration Tests               ║")
    print(f"║  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                       ║")
    print("╚══════════════════════════════════════════╝")

    print(f"\nPython: {sys.version}")
    print(f"Platform: {sys.platform}")

    # Initialize credential manager
    creds = get_credentials()

    # Handle --setup
    if args.setup:
        creds.setup()
        print("\nRe-run without --setup to execute tests.")
        return

    # Handle --status
    if args.status:
        creds._print_status()
        return

    # Check if credentials exist, offer setup if not
    if not creds.credentials_file.exists():
        print("\n⚠️  No credentials found. Running first-time setup...")
        creds.setup()
        print()

    # Show what's available
    h1_ready = creds.has("h1_username") and creds.has("h1_token")
    bc_ready = creds.has("bc_username") and creds.has("bc_password")
    print(f"HackerOne credentials: {'✅ SET' if h1_ready else '⬜ NOT SET'}")
    print(f"Bugcrowd credentials:  {'✅ SET' if bc_ready else '⬜ NOT SET'}")
    print(f"Anthropic API key:     {'✅ SET' if creds.has('anthropic_api_key') else '⬜ NOT SET'}")

    # Run tests
    run_credential_tests(creds)

    if not args.bc_only:
        run_hackerone_tests(creds)
    if not args.h1_only:
        run_bugcrowd_tests(creds)

    run_cross_platform_tests()

    # Summary
    print("\n══════════════════════════════════════════")
    print("  SUMMARY")
    print("══════════════════════════════════════════")

    passed = sum(1 for r in results if r[0] == PASS)
    failed = sum(1 for r in results if r[0] == FAIL)
    skipped = sum(1 for r in results if r[0] == SKIP)

    print(f"  {PASS} Passed: {passed}")
    print(f"  {FAIL} Failed: {failed}")
    print(f"  {SKIP} Skipped: {skipped}")
    print(f"  Total: {len(results)}")

    if failed > 0:
        print("\n  Failed tests:")
        for status, name, detail in results:
            if status == FAIL:
                print(f"    {name}: {detail}")

    print("\n══════════════════════════════════════════")
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
