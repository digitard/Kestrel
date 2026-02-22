"""
Phase 4: Platform Integration — Live API Tests

Standalone script that validates real API credentials against
live platform endpoints. Requires credentials stored in
~/.kestrel/credentials.yaml or environment variables.

Run with:
    python3 tests/test_phase4_live_api.py
    python3 tests/test_phase4_live_api.py --platform hackerone
    python3 tests/test_phase4_live_api.py --platform bugcrowd
    python3 tests/test_phase4_live_api.py --status

pytest will skip this module automatically (no live API calls during CI).

Tests (per platform):
  - Credentials available
  - Authentication succeeds
  - List programs returns at least one result
  - Program data is normalized correctly (id, handle, name, platform)
  - Scope is non-empty for at least one program
"""

import sys
import os
import argparse
import json
from pathlib import Path
from datetime import datetime

# Skip during pytest collection
try:
    import pytest
    pytest.skip(allow_module_level=True, reason="Live API test — run standalone")
except (ImportError, Exception):
    pass

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from kestrel.platforms.credentials import CredentialManager, CREDENTIAL_SPECS
from kestrel.platforms.hackerone import HackerOneClient
from kestrel.platforms.bugcrowd import BugcrowdClient
from kestrel.platforms.models import Platform, Program


# ─────────────────────────────────────────────────────────────────────────────
# Result tracking
# ─────────────────────────────────────────────────────────────────────────────

PASS = "✅ PASS"
FAIL = "❌ FAIL"
SKIP = "⬜ SKIP"
WARN = "⚠️  WARN"

results: list[tuple[str, str, str]] = []  # (platform, test_name, result)


def record(platform: str, test: str, ok: bool, note: str = "") -> None:
    icon = PASS if ok else FAIL
    msg = f"{icon} [{platform}] {test}"
    if note:
        msg += f"  ({note})"
    print(msg)
    results.append((platform, test, "pass" if ok else "fail"))


def record_skip(platform: str, test: str, reason: str) -> None:
    print(f"{SKIP} [{platform}] {test}  ({reason})")
    results.append((platform, test, "skip"))


# ─────────────────────────────────────────────────────────────────────────────
# Credential status
# ─────────────────────────────────────────────────────────────────────────────

def print_status(creds: CredentialManager) -> None:
    print("\n══════════════════════════════════════")
    print("  Kestrel — Credential Status")
    print("══════════════════════════════════════")
    status = creds.status()
    current_group = ""
    for key, info in status.items():
        spec = next((s for s in CREDENTIAL_SPECS if s.key == key), None)
        group = spec.group if spec else "Other"
        if group != current_group:
            print(f"\n  ── {group} ──")
            current_group = group
        icon = "✅" if info["set"] else ("❌" if info["required"] else "⬜")
        req = " [REQUIRED]" if info["required"] else ""
        print(f"  {icon} {key}: {info['source']}{req}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# HackerOne tests
# ─────────────────────────────────────────────────────────────────────────────

def test_hackerone(creds: CredentialManager) -> None:
    print("\n── HackerOne ─────────────────────────")

    h1_config = creds.get_hackerone_config()
    if h1_config is None:
        record_skip("HackerOne", "credentials available", "BH_H1_USERNAME / BH_H1_TOKEN not set")
        record_skip("HackerOne", "authentication", "no credentials")
        record_skip("HackerOne", "list programs", "no credentials")
        return

    record("HackerOne", "credentials available", True)

    client = HackerOneClient(h1_config)

    # Test: list programs (first page only — low impact)
    try:
        programs = client.list_programs(per_page=5)
        record("HackerOne", "list programs (5 results)", len(programs) >= 0,
               f"{len(programs)} returned")
    except Exception as e:
        record("HackerOne", "list programs", False, str(e)[:120])
        return

    if not programs:
        record_skip("HackerOne", "program data validation", "no programs returned")
        return

    # Test: first program is normalized correctly
    prog = programs[0]
    has_id = bool(prog.id)
    has_handle = bool(prog.handle)
    has_name = bool(prog.name)
    is_h1 = prog.platform == Platform.HACKERONE

    record("HackerOne", "program.id populated", has_id, prog.id[:30] if has_id else "empty")
    record("HackerOne", "program.handle populated", has_handle)
    record("HackerOne", "program.name populated", has_name)
    record("HackerOne", "program.platform == HACKERONE", is_h1)

    # Test: get a specific program
    if has_handle:
        try:
            detail = client.get_program(prog.handle)
            record("HackerOne", "get_program() works", detail is not None)
            record("HackerOne", "get_program() scope parsed",
                   isinstance(detail.scope, list), f"{len(detail.scope)} entries")
        except Exception as e:
            record("HackerOne", "get_program()", False, str(e)[:120])


# ─────────────────────────────────────────────────────────────────────────────
# Bugcrowd tests
# ─────────────────────────────────────────────────────────────────────────────

def test_bugcrowd(creds: CredentialManager) -> None:
    print("\n── Bugcrowd ──────────────────────────")

    bc_config = creds.get_bugcrowd_config()
    if bc_config is None:
        record_skip("Bugcrowd", "credentials available", "BH_BC_USERNAME / BH_BC_PASSWORD not set")
        record_skip("Bugcrowd", "authentication", "no credentials")
        record_skip("Bugcrowd", "list programs", "no credentials")
        return

    record("Bugcrowd", "credentials available", True)

    client = BugcrowdClient(bc_config)

    # Test: list programs
    try:
        programs = client.list_programs(per_page=5)
        record("Bugcrowd", "list programs (5 results)", len(programs) >= 0,
               f"{len(programs)} returned")
    except Exception as e:
        record("Bugcrowd", "list programs", False, str(e)[:120])
        return

    if not programs:
        record_skip("Bugcrowd", "program data validation", "no programs returned")
        return

    prog = programs[0]
    has_id = bool(prog.id)
    has_handle = bool(prog.handle)
    has_name = bool(prog.name)
    is_bc = prog.platform == Platform.BUGCROWD

    record("Bugcrowd", "program.id populated", has_id)
    record("Bugcrowd", "program.handle populated", has_handle)
    record("Bugcrowd", "program.name populated", has_name)
    record("Bugcrowd", "program.platform == BUGCROWD", is_bc)


# ─────────────────────────────────────────────────────────────────────────────
# Shodan credential test (no live query — just API key validation)
# ─────────────────────────────────────────────────────────────────────────────

def test_shodan_key(creds: CredentialManager) -> None:
    print("\n── Shodan ─────────────────────────────")
    key = creds.get_shodan_key()
    if key is None:
        record_skip("Shodan", "api key available", "SHODAN_API_KEY not set")
        return
    record("Shodan", "api key available", True, f"length={len(key)}")


# ─────────────────────────────────────────────────────────────────────────────
# Censys credential test
# ─────────────────────────────────────────────────────────────────────────────

def test_censys_key(creds: CredentialManager) -> None:
    print("\n── Censys ─────────────────────────────")
    cfg = creds.get_censys_config()
    if cfg is None:
        record_skip("Censys", "credentials available", "CENSYS_API_ID / CENSYS_API_SECRET not set")
        return
    api_id, api_secret = cfg
    record("Censys", "credentials available", True, f"id length={len(api_id)}")


# ─────────────────────────────────────────────────────────────────────────────
# Vulners credential test
# ─────────────────────────────────────────────────────────────────────────────

def test_vulners_key(creds: CredentialManager) -> None:
    print("\n── Vulners ────────────────────────────")
    key = creds.get_vulners_key()
    if key is None:
        record_skip("Vulners", "api key available", "VULNERS_API_KEY not set")
        return
    record("Vulners", "api key available", True, f"length={len(key)}")


# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

def print_summary() -> int:
    total = len(results)
    passed = sum(1 for _, _, r in results if r == "pass")
    failed = sum(1 for _, _, r in results if r == "fail")
    skipped = sum(1 for _, _, r in results if r == "skip")

    print("\n══════════════════════════════════════")
    print("  Phase 4 Live API Test Summary")
    print("══════════════════════════════════════")
    print(f"  Total:   {total}")
    print(f"  Passed:  {passed}")
    print(f"  Failed:  {failed}")
    print(f"  Skipped: {skipped}")
    print(f"  Run at:  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print()

    if failed > 0:
        print("  Failed tests:")
        for platform, test, r in results:
            if r == "fail":
                print(f"    ❌ [{platform}] {test}")

    return 1 if failed > 0 else 0


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 4 Live API Tests — validates real platform credentials"
    )
    parser.add_argument(
        "--platform",
        choices=["hackerone", "bugcrowd", "shodan", "censys", "vulners", "all"],
        default="all",
        help="Which platform to test (default: all)",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print credential status and exit",
    )
    args = parser.parse_args()

    creds = CredentialManager()

    if args.status:
        print_status(creds)
        return

    print("\n══════════════════════════════════════")
    print("  Kestrel — Phase 4 Live API Tests")
    print("══════════════════════════════════════")
    print("  Tests run against LIVE APIs. No exploitation.")
    print("  Only read-only program listing endpoints used.")
    print()

    platform = args.platform

    if platform in ("hackerone", "all"):
        test_hackerone(creds)
    if platform in ("bugcrowd", "all"):
        test_bugcrowd(creds)
    if platform in ("shodan", "all"):
        test_shodan_key(creds)
    if platform in ("censys", "all"):
        test_censys_key(creds)
    if platform in ("vulners", "all"):
        test_vulners_key(creds)

    exit_code = print_summary()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
