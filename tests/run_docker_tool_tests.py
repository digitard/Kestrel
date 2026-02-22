#!/usr/bin/env python3
"""
Kestrel Docker Tool Integration Tests
======================================

Standalone script that:
  1. Builds the kestrel-tools Docker image (if not already built)
  2. Starts the container
  3. Runs each Tier 1 wrapped tool against a safe local target
  4. Pipes output back and verifies parsers can handle it
  5. Prints a clear PASS / FAIL report

Usage:
    python3 tests/run_docker_tool_tests.py [--build] [--tools nmap,nuclei,...] [--target <host>]

    --build     Force rebuild the Docker image before testing
    --tools     Comma-separated list of tools to test (default: all Tier 1 tools)
    --target    Override the default test target (default: scanme.nmap.org)

Requires:
    - Docker installed and running
    - kestrel-tools image (auto-built from docker/Dockerfile if missing)

IMPORTANT: Only run against targets you are authorized to scan.
           Default target is scanme.nmap.org (explicitly permitted for testing).
"""

import sys
import argparse
import textwrap
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ─────────────────────────────────────────────────────────────────────
# Guard: skip when run under pytest
# ─────────────────────────────────────────────────────────────────────

try:
    import pytest
    pytest.skip(
        reason="run_docker_tool_tests.py requires Docker — run directly, not via pytest",
        allow_module_level=True,
    )
except Exception:
    pass


# ─────────────────────────────────────────────────────────────────────
# Colours
# ─────────────────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED   = "\033[91m"
YELLOW = "\033[93m"
CYAN  = "\033[96m"
RESET = "\033[0m"
BOLD  = "\033[1m"


def _ok(msg: str) -> str:
    return f"{GREEN}[PASS]{RESET} {msg}"


def _fail(msg: str) -> str:
    return f"{RED}[FAIL]{RESET} {msg}"


def _info(msg: str) -> str:
    return f"{CYAN}[INFO]{RESET} {msg}"


def _warn(msg: str) -> str:
    return f"{YELLOW}[WARN]{RESET} {msg}"


# ─────────────────────────────────────────────────────────────────────
# Docker bootstrap
# ─────────────────────────────────────────────────────────────────────

def _check_docker() -> bool:
    """Return True if Docker daemon is reachable."""
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _image_exists(tag: str) -> bool:
    import subprocess
    result = subprocess.run(
        ["docker", "image", "inspect", tag],
        capture_output=True,
        timeout=10,
    )
    return result.returncode == 0


def _build_image(force: bool = False) -> bool:
    """Build the kestrel-tools image. Returns True on success."""
    import subprocess

    tag = "kestrel-tools:latest"
    docker_dir = Path(__file__).parent.parent / "docker"

    if not force and _image_exists(tag):
        print(_info(f"Image {tag} already exists — skipping build (use --build to force)"))
        return True

    print(_info(f"Building {tag} from {docker_dir}/Dockerfile …"))
    result = subprocess.run(
        ["docker", "build", "-t", tag, str(docker_dir)],
        timeout=600,
    )
    if result.returncode != 0:
        print(_fail(f"docker build failed (exit {result.returncode})"))
        return False
    print(_ok(f"Image {tag} built successfully"))
    return True


# ─────────────────────────────────────────────────────────────────────
# Test cases
# ─────────────────────────────────────────────────────────────────────

class ToolTestCase:
    """A single tool integration test."""

    def __init__(
        self,
        tool_name: str,
        request_kwargs: dict,
        verify_fn,
        description: str,
    ):
        self.tool_name = tool_name
        self.request_kwargs = request_kwargs
        self.verify_fn = verify_fn
        self.description = description


def _build_test_cases(target: str) -> list[ToolTestCase]:
    """Build test cases for all Tier 1 tools."""
    from kestrel.tools.base import ToolRequest

    cases = [
        ToolTestCase(
            tool_name="nmap",
            request_kwargs=dict(
                tool="nmap",
                target=target,
                options={"scan_type": "quick", "service_detection": False},
            ),
            verify_fn=lambda r: (
                r.success and len(r.hosts) > 0,
                f"Expected hosts > 0, got {len(r.hosts)}"
            ),
            description=f"nmap quick scan of {target}",
        ),
        ToolTestCase(
            tool_name="gobuster",
            request_kwargs=dict(
                tool="gobuster",
                target=f"http://{target}",
                options={"mode": "dir", "wordlist": "small"},
            ),
            verify_fn=lambda r: (
                r.success,
                "Gobuster parse succeeded"
            ),
            description=f"gobuster dir scan of http://{target}",
        ),
        ToolTestCase(
            tool_name="whatweb",
            request_kwargs=dict(
                tool="whatweb",
                target=f"http://{target}",
                options={"aggression": 1},
            ),
            verify_fn=lambda r: (
                r.success,
                "WhatWeb parse succeeded"
            ),
            description=f"whatweb fingerprint of http://{target}",
        ),
        ToolTestCase(
            tool_name="subfinder",
            request_kwargs=dict(
                tool="subfinder",
                target=target if "." in target else "example.com",
                options={},
            ),
            verify_fn=lambda r: (
                r.success,
                "Subfinder parse succeeded"
            ),
            description=f"subfinder passive recon of {target}",
        ),
        ToolTestCase(
            tool_name="httpx",
            request_kwargs=dict(
                tool="httpx",
                target=f"http://{target}",
                options={"status_code": True, "title": True, "tech_detect": False},
            ),
            verify_fn=lambda r: (
                r.success,
                "httpx parse succeeded"
            ),
            description=f"httpx probe of http://{target}",
        ),
    ]
    return cases


# ─────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────

def run_tests(
    target: str,
    tool_filter: list[str] | None,
    build_image: bool,
) -> int:
    """
    Run Docker tool integration tests.

    Returns exit code: 0 = all passed, 1 = failures or setup error.
    """
    print(f"\n{BOLD}Kestrel Docker Tool Integration Tests{RESET}")
    print("=" * 60)
    print(_info(f"Target: {target}"))

    # 1. Docker check
    if not _check_docker():
        print(_fail("Docker daemon not reachable. Is Docker running?"))
        return 1

    # 2. Build image
    if not _build_image(force=build_image):
        return 1

    # 3. Set up UnifiedExecutor in Docker mode
    try:
        from kestrel.core.platform import get_platform, ExecutionMode
        from kestrel.core.executor import UnifiedExecutor
        from kestrel.core.docker_manager import DockerManager

        platform = get_platform()
        print(_info(f"Platform: {platform.summary}"))
        print(_info(f"Execution mode: {platform.execution_mode.value}"))

        executor = UnifiedExecutor(platform_info=platform)
        print(_info(f"Executor mode: {executor.execution_mode}"))
    except Exception as exc:
        print(_fail(f"Failed to initialise executor: {exc}"))
        return 1

    # 4. Get wrappers and parsers
    from kestrel.tools import (
        NmapWrapper, GobusterWrapper, WhatwebWrapper,
        SubfinderWrapper, HttpxWrapper,
    )
    from kestrel.parsers import get_parser
    from kestrel.tools.base import ToolRequest

    wrapper_map = {
        "nmap": NmapWrapper,
        "gobuster": GobusterWrapper,
        "whatweb": WhatwebWrapper,
        "subfinder": SubfinderWrapper,
        "httpx": HttpxWrapper,
    }

    # 5. Run test cases
    test_cases = _build_test_cases(target)
    if tool_filter:
        test_cases = [tc for tc in test_cases if tc.tool_name in tool_filter]

    passed = 0
    failed = 0
    skipped = 0

    for tc in test_cases:
        print(f"\n{BOLD}[{tc.tool_name.upper()}]{RESET} {tc.description}")

        wrapper_cls = wrapper_map.get(tc.tool_name)
        if not wrapper_cls:
            print(_warn(f"  No wrapper for {tc.tool_name} — skipping"))
            skipped += 1
            continue

        # Check tool availability in container
        if not executor.check_tool(tc.tool_name):
            print(_warn(f"  {tc.tool_name} not in container — skipping"))
            skipped += 1
            continue

        wrapper = wrapper_cls(executor=executor)
        request = ToolRequest(**tc.request_kwargs)

        # Build and show command
        cmd = wrapper.build_command(request)
        print(f"  Command: {cmd[:120]}{'…' if len(cmd) > 120 else ''}")

        # Execute
        exec_result = wrapper.execute(request)
        print(f"  Exit code: {exec_result.exit_code}  Duration: {exec_result.duration_seconds:.1f}s")

        if exec_result.stdout:
            preview = exec_result.stdout[:300].replace("\n", " ")
            print(f"  Output preview: {preview}{'…' if len(exec_result.stdout) > 300 else ''}")

        if not exec_result.success:
            print(_fail(f"  Execution failed: {exec_result.error_message or exec_result.stderr[:200]}"))
            failed += 1
            continue

        # Parse output
        try:
            parser = get_parser(tc.tool_name)
            parsed = parser.parse(exec_result.stdout, cmd)

            ok, msg = tc.verify_fn(parsed)
            if ok:
                print(_ok(f"  Parsed OK — {parsed.finding_count} findings"))
                passed += 1
            else:
                print(_fail(f"  Verification failed: {msg}"))
                failed += 1
        except KeyError:
            # No parser for this tool yet
            print(_ok(f"  Execution succeeded (no parser to verify)"))
            passed += 1
        except Exception as exc:
            print(_fail(f"  Parser error: {exc}"))
            failed += 1

    # 6. Summary
    print(f"\n{'=' * 60}")
    print(f"{BOLD}Results:{RESET} {passed} passed, {failed} failed, {skipped} skipped")

    if failed:
        print(_fail(f"{failed} test(s) failed"))
        return 1
    else:
        print(_ok("All tests passed"))
        return 0


# ─────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=textwrap.dedent(__doc__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Force rebuild Docker image before testing",
    )
    parser.add_argument(
        "--tools",
        default=None,
        help="Comma-separated tool list (e.g., nmap,whatweb). Default: all.",
    )
    parser.add_argument(
        "--target",
        default="scanme.nmap.org",
        help="Target host for testing (default: scanme.nmap.org). "
             "ONLY use authorized targets.",
    )

    args = parser.parse_args()
    tool_filter = [t.strip() for t in args.tools.split(",")] if args.tools else None

    print(f"\n{YELLOW}⚠  Only scan targets you are authorized to test.{RESET}")
    print(f"{YELLOW}⚠  Default target scanme.nmap.org is explicitly permitted.{RESET}\n")

    sys.exit(run_tests(
        target=args.target,
        tool_filter=tool_filter,
        build_image=args.build,
    ))


if __name__ == "__main__":
    main()
