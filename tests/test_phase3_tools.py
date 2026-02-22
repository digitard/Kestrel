"""
Phase 3 Tests - Tool Layer

Tests for:
- BaseToolWrapper.execute() wired to UnifiedExecutor
- New Tier 1 wrappers: NucleiWrapper, SubfinderWrapper, FfufWrapper,
  HttpxWrapper, WhatwebWrapper
- New parsers: NucleiParser, SubfinderParser, FfufParser, HttpxParser,
  WhatwebParser
- ToolRegistry executor-aware discovery
- All 9 wrappers registered in global registry
- Import smoke tests
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

def _make_execution_result(stdout="", stderr="", exit_code=0, success=True):
    """Build a mock ExecutionResult."""
    from kestrel.core.executor import ExecutionResult, ExecutionStatus
    from datetime import datetime

    now = datetime.now()
    return ExecutionResult(
        command="mock-command",
        status=ExecutionStatus.COMPLETED if success else ExecutionStatus.FAILED,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=now,
        completed_at=now,
        duration_seconds=0.1,
    )


# ─────────────────────────────────────────────────────────────────────
# BaseToolWrapper.execute() wiring
# ─────────────────────────────────────────────────────────────────────

class TestBaseToolWrapperExecute:
    """Test BaseToolWrapper.execute() delegates to UnifiedExecutor."""

    def test_execute_calls_executor(self):
        """execute() should call executor.execute() with built command."""
        from kestrel.tools.nmap import NmapWrapper
        from kestrel.tools.base import ToolRequest

        mock_executor = MagicMock()
        mock_executor.execute.return_value = _make_execution_result(stdout="nmap output")

        wrapper = NmapWrapper(executor=mock_executor)
        request = ToolRequest(tool="nmap", target="example.com")
        result = wrapper.execute(request)

        mock_executor.execute.assert_called_once()
        call_kwargs = mock_executor.execute.call_args
        assert "nmap" in call_kwargs[1]["command"] or "nmap" in str(call_kwargs)
        assert result.stdout == "nmap output"

    def test_execute_returns_failed_on_validation_error(self):
        """execute() with invalid request returns FAILED ExecutionResult."""
        from kestrel.tools.nmap import NmapWrapper
        from kestrel.tools.base import ToolRequest
        from kestrel.core.executor import ExecutionStatus

        mock_executor = MagicMock()
        wrapper = NmapWrapper(executor=mock_executor)

        # Empty target fails validation
        request = ToolRequest(tool="nmap", target="")
        result = wrapper.execute(request)

        assert result.status == ExecutionStatus.FAILED
        assert "Validation failed" in result.error_message
        mock_executor.execute.assert_not_called()

    def test_execute_uses_default_timeout(self):
        """execute() should use wrapper's default timeout."""
        from kestrel.tools.nmap import NmapWrapper
        from kestrel.tools.base import ToolRequest

        mock_executor = MagicMock()
        mock_executor.execute.return_value = _make_execution_result()

        wrapper = NmapWrapper(executor=mock_executor)
        request = ToolRequest(tool="nmap", target="example.com")
        wrapper.execute(request)

        call_kwargs = mock_executor.execute.call_args[1]
        assert call_kwargs["timeout"] == wrapper.get_default_timeout()

    def test_execute_respects_request_timeout(self):
        """execute() should use request.timeout when set."""
        from kestrel.tools.nmap import NmapWrapper
        from kestrel.tools.base import ToolRequest

        mock_executor = MagicMock()
        mock_executor.execute.return_value = _make_execution_result()

        wrapper = NmapWrapper(executor=mock_executor)
        request = ToolRequest(tool="nmap", target="example.com", timeout=42)
        wrapper.execute(request)

        call_kwargs = mock_executor.execute.call_args[1]
        assert call_kwargs["timeout"] == 42

    def test_executor_lazy_created_when_none(self):
        """Executor should be auto-created on first execute() call if not provided."""
        from kestrel.tools.base import BaseToolWrapper, ToolRequest, ToolCategory, ToolSchema, ValidationResult

        class MinimalWrapper(BaseToolWrapper):
            @property
            def name(self):
                return "echo"
            @property
            def category(self):
                return ToolCategory.UTILITY
            def get_schema(self):
                return ToolSchema(name="echo", description="echo", category=self.category)
            def validate(self, req):
                return ValidationResult()
            def build_command(self, req):
                return f"echo {req.target}"

        wrapper = MinimalWrapper()
        assert wrapper._executor is None

        # Patch UnifiedExecutor at its definition site so we don't actually run anything
        mock_result = _make_execution_result(stdout="hello")
        with patch("kestrel.core.executor.UnifiedExecutor") as MockExec:
            instance = MockExec.return_value
            instance.execute.return_value = mock_result
            request = ToolRequest(tool="echo", target="hello")
            wrapper.execute(request)
            # Executor was created lazily
            MockExec.assert_called_once()


# ─────────────────────────────────────────────────────────────────────
# NucleiWrapper
# ─────────────────────────────────────────────────────────────────────

class TestNucleiWrapper:
    """Tests for NucleiWrapper."""

    def test_name_and_category(self):
        from kestrel.tools.nuclei import NucleiWrapper
        from kestrel.tools.base import ToolCategory
        w = NucleiWrapper()
        assert w.name == "nuclei"
        assert w.category == ToolCategory.VULNERABILITY

    def test_schema_has_required_options(self):
        from kestrel.tools.nuclei import NucleiWrapper
        w = NucleiWrapper()
        schema = w.get_schema()
        option_names = [o["name"] for o in schema.options]
        assert "templates" in option_names
        assert "severity" in option_names
        assert "rate_limit" in option_names

    def test_build_command_basic(self):
        from kestrel.tools.nuclei import NucleiWrapper
        from kestrel.tools.base import ToolRequest
        w = NucleiWrapper()
        cmd = w.build_command(ToolRequest(tool="nuclei", target="https://example.com"))
        assert "nuclei" in cmd
        assert "https://example.com" in cmd

    def test_build_command_with_templates(self):
        from kestrel.tools.nuclei import NucleiWrapper
        from kestrel.tools.base import ToolRequest
        w = NucleiWrapper()
        cmd = w.build_command(ToolRequest(
            tool="nuclei", target="https://example.com",
            options={"templates": "cves"}
        ))
        assert "-t cves" in cmd

    def test_build_command_with_severity(self):
        from kestrel.tools.nuclei import NucleiWrapper
        from kestrel.tools.base import ToolRequest
        w = NucleiWrapper()
        cmd = w.build_command(ToolRequest(
            tool="nuclei", target="https://example.com",
            options={"severity": "critical,high"}
        ))
        assert "-severity critical,high" in cmd

    def test_build_command_json_output_default(self):
        from kestrel.tools.nuclei import NucleiWrapper
        from kestrel.tools.base import ToolRequest
        w = NucleiWrapper()
        cmd = w.build_command(ToolRequest(tool="nuclei", target="https://example.com"))
        assert "-jsonl" in cmd

    def test_validate_invalid_severity(self):
        from kestrel.tools.nuclei import NucleiWrapper
        from kestrel.tools.base import ToolRequest
        w = NucleiWrapper()
        result = w.validate(ToolRequest(
            tool="nuclei", target="https://example.com",
            options={"severity": "bogus"}
        ))
        assert not result.valid

    def test_validate_valid_severity(self):
        from kestrel.tools.nuclei import NucleiWrapper
        from kestrel.tools.base import ToolRequest
        w = NucleiWrapper()
        result = w.validate(ToolRequest(
            tool="nuclei", target="https://example.com",
            options={"severity": "high,critical"}
        ))
        assert result.valid

    def test_default_timeout(self):
        from kestrel.tools.nuclei import NucleiWrapper
        w = NucleiWrapper()
        assert w.get_default_timeout() == 600


# ─────────────────────────────────────────────────────────────────────
# SubfinderWrapper
# ─────────────────────────────────────────────────────────────────────

class TestSubfinderWrapper:
    """Tests for SubfinderWrapper."""

    def test_name_and_category(self):
        from kestrel.tools.subfinder import SubfinderWrapper
        from kestrel.tools.base import ToolCategory
        w = SubfinderWrapper()
        assert w.name == "subfinder"
        assert w.category == ToolCategory.RECON

    def test_build_command_basic(self):
        from kestrel.tools.subfinder import SubfinderWrapper
        from kestrel.tools.base import ToolRequest
        w = SubfinderWrapper()
        cmd = w.build_command(ToolRequest(tool="subfinder", target="example.com"))
        assert "subfinder" in cmd
        assert "-d example.com" in cmd

    def test_build_command_all_sources(self):
        from kestrel.tools.subfinder import SubfinderWrapper
        from kestrel.tools.base import ToolRequest
        w = SubfinderWrapper()
        cmd = w.build_command(ToolRequest(
            tool="subfinder", target="example.com",
            options={"all_sources": True}
        ))
        assert "-all" in cmd

    def test_build_command_json_output_default(self):
        from kestrel.tools.subfinder import SubfinderWrapper
        from kestrel.tools.base import ToolRequest
        w = SubfinderWrapper()
        cmd = w.build_command(ToolRequest(tool="subfinder", target="example.com"))
        assert "-oJ" in cmd

    def test_validate_warns_on_url_target(self):
        from kestrel.tools.subfinder import SubfinderWrapper
        from kestrel.tools.base import ToolRequest
        w = SubfinderWrapper()
        result = w.validate(ToolRequest(
            tool="subfinder", target="https://example.com"
        ))
        assert result.valid  # Still valid, just a warning
        assert len(result.warnings) > 0

    def test_validate_valid_domain(self):
        from kestrel.tools.subfinder import SubfinderWrapper
        from kestrel.tools.base import ToolRequest
        w = SubfinderWrapper()
        result = w.validate(ToolRequest(tool="subfinder", target="example.com"))
        assert result.valid


# ─────────────────────────────────────────────────────────────────────
# FfufWrapper
# ─────────────────────────────────────────────────────────────────────

class TestFfufWrapper:
    """Tests for FfufWrapper."""

    def test_name_and_category(self):
        from kestrel.tools.ffuf import FfufWrapper
        from kestrel.tools.base import ToolCategory
        w = FfufWrapper()
        assert w.name == "ffuf"
        assert w.category == ToolCategory.ENUMERATION

    def test_build_command_basic(self):
        from kestrel.tools.ffuf import FfufWrapper
        from kestrel.tools.base import ToolRequest
        w = FfufWrapper()
        cmd = w.build_command(ToolRequest(
            tool="ffuf", target="https://example.com/FUZZ"
        ))
        assert "ffuf" in cmd
        assert "https://example.com/FUZZ" in cmd

    def test_build_command_with_extensions(self):
        from kestrel.tools.ffuf import FfufWrapper
        from kestrel.tools.base import ToolRequest
        w = FfufWrapper()
        cmd = w.build_command(ToolRequest(
            tool="ffuf", target="https://example.com/FUZZ",
            options={"extensions": "php,html"}
        ))
        assert "-e php,html" in cmd

    def test_build_command_filter_codes(self):
        from kestrel.tools.ffuf import FfufWrapper
        from kestrel.tools.base import ToolRequest
        w = FfufWrapper()
        cmd = w.build_command(ToolRequest(
            tool="ffuf", target="https://example.com/FUZZ",
            options={"filter_codes": "404,400"}
        ))
        assert "-fc 404,400" in cmd

    def test_build_command_json_output_default(self):
        from kestrel.tools.ffuf import FfufWrapper
        from kestrel.tools.base import ToolRequest
        w = FfufWrapper()
        cmd = w.build_command(ToolRequest(
            tool="ffuf", target="https://example.com/FUZZ"
        ))
        assert "-of json" in cmd

    def test_validate_warns_no_fuzz_keyword(self):
        from kestrel.tools.ffuf import FfufWrapper
        from kestrel.tools.base import ToolRequest
        w = FfufWrapper()
        result = w.validate(ToolRequest(tool="ffuf", target="https://example.com"))
        assert result.valid
        assert len(result.warnings) > 0

    def test_validate_invalid_threads(self):
        from kestrel.tools.ffuf import FfufWrapper
        from kestrel.tools.base import ToolRequest
        w = FfufWrapper()
        result = w.validate(ToolRequest(
            tool="ffuf", target="https://example.com/FUZZ",
            options={"threads": 999}
        ))
        assert not result.valid

    def test_wordlist_resolution(self):
        from kestrel.tools.ffuf import FfufWrapper
        w = FfufWrapper()
        resolved = w._resolve_wordlist("common")
        assert resolved.endswith(".txt")

    def test_wordlist_passthrough_for_custom_path(self):
        from kestrel.tools.ffuf import FfufWrapper
        w = FfufWrapper()
        resolved = w._resolve_wordlist("/custom/wordlist.txt")
        assert resolved == "/custom/wordlist.txt"


# ─────────────────────────────────────────────────────────────────────
# HttpxWrapper
# ─────────────────────────────────────────────────────────────────────

class TestHttpxWrapper:
    """Tests for HttpxWrapper."""

    def test_name_and_category(self):
        from kestrel.tools.httpx import HttpxWrapper
        from kestrel.tools.base import ToolCategory
        w = HttpxWrapper()
        assert w.name == "httpx"
        assert w.category == ToolCategory.FINGERPRINT

    def test_build_command_basic(self):
        from kestrel.tools.httpx import HttpxWrapper
        from kestrel.tools.base import ToolRequest
        w = HttpxWrapper()
        cmd = w.build_command(ToolRequest(tool="httpx", target="https://example.com"))
        assert "httpx" in cmd
        assert "https://example.com" in cmd

    def test_build_command_status_code_on_by_default(self):
        from kestrel.tools.httpx import HttpxWrapper
        from kestrel.tools.base import ToolRequest
        w = HttpxWrapper()
        cmd = w.build_command(ToolRequest(tool="httpx", target="example.com"))
        assert "-status-code" in cmd

    def test_build_command_title_on_by_default(self):
        from kestrel.tools.httpx import HttpxWrapper
        from kestrel.tools.base import ToolRequest
        w = HttpxWrapper()
        cmd = w.build_command(ToolRequest(tool="httpx", target="example.com"))
        assert "-title" in cmd

    def test_build_command_tech_detect_on_by_default(self):
        from kestrel.tools.httpx import HttpxWrapper
        from kestrel.tools.base import ToolRequest
        w = HttpxWrapper()
        cmd = w.build_command(ToolRequest(tool="httpx", target="example.com"))
        assert "-tech-detect" in cmd

    def test_build_command_json_output_default(self):
        from kestrel.tools.httpx import HttpxWrapper
        from kestrel.tools.base import ToolRequest
        w = HttpxWrapper()
        cmd = w.build_command(ToolRequest(tool="httpx", target="example.com"))
        assert "-json" in cmd

    def test_validate_valid_target(self):
        from kestrel.tools.httpx import HttpxWrapper
        from kestrel.tools.base import ToolRequest
        w = HttpxWrapper()
        result = w.validate(ToolRequest(tool="httpx", target="https://example.com"))
        assert result.valid


# ─────────────────────────────────────────────────────────────────────
# WhatwebWrapper
# ─────────────────────────────────────────────────────────────────────

class TestWhatwebWrapper:
    """Tests for WhatwebWrapper."""

    def test_name_and_category(self):
        from kestrel.tools.whatweb import WhatwebWrapper
        from kestrel.tools.base import ToolCategory
        w = WhatwebWrapper()
        assert w.name == "whatweb"
        assert w.category == ToolCategory.FINGERPRINT

    def test_build_command_basic(self):
        from kestrel.tools.whatweb import WhatwebWrapper
        from kestrel.tools.base import ToolRequest
        w = WhatwebWrapper()
        cmd = w.build_command(ToolRequest(tool="whatweb", target="https://example.com"))
        assert "whatweb" in cmd
        assert "https://example.com" in cmd

    def test_build_command_aggression_default(self):
        from kestrel.tools.whatweb import WhatwebWrapper
        from kestrel.tools.base import ToolRequest
        w = WhatwebWrapper()
        cmd = w.build_command(ToolRequest(tool="whatweb", target="https://example.com"))
        assert "-a 1" in cmd

    def test_build_command_aggression_custom(self):
        from kestrel.tools.whatweb import WhatwebWrapper
        from kestrel.tools.base import ToolRequest
        w = WhatwebWrapper()
        cmd = w.build_command(ToolRequest(
            tool="whatweb", target="https://example.com",
            options={"aggression": 3}
        ))
        assert "-a 3" in cmd

    def test_build_command_json_output_default(self):
        from kestrel.tools.whatweb import WhatwebWrapper
        from kestrel.tools.base import ToolRequest
        w = WhatwebWrapper()
        cmd = w.build_command(ToolRequest(tool="whatweb", target="https://example.com"))
        assert "--log-json" in cmd

    def test_validate_invalid_aggression(self):
        from kestrel.tools.whatweb import WhatwebWrapper
        from kestrel.tools.base import ToolRequest
        w = WhatwebWrapper()
        result = w.validate(ToolRequest(
            tool="whatweb", target="https://example.com",
            options={"aggression": 9}
        ))
        assert not result.valid

    def test_validate_valid_aggression(self):
        from kestrel.tools.whatweb import WhatwebWrapper
        from kestrel.tools.base import ToolRequest
        w = WhatwebWrapper()
        result = w.validate(ToolRequest(
            tool="whatweb", target="https://example.com",
            options={"aggression": 2}
        ))
        assert result.valid


# ─────────────────────────────────────────────────────────────────────
# NucleiParser
# ─────────────────────────────────────────────────────────────────────

class TestNucleiParser:
    """Tests for NucleiParser."""

    SAMPLE_OUTPUT = "\n".join([
        json.dumps({
            "template-id": "cve-2021-41773",
            "info": {
                "name": "Apache HTTP Server Path Traversal",
                "severity": "critical",
                "description": "RCE via path traversal",
            },
            "matched-at": "https://example.com/cgi-bin/.%2e/etc/passwd",
            "extracted-results": ["/etc/passwd"],
        }),
        json.dumps({
            "template-id": "http-missing-security-headers",
            "info": {
                "name": "Missing Security Headers",
                "severity": "info",
            },
            "matched-at": "https://example.com",
        }),
    ])

    def test_tool_name(self):
        from kestrel.parsers.nuclei import NucleiParser
        assert NucleiParser().tool_name == "nuclei"

    def test_can_parse_jsonl(self):
        from kestrel.parsers.nuclei import NucleiParser
        assert NucleiParser().can_parse(self.SAMPLE_OUTPUT)

    def test_cannot_parse_nmap_output(self):
        from kestrel.parsers.nuclei import NucleiParser
        nmap_output = "Nmap scan report for example.com\nPORT   STATE SERVICE\n80/tcp open  http"
        assert not NucleiParser().can_parse(nmap_output)

    def test_parses_vulnerabilities(self):
        from kestrel.parsers.nuclei import NucleiParser
        result = NucleiParser().parse(self.SAMPLE_OUTPUT)
        assert result.success
        assert len(result.vulnerabilities) == 2

    def test_severity_mapping(self):
        from kestrel.parsers.nuclei import NucleiParser
        from kestrel.parsers.base import Severity
        result = NucleiParser().parse(self.SAMPLE_OUTPUT)
        critical_vulns = [v for v in result.vulnerabilities if v.severity == Severity.CRITICAL]
        assert len(critical_vulns) == 1
        assert "Apache" in critical_vulns[0].title

    def test_cve_extraction(self):
        from kestrel.parsers.nuclei import NucleiParser
        result = NucleiParser().parse(self.SAMPLE_OUTPUT)
        cve_vulns = [v for v in result.vulnerabilities if v.cve_id]
        assert len(cve_vulns) == 1
        assert cve_vulns[0].cve_id == "CVE-2021-41773"

    def test_empty_output(self):
        from kestrel.parsers.nuclei import NucleiParser
        result = NucleiParser().parse("")
        assert result.success
        assert len(result.vulnerabilities) == 0

    def test_finding_count(self):
        from kestrel.parsers.nuclei import NucleiParser
        result = NucleiParser().parse(self.SAMPLE_OUTPUT)
        assert result.finding_count == 2


# ─────────────────────────────────────────────────────────────────────
# SubfinderParser
# ─────────────────────────────────────────────────────────────────────

class TestSubfinderParser:
    """Tests for SubfinderParser."""

    PLAIN_OUTPUT = "sub1.example.com\nsub2.example.com\nsub3.example.com"
    JSON_OUTPUT = "\n".join([
        json.dumps({"host": "sub1.example.com", "source": "crtsh"}),
        json.dumps({"host": "sub2.example.com", "source": "hackertarget"}),
    ])

    def test_tool_name(self):
        from kestrel.parsers.subfinder import SubfinderParser
        assert SubfinderParser().tool_name == "subfinder"

    def test_can_parse_plain_text(self):
        from kestrel.parsers.subfinder import SubfinderParser
        assert SubfinderParser().can_parse(self.PLAIN_OUTPUT)

    def test_can_parse_json(self):
        from kestrel.parsers.subfinder import SubfinderParser
        assert SubfinderParser().can_parse(self.JSON_OUTPUT)

    def test_parses_plain_subdomains(self):
        from kestrel.parsers.subfinder import SubfinderParser
        result = SubfinderParser().parse(self.PLAIN_OUTPUT)
        assert result.success
        assert len(result.hosts) == 3
        hostnames = [h.hostname for h in result.hosts]
        assert "sub1.example.com" in hostnames

    def test_parses_json_subdomains(self):
        from kestrel.parsers.subfinder import SubfinderParser
        result = SubfinderParser().parse(self.JSON_OUTPUT)
        assert result.success
        assert len(result.hosts) == 2

    def test_deduplication(self):
        from kestrel.parsers.subfinder import SubfinderParser
        dupes = "sub1.example.com\nsub1.example.com\nsub2.example.com"
        result = SubfinderParser().parse(dupes)
        assert len(result.hosts) == 2

    def test_empty_output(self):
        from kestrel.parsers.subfinder import SubfinderParser
        result = SubfinderParser().parse("")
        assert result.success
        assert len(result.hosts) == 0


# ─────────────────────────────────────────────────────────────────────
# FfufParser
# ─────────────────────────────────────────────────────────────────────

class TestFfufParser:
    """Tests for FfufParser."""

    SAMPLE_OUTPUT = json.dumps({
        "commandline": "ffuf -u https://example.com/FUZZ -w wordlist.txt -of json",
        "results": [
            {
                "input": {"FUZZ": "admin"},
                "position": 1,
                "status": 200,
                "length": 1234,
                "url": "https://example.com/admin",
                "redirectlocation": "",
            },
            {
                "input": {"FUZZ": "login"},
                "position": 2,
                "status": 302,
                "length": 45,
                "url": "https://example.com/login",
                "redirectlocation": "https://example.com/auth/login",
            },
        ],
    })

    def test_tool_name(self):
        from kestrel.parsers.ffuf import FfufParser
        assert FfufParser().tool_name == "ffuf"

    def test_can_parse_ffuf_json(self):
        from kestrel.parsers.ffuf import FfufParser
        assert FfufParser().can_parse(self.SAMPLE_OUTPUT)

    def test_cannot_parse_non_ffuf(self):
        from kestrel.parsers.ffuf import FfufParser
        assert not FfufParser().can_parse('{"not": "ffuf"}')

    def test_parses_paths(self):
        from kestrel.parsers.ffuf import FfufParser
        result = FfufParser().parse(self.SAMPLE_OUTPUT)
        assert result.success
        assert len(result.paths) == 2

    def test_path_status_codes(self):
        from kestrel.parsers.ffuf import FfufParser
        result = FfufParser().parse(self.SAMPLE_OUTPUT)
        codes = [p.status_code for p in result.paths]
        assert 200 in codes
        assert 302 in codes

    def test_redirect_captured(self):
        from kestrel.parsers.ffuf import FfufParser
        result = FfufParser().parse(self.SAMPLE_OUTPUT)
        redirect_paths = [p for p in result.paths if p.redirect]
        assert len(redirect_paths) == 1
        assert "auth/login" in redirect_paths[0].redirect

    def test_empty_results(self):
        from kestrel.parsers.ffuf import FfufParser
        empty = json.dumps({
            "commandline": "ffuf ...",
            "results": [],
        })
        result = FfufParser().parse(empty)
        assert result.success
        assert len(result.paths) == 0

    def test_invalid_json(self):
        from kestrel.parsers.ffuf import FfufParser
        result = FfufParser().parse("not json at all")
        assert not result.success


# ─────────────────────────────────────────────────────────────────────
# HttpxParser
# ─────────────────────────────────────────────────────────────────────

class TestHttpxParser:
    """Tests for HttpxParser."""

    SAMPLE_OUTPUT = "\n".join([
        json.dumps({
            "url": "https://example.com",
            "status-code": 200,
            "title": "Example Domain",
            "tech": ["Nginx/1.18.0", "Bootstrap/4.6"],
            "host": "93.184.216.34",
        }),
        json.dumps({
            "url": "http://api.example.com",
            "status-code": 401,
            "title": "Unauthorized",
            "tech": [],
            "host": "93.184.216.35",
        }),
    ])

    def test_tool_name(self):
        from kestrel.parsers.httpx import HttpxParser
        assert HttpxParser().tool_name == "httpx"

    def test_can_parse_httpx_jsonl(self):
        from kestrel.parsers.httpx import HttpxParser
        assert HttpxParser().can_parse(self.SAMPLE_OUTPUT)

    def test_parses_hosts(self):
        from kestrel.parsers.httpx import HttpxParser
        result = HttpxParser().parse(self.SAMPLE_OUTPUT)
        assert result.success
        assert len(result.hosts) == 2

    def test_port_detection_https(self):
        from kestrel.parsers.httpx import HttpxParser
        result = HttpxParser().parse(self.SAMPLE_OUTPUT)
        https_hosts = [h for h in result.hosts if h.ports and h.ports[0].port == 443]
        assert len(https_hosts) == 1

    def test_port_detection_http(self):
        from kestrel.parsers.httpx import HttpxParser
        result = HttpxParser().parse(self.SAMPLE_OUTPUT)
        http_hosts = [h for h in result.hosts if h.ports and h.ports[0].port == 80]
        assert len(http_hosts) == 1

    def test_tech_in_extra_info(self):
        from kestrel.parsers.httpx import HttpxParser
        result = HttpxParser().parse(self.SAMPLE_OUTPUT)
        nginx_hosts = [
            h for h in result.hosts
            if h.ports and h.ports[0].extra_info and "Nginx" in h.ports[0].extra_info
        ]
        assert len(nginx_hosts) >= 1

    def test_empty_output(self):
        from kestrel.parsers.httpx import HttpxParser
        result = HttpxParser().parse("")
        assert result.success
        assert len(result.hosts) == 0


# ─────────────────────────────────────────────────────────────────────
# WhatwebParser
# ─────────────────────────────────────────────────────────────────────

class TestWhatwebParser:
    """Tests for WhatwebParser."""

    SAMPLE_OUTPUT = json.dumps([
        {
            "target": "https://example.com",
            "http_status": 200,
            "plugins": {
                "Nginx": {"version": ["1.18.0"]},
                "WordPress": {"version": ["5.9.3"]},
                "jQuery": {},
            },
        }
    ])

    def test_tool_name(self):
        from kestrel.parsers.whatweb import WhatwebParser
        assert WhatwebParser().tool_name == "whatweb"

    def test_can_parse_whatweb_json(self):
        from kestrel.parsers.whatweb import WhatwebParser
        assert WhatwebParser().can_parse(self.SAMPLE_OUTPUT)

    def test_cannot_parse_random_json(self):
        from kestrel.parsers.whatweb import WhatwebParser
        assert not WhatwebParser().can_parse('{"not": "whatweb"}')

    def test_parses_hosts(self):
        from kestrel.parsers.whatweb import WhatwebParser
        result = WhatwebParser().parse(self.SAMPLE_OUTPUT)
        assert result.success
        assert len(result.hosts) == 1

    def test_tech_captured_in_extra_info(self):
        from kestrel.parsers.whatweb import WhatwebParser
        result = WhatwebParser().parse(self.SAMPLE_OUTPUT)
        host = result.hosts[0]
        extra = host.ports[0].extra_info if host.ports else ""
        assert "Nginx" in extra
        assert "WordPress" in extra

    def test_versions_in_extra_info(self):
        from kestrel.parsers.whatweb import WhatwebParser
        result = WhatwebParser().parse(self.SAMPLE_OUTPUT)
        extra = result.hosts[0].ports[0].extra_info
        assert "1.18.0" in extra

    def test_port_detection_https(self):
        from kestrel.parsers.whatweb import WhatwebParser
        result = WhatwebParser().parse(self.SAMPLE_OUTPUT)
        port = result.hosts[0].ports[0].port
        assert port == 443

    def test_empty_output(self):
        from kestrel.parsers.whatweb import WhatwebParser
        result = WhatwebParser().parse("")
        assert result.success
        assert len(result.hosts) == 0

    def test_invalid_json(self):
        from kestrel.parsers.whatweb import WhatwebParser
        result = WhatwebParser().parse("not json")
        assert not result.success


# ─────────────────────────────────────────────────────────────────────
# ToolRegistry executor integration
# ─────────────────────────────────────────────────────────────────────

class TestToolRegistryExecutorIntegration:
    """Test ToolRegistry executor-aware features."""

    def test_registry_accepts_executor(self):
        from kestrel.tools.registry import ToolRegistry
        mock_executor = MagicMock()
        registry = ToolRegistry(executor=mock_executor)
        assert registry._executor is mock_executor

    def test_registry_uses_executor_for_tool_check(self):
        """When executor is set, check_tool should delegate to it."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools.nmap import NmapWrapper

        mock_executor = MagicMock()
        mock_executor.check_tool.return_value = True

        registry = ToolRegistry(executor=mock_executor)
        registry.register_wrapped_tool(NmapWrapper())

        mock_executor.check_tool.assert_called_with("nmap")

    def test_registry_without_executor_uses_shutil(self):
        """Without executor, registration uses local shutil.which."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools.nmap import NmapWrapper

        with patch("kestrel.tools.registry.shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/nmap"
            registry = ToolRegistry()  # No executor
            info = registry.register_wrapped_tool(NmapWrapper())
            # shutil.which was used
            mock_which.assert_called()

    def test_all_nine_wrappers_registered_in_global_registry(self):
        """Global registry should register all 9 Tier 1 wrapped tools."""
        from kestrel.tools.registry import ToolRegistry, ToolTier, reset_registry

        # Reset and rebuild without triggering real discovery
        reset_registry()

        expected_tools = {
            "nmap", "gobuster", "nikto", "sqlmap",
            "nuclei", "subfinder", "ffuf", "httpx", "whatweb",
        }

        with patch("kestrel.tools.registry.shutil.which") as mock_which, \
             patch("kestrel.core.executor.UnifiedExecutor") as MockExec:

            # All tools "available"
            mock_which.return_value = "/usr/bin/mock"

            mock_exec_instance = MockExec.return_value
            mock_exec_instance.check_tool.return_value = True
            mock_exec_instance.execute.return_value = _make_execution_result(
                stdout="v1.0.0"
            )

            registry = ToolRegistry(executor=mock_exec_instance)

            # Import and call _initialize_registry directly to avoid full discovery
            from kestrel.tools.registry import _initialize_registry
            with patch("kestrel.tools.registry.ToolRegistry.discover"):
                _initialize_registry(registry)

            wrapped = {
                name for name, info in registry._tools.items()
                if info.tier == ToolTier.WRAPPED
            }
            assert expected_tools == wrapped

        reset_registry()

    def test_discover_uses_executor_check_tool(self):
        """discover() should use executor.check_tool when executor is set."""
        from kestrel.tools.registry import ToolRegistry

        mock_executor = MagicMock()
        mock_executor.check_tool.return_value = False  # All tools unavailable

        registry = ToolRegistry(executor=mock_executor)
        summary = registry.discover(probe_help=False)

        # Should have called check_tool for each known tool
        assert mock_executor.check_tool.call_count > 0
        assert summary["found"] == 0


# ─────────────────────────────────────────────────────────────────────
# Parser registry completeness
# ─────────────────────────────────────────────────────────────────────

class TestParserRegistryCompleteness:
    """Test that all 9 tools have parsers registered."""

    def test_all_nine_parsers_in_registry(self):
        from kestrel.parsers import PARSERS
        expected = {"nmap", "gobuster", "nikto", "sqlmap",
                    "nuclei", "subfinder", "ffuf", "httpx", "whatweb"}
        assert expected == set(PARSERS.keys())

    def test_get_parser_nuclei(self):
        from kestrel.parsers import get_parser
        from kestrel.parsers.nuclei import NucleiParser
        assert isinstance(get_parser("nuclei"), NucleiParser)

    def test_get_parser_subfinder(self):
        from kestrel.parsers import get_parser
        from kestrel.parsers.subfinder import SubfinderParser
        assert isinstance(get_parser("subfinder"), SubfinderParser)

    def test_get_parser_ffuf(self):
        from kestrel.parsers import get_parser
        from kestrel.parsers.ffuf import FfufParser
        assert isinstance(get_parser("ffuf"), FfufParser)

    def test_get_parser_httpx(self):
        from kestrel.parsers import get_parser
        from kestrel.parsers.httpx import HttpxParser
        assert isinstance(get_parser("httpx"), HttpxParser)

    def test_get_parser_whatweb(self):
        from kestrel.parsers import get_parser
        from kestrel.parsers.whatweb import WhatwebParser
        assert isinstance(get_parser("whatweb"), WhatwebParser)


# ─────────────────────────────────────────────────────────────────────
# Import smoke tests
# ─────────────────────────────────────────────────────────────────────

class TestPhase3Imports:
    """Smoke tests: all new Phase 3 symbols importable."""

    def test_import_new_wrappers(self):
        from kestrel.tools import (
            NucleiWrapper,
            SubfinderWrapper,
            FfufWrapper,
            HttpxWrapper,
            WhatwebWrapper,
        )
        for cls in [NucleiWrapper, SubfinderWrapper, FfufWrapper, HttpxWrapper, WhatwebWrapper]:
            assert cls is not None

    def test_import_new_parsers(self):
        from kestrel.parsers import (
            NucleiParser,
            SubfinderParser,
            FfufParser,
            HttpxParser,
            WhatwebParser,
        )
        for cls in [NucleiParser, SubfinderParser, FfufParser, HttpxParser, WhatwebParser]:
            assert cls is not None

    def test_wrapper_instantiation(self):
        from kestrel.tools import (
            NucleiWrapper, SubfinderWrapper, FfufWrapper,
            HttpxWrapper, WhatwebWrapper,
        )
        for cls in [NucleiWrapper, SubfinderWrapper, FfufWrapper, HttpxWrapper, WhatwebWrapper]:
            w = cls()
            assert w.name
            assert w.category
            assert w.get_schema() is not None

    def test_parser_instantiation(self):
        from kestrel.parsers import (
            NucleiParser, SubfinderParser, FfufParser,
            HttpxParser, WhatwebParser,
        )
        for cls in [NucleiParser, SubfinderParser, FfufParser, HttpxParser, WhatwebParser]:
            p = cls()
            assert p.tool_name
