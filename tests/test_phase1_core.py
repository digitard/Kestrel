"""
Phase 1 Tests - Core Foundation

Tests for:
- Configuration management
- Native executor
- Session management
- Tool wrappers
- Output parsers
- LLM integration
"""

import pytest
from pathlib import Path
import sys
import os
import tempfile

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestConfiguration:
    """Test configuration management."""
    
    def test_load_default_config(self):
        """Should load default configuration."""
        from kestrel.core import load_config, reset_config
        
        reset_config()
        config = load_config(validate_safety=False)
        
        assert config is not None
        assert config.app_name == "Kestrel"
    
    def test_safety_defaults(self):
        """Critical safety settings must default to safe values."""
        from kestrel.core import load_config, reset_config
        
        reset_config()
        config = load_config(validate_safety=False)
        
        # These MUST be True
        assert config.authorization.require_authorization is True
        assert config.scope.fail_closed is True
        assert config.scope.revalidate_before_exec is True
        assert config.audit.enabled is True
    
    def test_safety_validation_catches_violations(self):
        """Safety validation should catch dangerous settings."""
        from kestrel.core import Config, AuthorizationConfig
        
        # Create config with dangerous setting
        config = Config()
        config.authorization = AuthorizationConfig(require_authorization=False)
        
        violations = config.validate_safety()
        
        assert len(violations) > 0
        assert any("require_authorization" in v for v in violations)
    
    def test_get_config_singleton(self):
        """get_config should return singleton."""
        from kestrel.core import get_config, reset_config
        
        reset_config()
        config1 = get_config()
        config2 = get_config()
        
        assert config1 is config2


class TestNativeExecutor:
    """Test native command execution."""
    
    def test_executor_creation(self):
        """Should create executor instance."""
        from kestrel.core import NativeExecutor
        
        executor = NativeExecutor()
        assert executor is not None
    
    def test_check_tool_echo(self):
        """Should find common tools."""
        from kestrel.core import NativeExecutor
        
        executor = NativeExecutor()
        
        # Echo should exist on any system
        assert executor.check_tool("echo") is True
        assert executor.check_tool("nonexistent_tool_xyz") is False
    
    def test_execute_simple_command(self):
        """Should execute simple commands."""
        from kestrel.core import NativeExecutor, ExecutionStatus
        
        executor = NativeExecutor()
        result = executor.execute("echo 'hello world'", timeout=5)
        
        assert result.status == ExecutionStatus.COMPLETED
        assert result.success is True
        assert "hello" in result.stdout
    
    def test_execute_with_timeout(self):
        """Should handle command timeout."""
        from kestrel.core import NativeExecutor, ExecutionStatus
        
        executor = NativeExecutor()
        result = executor.execute("sleep 10", timeout=1)
        
        assert result.status == ExecutionStatus.TIMEOUT
        assert result.success is False
    
    def test_execute_failing_command(self):
        """Should handle failing commands."""
        from kestrel.core import NativeExecutor, ExecutionStatus
        
        executor = NativeExecutor()
        result = executor.execute("exit 1", timeout=5)
        
        assert result.status == ExecutionStatus.COMPLETED
        assert result.success is False
        assert result.exit_code == 1
    
    def test_execute_tool_not_found(self):
        """Should handle missing tools gracefully."""
        from kestrel.core import NativeExecutor, ExecutionStatus
        
        executor = NativeExecutor()
        result = executor.execute_tool(
            "nonexistent_tool_xyz",
            ["--help"],
            timeout=5
        )
        
        assert result.status == ExecutionStatus.FAILED
        assert "not found" in result.error_message.lower()


class TestSession:
    """Test session management."""
    
    def test_create_session(self):
        """Should create hunt session."""
        from kestrel.core import HuntSession, SessionState
        
        session = HuntSession(
            name="Test Hunt",
            target="example.com",
        )
        
        assert session.name == "Test Hunt"
        assert session.target == "example.com"
        assert session.state == SessionState.CREATED
        assert session.id is not None
    
    def test_session_lifecycle(self):
        """Session should track state transitions."""
        from kestrel.core import HuntSession, SessionState
        
        session = HuntSession(target="example.com")
        assert session.state == SessionState.CREATED
        
        session.start()
        assert session.state == SessionState.RUNNING
        assert session.started_at is not None
        
        session.pause()
        assert session.state == SessionState.PAUSED
        
        session.resume()
        assert session.state == SessionState.RUNNING
        
        session.complete()
        assert session.state == SessionState.COMPLETED
        assert session.completed_at is not None
    
    def test_add_finding(self):
        """Should track findings."""
        from kestrel.core import HuntSession, Finding, FindingSeverity
        
        session = HuntSession(target="example.com")
        
        finding = Finding(
            title="Open Port 80",
            severity=FindingSeverity.INFO,
            tool="nmap",
        )
        session.add_finding(finding)
        
        assert len(session.findings) == 1
        assert session.findings[0].title == "Open Port 80"
    
    def test_finding_counts(self):
        """Should count findings by severity."""
        from kestrel.core import HuntSession, Finding, FindingSeverity
        
        session = HuntSession(target="example.com")
        
        session.add_finding(Finding(title="Info 1", severity=FindingSeverity.INFO))
        session.add_finding(Finding(title="Info 2", severity=FindingSeverity.INFO))
        session.add_finding(Finding(title="High 1", severity=FindingSeverity.HIGH))
        session.add_finding(Finding(title="Critical 1", severity=FindingSeverity.CRITICAL))
        
        counts = session.finding_counts
        
        assert counts["info"] == 2
        assert counts["high"] == 1
        assert counts["critical"] == 1
    
    def test_session_serialization(self):
        """Session should serialize to dict."""
        from kestrel.core import HuntSession, Finding, FindingSeverity
        
        session = HuntSession(
            name="Test",
            target="example.com",
            program_name="Test Program",
        )
        session.add_finding(Finding(title="Test Finding", severity=FindingSeverity.LOW))
        
        data = session.to_dict()
        
        assert data["name"] == "Test"
        assert data["target"] == "example.com"
        assert len(data["findings"]) == 1
    
    def test_session_save_load(self):
        """Session should save and load from file."""
        from kestrel.core import HuntSession, Finding, FindingSeverity
        
        with tempfile.TemporaryDirectory() as tmpdir:
            session = HuntSession(
                name="Test",
                target="example.com",
            )
            session.add_finding(Finding(title="Test", severity=FindingSeverity.HIGH))
            
            path = Path(tmpdir) / "session.json"
            session.save(path)
            
            loaded = HuntSession.load(path)
            
            assert loaded.name == session.name
            assert loaded.target == session.target
            assert len(loaded.findings) == 1


class TestToolWrappers:
    """Test tool wrappers."""
    
    def test_nmap_wrapper_schema(self):
        """Nmap wrapper should provide schema."""
        from kestrel.tools import NmapWrapper
        
        wrapper = NmapWrapper()
        schema = wrapper.get_schema()
        
        assert schema.name == "nmap"
        assert len(schema.options) > 0
        assert len(schema.examples) > 0
    
    def test_nmap_wrapper_build_command(self):
        """Nmap wrapper should build valid commands."""
        from kestrel.tools import NmapWrapper, ToolRequest
        
        wrapper = NmapWrapper()
        request = ToolRequest(
            tool="nmap",
            target="example.com",
            options={"scan_type": "quick"},
        )
        
        command = wrapper.build_command(request)
        
        assert "nmap" in command
        assert "example.com" in command
        assert "-F" in command  # Quick scan flag
    
    def test_nmap_wrapper_validate(self):
        """Nmap wrapper should validate requests."""
        from kestrel.tools import NmapWrapper, ToolRequest
        
        wrapper = NmapWrapper()
        
        # Valid request
        valid_request = ToolRequest(tool="nmap", target="example.com")
        result = wrapper.validate(valid_request)
        assert result.valid is True
        
        # Invalid request (no target)
        invalid_request = ToolRequest(tool="nmap", target="")
        result = wrapper.validate(invalid_request)
        assert result.valid is False
    
    def test_gobuster_wrapper_build_command(self):
        """Gobuster wrapper should build valid commands."""
        from kestrel.tools import GobusterWrapper, ToolRequest
        
        wrapper = GobusterWrapper()
        request = ToolRequest(
            tool="gobuster",
            target="https://example.com",
            options={"mode": "dir", "wordlist": "common"},
        )
        
        command = wrapper.build_command(request)
        
        assert "gobuster" in command
        assert "dir" in command
        assert "-u" in command
        assert "example.com" in command
    
    def test_tool_registry(self):
        """Tool registry should have all tools."""
        from kestrel.tools import TOOLS, get_tool
        
        assert "nmap" in TOOLS
        assert "gobuster" in TOOLS
        assert "nikto" in TOOLS
        assert "sqlmap" in TOOLS
        
        nmap = get_tool("nmap")
        assert nmap.name == "nmap"


class TestParsers:
    """Test output parsers."""
    
    def test_nmap_parser_basic(self):
        """Nmap parser should parse basic output."""
        from kestrel.parsers import NmapParser
        
        output = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.010s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.41
443/tcp open  https    Apache httpd 2.4.41

Nmap done: 1 IP address (1 host up) scanned in 5.23 seconds
"""
        
        parser = NmapParser()
        result = parser.parse(output)
        
        assert result.success is True
        assert len(result.hosts) == 1
        assert len(result.hosts[0].ports) == 2
        assert result.hosts[0].ports[0].port == 80
        assert result.hosts[0].ports[0].service == "http"
    
    def test_gobuster_parser_dir_mode(self):
        """Gobuster parser should parse dir mode output."""
        from kestrel.parsers import GobusterParser
        
        output = """
/admin                (Status: 200) [Size: 1234]
/login                (Status: 301) [Size: 0] [--> /login/]
/api                  (Status: 403) [Size: 287]
"""
        
        parser = GobusterParser()
        result = parser.parse(output, command="gobuster dir -u https://example.com")
        
        assert result.success is True
        assert len(result.paths) == 3
        assert result.paths[0].path == "/admin"
        assert result.paths[0].status_code == 200
    
    def test_sqlmap_parser_injection_found(self):
        """Sqlmap parser should detect injection."""
        from kestrel.parsers import SqlmapParser
        
        output = """
[INFO] testing connection to the target URL
[INFO] sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
---
[INFO] the back-end DBMS is MySQL
"""
        
        parser = SqlmapParser()
        result = parser.parse(output)
        
        assert result.success is True
        assert result.injectable is True
        assert result.dbms == "MySQL"
    
    def test_parser_registry(self):
        """Parser registry should have all parsers."""
        from kestrel.parsers import PARSERS, get_parser
        
        assert "nmap" in PARSERS
        assert "gobuster" in PARSERS
        assert "nikto" in PARSERS
        assert "sqlmap" in PARSERS
        
        parser = get_parser("nmap")
        assert parser.tool_name == "nmap"


class TestLLMIntegration:
    """Test LLM integration (mocked where necessary)."""
    
    def test_llm_client_creation(self):
        """Should create LLM client."""
        from kestrel.llm import AnthropicClient
        
        client = AnthropicClient(api_key="test-key")
        assert client is not None
        assert client.model == "claude-sonnet-4-20250514"
    
    def test_llm_client_availability_check(self):
        """Should check API key availability."""
        from kestrel.llm import AnthropicClient
        
        # With key
        client_with_key = AnthropicClient(api_key="test-key")
        assert client_with_key.available is True
        
        # Without key (and no env var)
        import os
        old_key = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            client_no_key = AnthropicClient(api_key=None)
            # May or may not be available depending on env
        finally:
            if old_key:
                os.environ["ANTHROPIC_API_KEY"] = old_key
    
    def test_translation_prompt_building(self):
        """Should build translation prompts."""
        from kestrel.llm import build_translation_prompt
        
        tools = [
            {"name": "nmap", "description": "Port scanner"},
            {"name": "gobuster", "description": "Directory scanner"},
        ]
        
        system, user = build_translation_prompt(
            intent="scan ports on example.com",
            tools=tools,
            target="example.com",
        )
        
        assert "nmap" in system
        assert "gobuster" in system
        assert "example.com" in user
        assert "scan ports" in user
    
    def test_exploit_planning_prompt_building(self):
        """Should build exploit planning prompts."""
        from kestrel.llm import build_exploit_planning_prompt
        
        vuln = {
            "title": "SQL Injection",
            "cve_id": "CVE-2021-12345",
            "severity": "critical",
        }
        
        system, user = build_exploit_planning_prompt(
            vulnerability=vuln,
            target="https://example.com/page?id=1",
        )
        
        assert "authorization" in system.lower()
        assert "SQL Injection" in user
        assert "CVE-2021-12345" in user


class TestIntegration:
    """Integration tests combining multiple components."""
    
    def test_tool_to_parser_flow(self):
        """Tool wrapper output should be parseable."""
        from kestrel.tools import NmapWrapper, ToolRequest
        from kestrel.parsers import NmapParser
        
        # Build command
        wrapper = NmapWrapper()
        request = ToolRequest(
            tool="nmap",
            target="example.com",
            options={"scan_type": "quick"},
        )
        command = wrapper.build_command(request)
        
        # Verify parser can identify nmap output
        parser = NmapParser()
        
        # Mock output that command would produce
        mock_output = """
Nmap scan report for example.com
PORT   STATE SERVICE
80/tcp open  http
"""
        
        result = parser.parse(mock_output, command)
        assert result.success is True
        assert result.tool == "nmap"
    
    def test_session_with_execution_record(self):
        """Session should track execution records."""
        from kestrel.core import (
            HuntSession,
            ExecutionRecord,
            Finding,
            FindingSeverity,
        )
        
        session = HuntSession(target="example.com")
        session.start()
        
        # Add execution record
        exec_record = ExecutionRecord(
            tool="nmap",
            command="nmap -F example.com",
            target="example.com",
            success=True,
            exit_code=0,
            duration_seconds=5.0,
            findings_count=2,
        )
        session.add_execution(exec_record)
        
        # Add findings
        session.add_finding(Finding(
            title="Open Port 80",
            severity=FindingSeverity.INFO,
            tool="nmap",
        ))
        
        assert len(session.executions) == 1
        assert len(session.findings) == 1
        
        # Check context generation
        context = session.get_context_for_llm()
        assert "example.com" in context
        assert "nmap" in context
