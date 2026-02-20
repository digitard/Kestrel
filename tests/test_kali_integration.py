"""
Kali Integration Tests - OS/Install Layer Validation

These tests require actual Kali Linux with tools installed.
They will be SKIPPED in environments without the required tools.

Run on Kali with:
    pytest tests/test_kali_integration.py -v

To run ALL tests including slow ones:
    pytest tests/test_kali_integration.py -v --run-slow
"""

import pytest
import subprocess
import os
from pathlib import Path
import sys

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# =============================================================================
# Helper Functions
# =============================================================================

def is_kali() -> bool:
    """Check if running on Kali Linux."""
    try:
        with open("/etc/os-release") as f:
            return "kali" in f.read().lower()
    except FileNotFoundError:
        return False


def tool_exists(tool: str) -> bool:
    """Check if a tool is installed."""
    try:
        result = subprocess.run(
            ["which", tool],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def wordlist_exists(path: str) -> bool:
    """Check if a wordlist file exists."""
    return Path(path).exists()


# =============================================================================
# Skip Markers
# =============================================================================

# Skip entire module if not on Kali
pytestmark = pytest.mark.skipif(
    not is_kali(),
    reason="Kali Linux required for integration tests"
)

# Individual tool markers
requires_nmap = pytest.mark.skipif(
    not tool_exists("nmap"),
    reason="nmap not installed"
)

requires_gobuster = pytest.mark.skipif(
    not tool_exists("gobuster"),
    reason="gobuster not installed"
)

requires_nikto = pytest.mark.skipif(
    not tool_exists("nikto"),
    reason="nikto not installed"
)

requires_sqlmap = pytest.mark.skipif(
    not tool_exists("sqlmap"),
    reason="sqlmap not installed"
)

requires_nuclei = pytest.mark.skipif(
    not tool_exists("nuclei"),
    reason="nuclei not installed"
)

# Slow test marker (for tests that take >10 seconds)
# Run with: pytest -m slow  OR  pytest (includes all)
# Skip slow: pytest -m "not slow"
slow_test = pytest.mark.slow


# =============================================================================
# Environment Tests
# =============================================================================

class TestKaliEnvironment:
    """Verify Kali Linux environment."""
    
    def test_is_kali_linux(self):
        """Should be running on Kali Linux."""
        assert is_kali(), "Not running on Kali Linux"
    
    def test_os_release_readable(self):
        """Should be able to read /etc/os-release."""
        assert Path("/etc/os-release").exists()
        
        with open("/etc/os-release") as f:
            content = f.read()
            assert "kali" in content.lower()
    
    def test_python_version(self):
        """Python 3.11+ should be available."""
        import sys
        assert sys.version_info >= (3, 11), f"Python 3.11+ required, got {sys.version}"
    
    def test_home_directory_writable(self):
        """Home directory should be writable."""
        home = Path.home()
        assert home.exists()
        
        test_file = home / ".kestrel_test"
        try:
            test_file.write_text("test")
            assert test_file.exists()
        finally:
            test_file.unlink(missing_ok=True)


class TestToolAvailability:
    """Verify required tools are installed."""
    
    def test_nmap_installed(self):
        """nmap should be installed."""
        assert tool_exists("nmap"), "nmap not found - run: sudo apt install nmap"
    
    def test_gobuster_installed(self):
        """gobuster should be installed."""
        assert tool_exists("gobuster"), "gobuster not found - run: sudo apt install gobuster"
    
    def test_nikto_installed(self):
        """nikto should be installed."""
        assert tool_exists("nikto"), "nikto not found - run: sudo apt install nikto"
    
    def test_sqlmap_installed(self):
        """sqlmap should be installed."""
        assert tool_exists("sqlmap"), "sqlmap not found - run: sudo apt install sqlmap"
    
    def test_curl_installed(self):
        """curl should be installed."""
        assert tool_exists("curl"), "curl not found - run: sudo apt install curl"
    
    def test_wget_installed(self):
        """wget should be installed."""
        assert tool_exists("wget"), "wget not found - run: sudo apt install wget"
    
    def test_jq_installed(self):
        """jq should be installed (optional, for JSON parsing)."""
        if not tool_exists("jq"):
            pytest.skip("jq not installed - optional, run: sudo apt install jq")
        assert tool_exists("jq")


class TestWordlists:
    """Verify wordlist files exist."""
    
    WORDLISTS = {
        "dirb_common": "/usr/share/wordlists/dirb/common.txt",
        "dirb_small": "/usr/share/wordlists/dirb/small.txt",
        "dirb_big": "/usr/share/wordlists/dirb/big.txt",
        "dirbuster_small": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "dirbuster_medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    }
    
    def test_dirb_common_wordlist(self):
        """dirb common.txt should exist."""
        path = self.WORDLISTS["dirb_common"]
        assert Path(path).exists(), f"Wordlist not found: {path}"
    
    def test_dirb_small_wordlist(self):
        """dirb small.txt should exist."""
        path = self.WORDLISTS["dirb_small"]
        assert Path(path).exists(), f"Wordlist not found: {path}"
    
    def test_dirbuster_small_wordlist(self):
        """dirbuster small wordlist should exist."""
        path = self.WORDLISTS["dirbuster_small"]
        assert Path(path).exists(), f"Wordlist not found: {path}"
    
    def test_wordlists_readable(self):
        """Wordlists should be readable."""
        for name, path in self.WORDLISTS.items():
            if Path(path).exists():
                # Try to read first line
                with open(path) as f:
                    first_line = f.readline()
                    assert len(first_line) > 0, f"Wordlist {name} appears empty"


# =============================================================================
# Tool Execution Tests
# =============================================================================

class TestNmapExecution:
    """Test actual nmap execution."""
    
    @requires_nmap
    def test_nmap_version(self):
        """nmap --version should work."""
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        assert result.returncode == 0
        assert "Nmap" in result.stdout
    
    @requires_nmap
    def test_nmap_help(self):
        """nmap --help should show usage."""
        result = subprocess.run(
            ["nmap", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        # nmap --help returns non-zero but outputs help
        assert "TARGET SPECIFICATION" in result.stdout or "usage" in result.stdout.lower()
    
    @requires_nmap
    def test_nmap_scan_localhost(self):
        """nmap should be able to scan localhost."""
        from kestrel.core import NativeExecutor
        from kestrel.parsers import NmapParser
        
        executor = NativeExecutor()
        result = executor.execute("nmap -F 127.0.0.1", timeout=30)
        
        assert result.success, f"nmap failed: {result.stderr}"
        assert "Nmap scan report" in result.stdout
        
        # Parse the output
        parser = NmapParser()
        parsed = parser.parse(result.stdout, result.command)
        
        assert parsed.success
        assert len(parsed.hosts) >= 1
        assert parsed.hosts[0].ip == "127.0.0.1"
    
    @requires_nmap
    @slow_test
    def test_nmap_service_detection_localhost(self):
        """nmap -sV should detect services on localhost."""
        from kestrel.core import NativeExecutor
        from kestrel.parsers import NmapParser
        
        executor = NativeExecutor()
        result = executor.execute("nmap -sV -F 127.0.0.1", timeout=60)
        
        assert result.success
        
        parser = NmapParser()
        parsed = parser.parse(result.stdout)
        
        # Should have at least identified some services
        if parsed.hosts and parsed.hosts[0].ports:
            for port in parsed.hosts[0].ports:
                # Service detection should populate service field
                assert port.service is not None or port.state == "closed"


class TestGobusterExecution:
    """Test actual gobuster execution."""
    
    @requires_gobuster
    def test_gobuster_version(self):
        """gobuster should report its version."""
        # gobuster doesn't have a traditional --version flag
        # Check that it runs and outputs something useful
        result = subprocess.run(
            ["gobuster", "-h"],
            capture_output=True,
            text=True,
            timeout=10
        )
        assert result.returncode == 0
        assert "gobuster" in result.stdout.lower() or "usage" in result.stdout.lower()
    
    @requires_gobuster
    def test_gobuster_help(self):
        """gobuster --help should show usage."""
        result = subprocess.run(
            ["gobuster", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        assert result.returncode == 0
        assert "dir" in result.stdout  # Should mention dir mode
    
    @requires_gobuster
    def test_gobuster_wrapper_command_valid(self):
        """Gobuster wrapper should produce valid command syntax."""
        from kestrel.tools import GobusterWrapper, ToolRequest
        
        wrapper = GobusterWrapper()
        request = ToolRequest(
            tool="gobuster",
            target="http://127.0.0.1",
            options={"mode": "dir", "wordlist": "small"},
        )
        
        command = wrapper.build_command(request)
        
        # Verify the wordlist path exists
        assert "/usr/share/wordlists/dirb/small.txt" in command
        assert Path("/usr/share/wordlists/dirb/small.txt").exists()


class TestNiktoExecution:
    """Test actual nikto execution."""
    
    @requires_nikto
    def test_nikto_version(self):
        """nikto -Version should work."""
        result = subprocess.run(
            ["nikto", "-Version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        # nikto -Version outputs to stderr
        output = result.stdout + result.stderr
        assert "Nikto" in output or "nikto" in output.lower()
    
    @requires_nikto
    def test_nikto_help(self):
        """nikto -Help should show options."""
        result = subprocess.run(
            ["nikto", "-Help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout + result.stderr
        assert "-host" in output.lower() or "-h" in output


class TestSqlmapExecution:
    """Test actual sqlmap execution."""
    
    @requires_sqlmap
    def test_sqlmap_version(self):
        """sqlmap --version should work."""
        result = subprocess.run(
            ["sqlmap", "--version"],
            capture_output=True,
            text=True,
            timeout=30  # sqlmap can be slow to start
        )
        assert result.returncode == 0
        # sqlmap outputs just the version number like "1.9.11#stable"
        assert len(result.stdout.strip()) > 0
    
    @requires_sqlmap
    def test_sqlmap_help(self):
        """sqlmap --help should show usage."""
        result = subprocess.run(
            ["sqlmap", "-h"],
            capture_output=True,
            text=True,
            timeout=30  # sqlmap can be slow to start
        )
        assert result.returncode == 0
        assert "target" in result.stdout.lower()


# =============================================================================
# Integration Tests with Kestrel
# =============================================================================

class TestExecutorWithRealTools:
    """Test NativeExecutor with actual Kali tools."""
    
    def test_executor_check_real_tools(self):
        """Executor should correctly detect installed tools."""
        from kestrel.core import NativeExecutor
        
        executor = NativeExecutor()
        
        # These should be true on Kali
        if tool_exists("nmap"):
            assert executor.check_tool("nmap") is True
        
        if tool_exists("gobuster"):
            assert executor.check_tool("gobuster") is True
        
        # This should always be false
        assert executor.check_tool("nonexistent_fake_tool_xyz") is False
    
    def test_executor_get_tool_versions(self):
        """Executor should retrieve tool versions."""
        from kestrel.core import NativeExecutor
        
        executor = NativeExecutor()
        
        if tool_exists("nmap"):
            version = executor.get_tool_version("nmap")
            assert version is not None
            assert "nmap" in version.lower() or version != "version unknown"
        
        if tool_exists("curl"):
            version = executor.get_tool_version("curl")
            assert version is not None
    
    @requires_nmap
    def test_executor_execute_tool_method(self):
        """execute_tool should work with real tools."""
        from kestrel.core import NativeExecutor, ExecutionStatus
        
        executor = NativeExecutor()
        result = executor.execute_tool(
            "nmap",
            ["--version"],
            timeout=10
        )
        
        assert result.status == ExecutionStatus.COMPLETED
        assert result.success is True
        assert "Nmap" in result.stdout


class TestKaliEnvironmentCheck:
    """Test the check_kali_environment function."""
    
    def test_environment_check_returns_dict(self):
        """check_kali_environment should return proper structure."""
        from kestrel.core import check_kali_environment
        
        result = check_kali_environment()
        
        assert isinstance(result, dict)
        assert "is_kali" in result
        assert "tools" in result
        assert "missing_tools" in result
        assert "ready" in result
    
    def test_environment_check_detects_kali(self):
        """Should correctly identify Kali Linux."""
        from kestrel.core import check_kali_environment
        
        result = check_kali_environment()
        
        assert result["is_kali"] is True
    
    def test_environment_check_finds_tools(self):
        """Should find installed tools."""
        from kestrel.core import check_kali_environment
        
        result = check_kali_environment()
        
        # Check that tools dict has entries
        assert len(result["tools"]) > 0
        
        # nmap should be detected if installed
        if tool_exists("nmap"):
            assert result["tools"]["nmap"]["available"] is True
            assert result["tools"]["nmap"]["path"] is not None


class TestToolcheckScript:
    """Test the toolcheck.sh script."""
    
    def test_toolcheck_exists(self):
        """toolcheck.sh should exist in project root."""
        project_root = Path(__file__).parent.parent
        toolcheck = project_root / "toolcheck.sh"
        
        assert toolcheck.exists(), "toolcheck.sh not found"
        assert os.access(toolcheck, os.X_OK), "toolcheck.sh not executable"
    
    def test_toolcheck_runs(self):
        """toolcheck.sh should run without errors."""
        project_root = Path(__file__).parent.parent
        toolcheck = project_root / "toolcheck.sh"
        
        result = subprocess.run(
            [str(toolcheck)],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(project_root)
        )
        
        # Should output something
        output = result.stdout + result.stderr
        assert len(output) > 0
        
        # Should mention Kestrel
        assert "Kestrel" in output or "kestrel" in output.lower()


# =============================================================================
# Summary Report
# =============================================================================

class TestSummary:
    """Generate a summary of the Kali environment."""
    
    def test_print_environment_summary(self, capsys):
        """Print environment summary (always passes, for info)."""
        from kestrel.core import check_kali_environment
        
        result = check_kali_environment()
        
        print("\n" + "="*60)
        print("KALI ENVIRONMENT SUMMARY")
        print("="*60)
        print(f"Is Kali: {result['is_kali']}")
        print(f"Ready: {result['ready']}")
        print(f"\nTools:")
        
        for tool, info in result["tools"].items():
            status = "✓" if info["available"] else "✗"
            version = info.get("version", "N/A") if info["available"] else "not installed"
            print(f"  {status} {tool}: {version}")
        
        if result["missing_tools"]:
            print(f"\nMissing tools: {', '.join(result['missing_tools'])}")
            print("Install with: sudo apt install " + " ".join(result["missing_tools"]))
        
        print("="*60)
        
        # Always pass - this is informational
        assert True
