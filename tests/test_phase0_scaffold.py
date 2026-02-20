"""
Phase 0 Tests - Project Scaffold Validation

These tests verify the project structure is correctly established
before proceeding to Phase 1.
"""

import pytest
from pathlib import Path
import sys
import os


class TestProjectStructure:
    """Verify all required directories and files exist."""
    
    @pytest.fixture
    def project_root(self) -> Path:
        """Get project root directory."""
        # Navigate from tests/ to project root
        return Path(__file__).parent.parent
    
    def test_root_files_exist(self, project_root: Path):
        """Required root-level files must exist."""
        required_files = [
            "PROJECT_DOCUMENTATION.md",
            "PROJECT_JOURNAL.md",
            "VERSION",
            "README.md",
            "pyproject.toml",
            "toolcheck.sh",
        ]
        
        for filename in required_files:
            filepath = project_root / filename
            assert filepath.exists(), f"Missing required file: {filename}"
    
    def test_config_directory_exists(self, project_root: Path):
        """Config directory with default.yaml must exist."""
        config_dir = project_root / "config"
        assert config_dir.is_dir(), "Missing config/ directory"
        
        default_config = config_dir / "default.yaml"
        assert default_config.exists(), "Missing config/default.yaml"
    
    def test_package_structure_exists(self, project_root: Path):
        """Main package directories must exist."""
        package_root = project_root / "kestrel"
        assert package_root.is_dir(), "Missing kestrel/ package directory"
        
        required_modules = [
            "core",
            "tools",
            "parsers",
            "platforms",
            "hunting",
            "llm",
            "reports",
            "api",
            "api/routes",
            "web",
            "db",
        ]
        
        for module in required_modules:
            module_path = package_root / module
            assert module_path.is_dir(), f"Missing module directory: kestrel/{module}"
            
            # Each module should have __init__.py
            init_file = module_path / "__init__.py"
            assert init_file.exists(), f"Missing __init__.py in kestrel/{module}"
    
    def test_test_structure_exists(self, project_root: Path):
        """Test directories must exist."""
        tests_dir = project_root / "tests"
        assert tests_dir.is_dir(), "Missing tests/ directory"
        
        required_test_dirs = [
            "test_core",
            "test_tools",
            "test_parsers",
            "test_platforms",
            "test_hunting",
            "test_llm",
            "test_api",
            "fixtures",
        ]
        
        for test_dir in required_test_dirs:
            dir_path = tests_dir / test_dir
            assert dir_path.is_dir(), f"Missing test directory: tests/{test_dir}"
    
    def test_scripts_are_executable(self, project_root: Path):
        """Shell scripts should be executable."""
        scripts = ["toolcheck.sh"]
        
        for script in scripts:
            script_path = project_root / script
            assert script_path.exists(), f"Missing script: {script}"
            assert os.access(script_path, os.X_OK), f"Script not executable: {script}"


class TestVersionFile:
    """Verify VERSION file format and content."""
    
    @pytest.fixture
    def project_root(self) -> Path:
        return Path(__file__).parent.parent
    
    def test_version_file_readable(self, project_root: Path):
        """VERSION file should be readable."""
        version_file = project_root / "VERSION"
        content = version_file.read_text().strip()
        assert len(content) > 0, "VERSION file is empty"
    
    def test_version_format_valid(self, project_root: Path):
        """VERSION should match AA.BB.CC.DD format."""
        version_file = project_root / "VERSION"
        content = version_file.read_text().strip()
        
        parts = content.split(".")
        assert len(parts) == 4, f"VERSION should have 4 parts (AA.BB.CC.DD), got: {content}"
        
        for i, part in enumerate(parts):
            assert part.isdigit(), f"VERSION part {i+1} should be numeric, got: {part}"
    
    def test_version_is_valid_format(self, project_root: Path):
        """VERSION should be valid AA.BB.CC.DD format."""
        version_file = project_root / "VERSION"
        content = version_file.read_text().strip()
        
        parts = content.split(".")
        assert parts[0] == "0" or parts[0] == "1", f"Major version should be 0 or 1 during development, got: {parts[0]}"
        # Phase can be any valid number now
        assert parts[1].isdigit(), f"Phase version should be numeric, got: {parts[1]}"


class TestPackageImports:
    """Verify the package can be imported."""
    
    @pytest.fixture(autouse=True)
    def setup_path(self):
        """Add project to path for imports."""
        project_root = Path(__file__).parent.parent
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
    
    def test_main_package_imports(self):
        """Main package should import without errors."""
        import kestrel
        assert hasattr(kestrel, "__version__")
        assert hasattr(kestrel, "get_version")
        assert hasattr(kestrel, "get_version_info")
    
    def test_version_matches_file(self):
        """Package version should match VERSION file."""
        import kestrel
        
        project_root = Path(__file__).parent.parent
        version_file = project_root / "VERSION"
        file_version = version_file.read_text().strip()
        
        assert kestrel.__version__ == file_version, \
            f"Package version ({kestrel.__version__}) != VERSION file ({file_version})"
    
    def test_version_info_structure(self):
        """get_version_info should return proper structure."""
        import kestrel
        
        info = kestrel.get_version_info()
        
        assert isinstance(info, dict), "get_version_info should return dict"
        assert "version" in info
        assert "major" in info
        assert "phase" in info
        assert "feature" in info
        assert "build" in info
        
        # Development version checks (major should be 0 or 1)
        assert info["major"] in (0, 1), f"Major should be 0 or 1 during dev, got {info['major']}"
        assert isinstance(info["phase"], int), "Phase should be an integer"


class TestConfigFile:
    """Verify configuration file is valid."""
    
    @pytest.fixture
    def project_root(self) -> Path:
        return Path(__file__).parent.parent
    
    def test_config_is_valid_yaml(self, project_root: Path):
        """Config file should be valid YAML."""
        import yaml
        
        config_path = project_root / "config" / "default.yaml"
        content = config_path.read_text()
        
        # Should not raise
        config = yaml.safe_load(content)
        assert isinstance(config, dict), "Config should be a dictionary"
    
    def test_config_has_required_sections(self, project_root: Path):
        """Config should have all required sections."""
        import yaml
        
        config_path = project_root / "config" / "default.yaml"
        config = yaml.safe_load(config_path.read_text())
        
        required_sections = [
            "app",
            "server",
            "database",
            "platforms",
            "llm",
            "cve",
            "hunting",
            "scope",
            "authorization",
            "audit",
            "reports",
            "evidence",
        ]
        
        for section in required_sections:
            assert section in config, f"Missing config section: {section}"
    
    def test_safety_defaults_are_safe(self, project_root: Path):
        """Critical safety settings should default to safe values."""
        import yaml
        
        config_path = project_root / "config" / "default.yaml"
        config = yaml.safe_load(config_path.read_text())
        
        # Authorization must be required
        assert config["authorization"]["require_authorization"] is True, \
            "authorization.require_authorization MUST default to true"
        
        # Scope must fail closed
        assert config["scope"]["fail_closed"] is True, \
            "scope.fail_closed MUST default to true"
        
        # Scope revalidation must be enabled
        assert config["scope"]["revalidate_before_exec"] is True, \
            "scope.revalidate_before_exec MUST default to true"
        
        # Audit must be enabled
        assert config["audit"]["enabled"] is True, \
            "audit.enabled MUST default to true"


class TestDocumentation:
    """Verify documentation is present and meaningful."""
    
    @pytest.fixture
    def project_root(self) -> Path:
        return Path(__file__).parent.parent
    
    def test_project_documentation_has_content(self, project_root: Path):
        """PROJECT_DOCUMENTATION.md should have substantial content."""
        doc_path = project_root / "PROJECT_DOCUMENTATION.md"
        content = doc_path.read_text()
        
        # Should be substantial
        assert len(content) > 5000, "PROJECT_DOCUMENTATION.md seems too short"
        
        # Should have key sections
        assert "## Phase Plan" in content or "## Phase" in content, \
            "PROJECT_DOCUMENTATION.md should document phases"
        assert "Version" in content, \
            "PROJECT_DOCUMENTATION.md should mention versioning"
    
    def test_project_journal_exists_with_entry(self, project_root: Path):
        """PROJECT_JOURNAL.md should have at least the initial entry."""
        journal_path = project_root / "PROJECT_JOURNAL.md"
        content = journal_path.read_text()
        
        # Should have version 0.0.0.1 entry
        assert "0.0.0.1" in content, \
            "PROJECT_JOURNAL.md should have v0.0.0.1 entry"
    
    def test_readme_has_content(self, project_root: Path):
        """README.md should exist with useful content."""
        readme_path = project_root / "README.md"
        content = readme_path.read_text()
        
        assert len(content) > 500, "README.md seems too short"
        assert "Kestrel" in content, "README should mention project name"
