"""
Phase 1.1 Tests - Tool Registry

Tests for:
- ToolRegistry creation and initialization
- Tier 1 (wrapped) tool registration
- Tier 2 (discovered) tool registration
- System discovery
- Lookup methods (by category, capability, tier)
- Safety classification (authorization requirements)
- LLM context generation
- Serialization
- Global registry singleton
- Helper functions (version, help extraction, flag parsing)
"""

import pytest
from pathlib import Path
import sys
import shutil

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestToolRegistryCreation:
    """Test basic registry creation and state."""

    def test_create_empty_registry(self):
        """Should create an empty registry."""
        from kestrel.tools.registry import ToolRegistry

        registry = ToolRegistry()

        assert registry.tool_count == 0
        assert registry.available_count == 0
        assert registry.discovered is False

    def test_registry_starts_undiscovered(self):
        """Registry should not be discovered until discover() is called."""
        from kestrel.tools.registry import ToolRegistry

        registry = ToolRegistry()
        assert registry.discovered is False


class TestWrappedToolRegistration:
    """Test Tier 1 (wrapped) tool registration."""

    def test_register_nmap_wrapper(self):
        """Should register nmap as a wrapped tool."""
        from kestrel.tools.registry import ToolRegistry, ToolTier
        from kestrel.tools import NmapWrapper

        registry = ToolRegistry()
        info = registry.register_wrapped_tool(NmapWrapper(), has_parser=True)

        assert info.name == "nmap"
        assert info.tier == ToolTier.WRAPPED
        assert info.has_parser is True
        assert info.wrapper_class == NmapWrapper

    def test_register_all_wrapped_tools(self):
        """Should register all four wrapped tools."""
        from kestrel.tools.registry import ToolRegistry, ToolTier
        from kestrel.tools import NmapWrapper, GobusterWrapper, NiktoWrapper, SqlmapWrapper

        registry = ToolRegistry()
        wrappers = [NmapWrapper(), GobusterWrapper(), NiktoWrapper(), SqlmapWrapper()]

        for w in wrappers:
            registry.register_wrapped_tool(w, has_parser=True)

        assert registry.tool_count == 4

        for w in wrappers:
            info = registry.get(w.name)
            assert info is not None
            assert info.tier == ToolTier.WRAPPED

    def test_wrapped_tool_has_known_metadata(self):
        """Wrapped tools should pick up metadata from KNOWN_TOOLS."""
        from kestrel.tools.registry import ToolRegistry, ToolCapability
        from kestrel.tools import NmapWrapper

        registry = ToolRegistry()
        info = registry.register_wrapped_tool(NmapWrapper())

        assert len(info.capabilities) > 0
        assert ToolCapability.PORT_SCAN in info.capabilities

    def test_wrapped_sqlmap_requires_auth(self):
        """SQLmap should be marked as requiring authorization."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools import SqlmapWrapper

        registry = ToolRegistry()
        info = registry.register_wrapped_tool(SqlmapWrapper())

        assert info.requires_authorization is True
        assert info.can_modify_target is True
        assert info.is_passive is False


class TestDiscoveredToolRegistration:
    """Test Tier 2 (discovered) tool registration."""

    def test_register_discovered_tool(self):
        """Should register a tool found on the system."""
        from kestrel.tools.registry import ToolRegistry, ToolTier

        registry = ToolRegistry()

        # echo exists on all systems
        info = registry.register_discovered_tool("echo", probe_help=False)

        assert info.name == "echo"
        assert info.tier == ToolTier.DISCOVERED
        assert info.available is True

    def test_register_known_discovered_tool(self):
        """Discovered tool in KNOWN_TOOLS should get pre-defined metadata."""
        from kestrel.tools.registry import ToolRegistry, KNOWN_TOOLS

        registry = ToolRegistry()

        # curl is in KNOWN_TOOLS and likely installed
        if shutil.which("curl"):
            info = registry.register_discovered_tool("curl", probe_help=False)

            assert info.description == KNOWN_TOOLS["curl"]["description"]
            assert len(info.capabilities) > 0

    def test_register_unknown_tool_gets_defaults(self):
        """Unknown tools should get default metadata."""
        from kestrel.tools.registry import ToolRegistry, ToolCategory

        registry = ToolRegistry()
        info = registry.register_discovered_tool("echo", probe_help=False)

        # echo is not in KNOWN_TOOLS, should get defaults
        assert info.category == ToolCategory.UTILITY


class TestSystemDiscovery:
    """Test full system tool discovery."""

    def test_discovery_runs(self):
        """Discovery should run without errors."""
        from kestrel.tools.registry import ToolRegistry

        registry = ToolRegistry()
        result = registry.discover(probe_help=False)

        assert registry.discovered is True
        assert "found" in result
        assert "not_found" in result
        assert "total_registered" in result
        assert "discovery_time_seconds" in result

    def test_discovery_finds_common_tools(self):
        """Should find at least curl/wget on most systems."""
        from kestrel.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.discover(probe_help=False)

        # At least one common tool should exist
        common_tools = ["curl", "wget", "echo"]
        found_any = any(registry.has_tool(t) for t in common_tools)
        assert found_any, "Should find at least one common tool"

    def test_discovery_preserves_wrapped_tools(self):
        """Discovery should not overwrite wrapped tool registrations."""
        from kestrel.tools.registry import ToolRegistry, ToolTier
        from kestrel.tools import NmapWrapper

        registry = ToolRegistry()
        registry.register_wrapped_tool(NmapWrapper(), has_parser=True)
        registry.discover(probe_help=False)

        nmap = registry.get("nmap")
        if nmap:
            assert nmap.tier == ToolTier.WRAPPED
            assert nmap.has_parser is True

    def test_discovery_with_extra_tools(self):
        """Should check extra tools beyond KNOWN_TOOLS."""
        from kestrel.tools.registry import ToolRegistry

        registry = ToolRegistry()
        result = registry.discover(
            probe_help=False,
            extra_tools=["echo", "cat", "ls"],
        )

        # These basic tools should be found
        assert registry.has_tool("echo") or registry.has_tool("cat")

    def test_discovery_summary(self):
        """Summary should reflect discovered state."""
        from kestrel.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.discover(probe_help=False)

        summary = registry.summary()
        assert "total_registered" in summary
        assert "available" in summary
        assert "by_tier" in summary
        assert "by_category" in summary
        assert summary["available"] > 0


class TestLookupMethods:
    """Test registry query/lookup methods."""

    def _make_registry(self):
        """Create a registry with wrapped tools + discovery."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools import NmapWrapper, GobusterWrapper, NiktoWrapper, SqlmapWrapper

        registry = ToolRegistry()
        for w in [NmapWrapper(), GobusterWrapper(), NiktoWrapper(), SqlmapWrapper()]:
            registry.register_wrapped_tool(w, has_parser=True)
        registry.discover(probe_help=False)
        return registry

    def test_get_existing_tool(self):
        """Should return ToolInfo for registered tools."""
        registry = self._make_registry()
        info = registry.get("nmap")

        # nmap may or may not be installed in this env
        assert info is not None
        assert info.name == "nmap"

    def test_get_nonexistent_tool(self):
        """Should return None for unknown tools."""
        registry = self._make_registry()
        assert registry.get("totally_fake_tool_xyz") is None

    def test_get_all(self):
        """Should return all registered tools."""
        registry = self._make_registry()
        all_tools = registry.get_all()

        assert len(all_tools) > 0
        assert len(all_tools) == registry.tool_count

    def test_get_available(self):
        """Should only return tools that are installed."""
        registry = self._make_registry()
        available = registry.get_available()

        for tool in available:
            assert tool.available is True

    def test_get_by_tier_wrapped(self):
        """Should filter to wrapped tools."""
        from kestrel.tools.registry import ToolTier

        registry = self._make_registry()
        wrapped = registry.get_by_tier(ToolTier.WRAPPED)

        for tool in wrapped:
            assert tool.tier == ToolTier.WRAPPED

    def test_get_by_category(self):
        """Should filter by category."""
        from kestrel.tools.base import ToolCategory

        registry = self._make_registry()
        recon = registry.get_by_category(ToolCategory.RECON)

        for tool in recon:
            assert tool.category == ToolCategory.RECON

    def test_get_by_capability(self):
        """Should filter by capability."""
        from kestrel.tools.registry import ToolCapability

        registry = self._make_registry()
        scanners = registry.get_by_capability(ToolCapability.PORT_SCAN)

        for tool in scanners:
            assert ToolCapability.PORT_SCAN in tool.capabilities

    def test_get_passive_tools(self):
        """Should return only passive tools."""
        registry = self._make_registry()
        passive = registry.get_passive_tools()

        for tool in passive:
            assert tool.is_passive is True

    def test_get_exploit_tools(self):
        """Should return tools requiring authorization."""
        registry = self._make_registry()
        exploit = registry.get_exploit_tools()

        for tool in exploit:
            assert tool.requires_authorization is True

    def test_has_tool(self):
        """has_tool should check both registration and availability."""
        from kestrel.tools.registry import ToolRegistry

        registry = ToolRegistry()
        # echo exists on all systems
        registry.register_discovered_tool("echo", probe_help=False)

        assert registry.has_tool("echo") is True
        assert registry.has_tool("fake_tool_xyz") is False


class TestSafetyClassification:
    """Test authorization and safety checks."""

    def test_unknown_tool_requires_auth(self):
        """Unknown tools should require auth (fail-closed)."""
        from kestrel.tools.registry import ToolRegistry

        registry = ToolRegistry()
        assert registry.requires_auth("completely_unknown_tool") is True

    def test_nmap_no_auth(self):
        """Nmap (recon) should not require auth."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools import NmapWrapper

        registry = ToolRegistry()
        registry.register_wrapped_tool(NmapWrapper())

        assert registry.requires_auth("nmap") is False

    def test_sqlmap_requires_auth(self):
        """SQLmap (exploit) should require auth."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools import SqlmapWrapper

        registry = ToolRegistry()
        registry.register_wrapped_tool(SqlmapWrapper())

        assert registry.requires_auth("sqlmap") is True

    def test_known_exploit_tools_flagged(self):
        """All tools in KNOWN_TOOLS marked requires_authorization should be flagged."""
        from kestrel.tools.registry import KNOWN_TOOLS

        exploit_tools = [
            name for name, meta in KNOWN_TOOLS.items()
            if meta.get("requires_authorization", False)
        ]

        # Ensure we have defined some exploit tools
        assert len(exploit_tools) > 0, "Should have exploit tools defined"

        # Each should be marked correctly
        for name in exploit_tools:
            assert KNOWN_TOOLS[name]["can_modify_target"] is True or \
                   KNOWN_TOOLS[name]["requires_authorization"] is True


class TestLLMContextGeneration:
    """Test LLM context string generation."""

    def _make_registry(self):
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools import NmapWrapper, GobusterWrapper, NiktoWrapper, SqlmapWrapper

        registry = ToolRegistry()
        for w in [NmapWrapper(), GobusterWrapper(), NiktoWrapper(), SqlmapWrapper()]:
            registry.register_wrapped_tool(w, has_parser=True)
        registry.discover(probe_help=False)
        return registry

    def test_build_llm_context(self):
        """Should generate non-empty context string."""
        registry = self._make_registry()
        context = registry.build_llm_context()

        assert len(context) > 0
        assert "Available Security Tools" in context

    def test_llm_context_includes_legend(self):
        """Context should include tier legend."""
        registry = self._make_registry()
        context = registry.build_llm_context()

        assert "★" in context or "○" in context
        assert "REQUIRES_AUTH" in context or "Legend" in context

    def test_llm_context_category_filter(self):
        """Should filter context by category."""
        from kestrel.tools.base import ToolCategory

        registry = self._make_registry()
        context = registry.build_llm_context(
            categories=[ToolCategory.RECON]
        )

        assert len(context) > 0

    def test_llm_context_capability_filter(self):
        """Should filter context by capability."""
        from kestrel.tools.registry import ToolCapability

        registry = self._make_registry()
        context = registry.build_llm_context(
            capabilities=[ToolCapability.PORT_SCAN]
        )

        assert len(context) > 0

    def test_build_tool_selection_prompt(self):
        """Should generate a tool selection prompt."""
        registry = self._make_registry()
        prompt = registry.build_tool_selection_prompt(
            "Scan the target for open ports and running services"
        )

        assert "Scan the target" in prompt
        assert "Available Security Tools" in prompt

    def test_tool_info_to_llm_context(self):
        """Individual ToolInfo should generate context string."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools import NmapWrapper

        registry = ToolRegistry()
        info = registry.register_wrapped_tool(NmapWrapper())

        context = info.to_llm_context()
        assert "nmap" in context
        assert "Tool:" in context

    def test_tool_info_to_llm_context_with_help(self):
        """ToolInfo context with help should include help excerpt."""
        from kestrel.tools.registry import ToolInfo, ToolTier, ToolCategory

        info = ToolInfo(
            name="test_tool",
            tier=ToolTier.DISCOVERED,
            available=True,
            help_text="This is a test tool that does testing things\nUsage: test_tool <args>",
        )

        context = info.to_llm_context(include_help=True)
        assert "Help excerpt" in context


class TestSerialization:
    """Test registry serialization."""

    def test_to_dict(self):
        """Should serialize registry to dict."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools import NmapWrapper

        registry = ToolRegistry()
        registry.register_wrapped_tool(NmapWrapper())

        data = registry.to_dict()

        assert "discovered" in data
        assert "tools" in data
        assert "nmap" in data["tools"]

    def test_tool_info_to_dict(self):
        """ToolInfo should serialize to dict."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools import NmapWrapper

        registry = ToolRegistry()
        info = registry.register_wrapped_tool(NmapWrapper())

        data = info.to_dict()

        assert data["name"] == "nmap"
        assert data["tier"] == "wrapped"
        assert data["has_wrapper"] is True
        assert "capabilities" in data
        assert isinstance(data["capabilities"], list)

    def test_summary(self):
        """Summary should contain expected keys."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools import NmapWrapper

        registry = ToolRegistry()
        registry.register_wrapped_tool(NmapWrapper())

        summary = registry.summary()

        assert "total_registered" in summary
        assert "by_tier" in summary
        assert "by_category" in summary
        assert summary["total_registered"] == 1


class TestGlobalRegistry:
    """Test global singleton registry."""

    def test_get_registry_returns_instance(self):
        """get_registry should return a ToolRegistry."""
        from kestrel.tools.registry import get_registry, reset_registry, ToolRegistry

        reset_registry()
        registry = get_registry()

        assert isinstance(registry, ToolRegistry)

    def test_get_registry_is_singleton(self):
        """get_registry should return the same instance."""
        from kestrel.tools.registry import get_registry, reset_registry

        reset_registry()
        r1 = get_registry()
        r2 = get_registry()

        assert r1 is r2

    def test_get_registry_has_wrapped_tools(self):
        """Global registry should have wrapped tools registered."""
        from kestrel.tools.registry import get_registry, reset_registry, ToolTier

        reset_registry()
        registry = get_registry()

        wrapped = registry.get_by_tier(ToolTier.WRAPPED)
        # Even if tools aren't installed, they should be registered
        wrapped_names = {t.name for t in registry.get_all() if t.tier == ToolTier.WRAPPED}

        assert "nmap" in wrapped_names
        assert "gobuster" in wrapped_names
        assert "nikto" in wrapped_names
        assert "sqlmap" in wrapped_names

    def test_get_registry_is_discovered(self):
        """Global registry should have run discovery."""
        from kestrel.tools.registry import get_registry, reset_registry

        reset_registry()
        registry = get_registry()

        assert registry.discovered is True

    def test_reset_registry(self):
        """reset_registry should clear the singleton."""
        from kestrel.tools.registry import get_registry, reset_registry

        reset_registry()
        r1 = get_registry()
        reset_registry()
        r2 = get_registry()

        assert r1 is not r2


class TestHelperFunctions:
    """Test module-level helper functions."""

    def test_extract_version_echo(self):
        """Should handle tools that don't have --version gracefully."""
        from kestrel.tools.registry import _extract_version

        # ls should return something or None, not crash
        result = _extract_version("ls")
        # Just assert it doesn't raise
        assert result is None or isinstance(result, str)

    def test_extract_help_text(self):
        """Should extract help text from a tool."""
        from kestrel.tools.registry import _extract_help_text

        # ls --help should work on most systems
        result = _extract_help_text("ls")
        assert result is None or len(result) > 0

    def test_parse_common_flags(self):
        """Should parse flags from help text."""
        from kestrel.tools.registry import _parse_common_flags

        help_text = """Usage: tool [options] target

Options:
  -p, --port PORT    Port to scan
  -t, --threads N    Number of threads
  -o FILE            Output file
  --verbose          Enable verbose output
  -h, --help         Show this help
"""
        flags = _parse_common_flags(help_text)

        assert len(flags) > 0
        flag_names = [f["flag"] for f in flags]
        # Should find at least some of these
        assert any("--port" in f or "-p" in f for f in flag_names)

    def test_parse_common_flags_empty(self):
        """Should handle empty help text."""
        from kestrel.tools.registry import _parse_common_flags

        flags = _parse_common_flags("")
        assert flags == []

    def test_extract_usage_hint(self):
        """Should extract usage line from help text."""
        from kestrel.tools.registry import _extract_usage_hint

        help_text = """Some tool v1.0

Usage: sometool [options] <target>

Options:
  -h  help
"""
        usage = _extract_usage_hint(help_text)
        assert "sometool" in usage

    def test_extract_usage_hint_missing(self):
        """Should return empty string if no usage line found."""
        from kestrel.tools.registry import _extract_usage_hint

        usage = _extract_usage_hint("no usage line here\njust text")
        assert usage == ""


class TestKnownToolsIntegrity:
    """Validate the KNOWN_TOOLS definitions."""

    def test_known_tools_have_required_fields(self):
        """All entries in KNOWN_TOOLS should have required metadata."""
        from kestrel.tools.registry import KNOWN_TOOLS

        required_fields = ["description", "category", "capabilities"]

        for name, meta in KNOWN_TOOLS.items():
            for field in required_fields:
                assert field in meta, f"{name} missing required field: {field}"

    def test_known_tools_categories_valid(self):
        """All categories in KNOWN_TOOLS should be valid ToolCategory values."""
        from kestrel.tools.registry import KNOWN_TOOLS
        from kestrel.tools.base import ToolCategory

        valid_categories = set(ToolCategory)
        for name, meta in KNOWN_TOOLS.items():
            assert meta["category"] in valid_categories, \
                f"{name} has invalid category: {meta['category']}"

    def test_known_tools_capabilities_valid(self):
        """All capabilities should be valid ToolCapability values."""
        from kestrel.tools.registry import KNOWN_TOOLS, ToolCapability

        valid_caps = set(ToolCapability)
        for name, meta in KNOWN_TOOLS.items():
            for cap in meta["capabilities"]:
                assert cap in valid_caps, \
                    f"{name} has invalid capability: {cap}"

    def test_exploit_tools_require_auth(self):
        """Tools with EXPLOIT capability should require authorization."""
        from kestrel.tools.registry import KNOWN_TOOLS, ToolCapability

        for name, meta in KNOWN_TOOLS.items():
            if ToolCapability.EXPLOIT in meta.get("capabilities", []):
                assert meta.get("requires_authorization", False) is True, \
                    f"{name} has EXPLOIT capability but doesn't require auth"

    def test_known_tools_count(self):
        """Should have a reasonable number of known tools defined."""
        from kestrel.tools.registry import KNOWN_TOOLS

        # We defined 25+ tools
        assert len(KNOWN_TOOLS) >= 20, \
            f"Expected 20+ known tools, got {len(KNOWN_TOOLS)}"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_register_same_tool_twice(self):
        """Re-registering a tool should overwrite."""
        from kestrel.tools.registry import ToolRegistry
        from kestrel.tools import NmapWrapper

        registry = ToolRegistry()
        registry.register_wrapped_tool(NmapWrapper(), has_parser=True)
        registry.register_wrapped_tool(NmapWrapper(), has_parser=False)

        assert registry.tool_count == 1
        info = registry.get("nmap")
        assert info.has_parser is False  # Should be overwritten

    def test_empty_context_generation(self):
        """Empty registry should generate context gracefully."""
        from kestrel.tools.registry import ToolRegistry

        registry = ToolRegistry()
        context = registry.build_llm_context()

        assert "No matching tools" in context

    def test_context_with_impossible_filter(self):
        """Filtering to nonexistent category should return no-match message."""
        from kestrel.tools.registry import ToolRegistry, ToolCapability

        registry = ToolRegistry()
        context = registry.build_llm_context(
            capabilities=[ToolCapability.WIRELESS]
        )

        assert "No matching tools" in context

    def test_tool_info_safety_flags_in_context(self):
        """ToolInfo with safety flags should show them in context."""
        from kestrel.tools.registry import ToolInfo, ToolTier

        info = ToolInfo(
            name="dangerous_tool",
            tier=ToolTier.DISCOVERED,
            available=True,
            requires_authorization=True,
            can_modify_target=True,
            is_passive=False,
        )

        context = info.to_llm_context()
        assert "REQUIRES_AUTH" in context
        assert "MODIFIES_TARGET" in context
        assert "ACTIVE" in context
