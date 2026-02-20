"""
Phase 2 Tests — LLM Abstraction Layer

Tests the new LLM abstraction layer without making real API calls.
All backends are mocked or tested via their Protocol compliance.
"""

import asyncio
import hashlib
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import AsyncIterator

from kestrel.llm.backend import Message, LLMResponse
from kestrel.llm.context_trimmer import (
    _estimate_tokens,
    estimate_messages_tokens,
    trim_context,
)
from kestrel.llm.hybrid_router import HybridRouter, _DEFAULT_SIMPLE_KEYWORDS, _DEFAULT_COMPLEX_KEYWORDS
from kestrel.llm.prompts import BUG_BOUNTY_SYSTEM_PROMPT


# ============================================================================
# Helpers
# ============================================================================

def make_response(content: str = "test response", model: str = "test-model") -> LLMResponse:
    """Create a minimal LLMResponse for testing."""
    return LLMResponse(content=content, model=model)


def make_backend(content: str = "ok", complexity_answer: str = "SIMPLE") -> MagicMock:
    """Create a mock LLMBackend."""
    backend = MagicMock()
    backend.analyze = AsyncMock(return_value=make_response(complexity_answer))
    backend.stream = AsyncMock(return_value=AsyncMock())
    backend.supports_vision = MagicMock(return_value=False)
    backend.max_context_tokens = MagicMock(return_value=4096)
    backend.last_usage = MagicMock(return_value=(0, 0))
    backend.estimated_cost = MagicMock(return_value=0.0)
    return backend


# ============================================================================
# backend.py — Protocol dataclasses
# ============================================================================

class TestMessage:
    def test_message_creation(self):
        msg = Message(role="user", content="hello")
        assert msg.role == "user"
        assert msg.content == "hello"

    def test_message_roles(self):
        for role in ("user", "assistant", "system"):
            msg = Message(role=role, content="x")
            assert msg.role == role

    def test_message_empty_content(self):
        msg = Message(role="user", content="")
        assert msg.content == ""


class TestLLMResponse:
    def test_defaults(self):
        r = LLMResponse(content="hi", model="m")
        assert r.content == "hi"
        assert r.model == "m"
        assert r.input_tokens == 0
        assert r.output_tokens == 0
        assert r.stop_reason == ""

    def test_full_fields(self):
        r = LLMResponse(
            content="response",
            model="claude-sonnet-4-6",
            input_tokens=100,
            output_tokens=50,
            stop_reason="end_turn",
        )
        assert r.input_tokens == 100
        assert r.output_tokens == 50
        assert r.stop_reason == "end_turn"


# ============================================================================
# context_trimmer.py
# ============================================================================

class TestEstimateTokens:
    def test_empty_string(self):
        assert _estimate_tokens("") >= 1

    def test_short_string(self):
        # "hello" = 5 chars → max(1, 5//4) = 1
        assert _estimate_tokens("hello") == 1

    def test_longer_string(self):
        # 40 chars → 10 tokens
        assert _estimate_tokens("a" * 40) == 10

    def test_returns_at_least_one(self):
        assert _estimate_tokens("") >= 1
        assert _estimate_tokens("x") >= 1


class TestEstimateMessagesTokens:
    def test_empty_list(self):
        assert estimate_messages_tokens([]) == 0

    def test_single_message(self):
        msg = Message(role="user", content="a" * 40)
        assert estimate_messages_tokens([msg]) == 10

    def test_multiple_messages(self):
        msgs = [
            Message(role="user", content="a" * 40),
            Message(role="assistant", content="b" * 40),
        ]
        assert estimate_messages_tokens(msgs) == 20


class TestTrimContext:
    def test_empty_context(self):
        assert trim_context([], 1000) == []

    def test_fits_in_budget(self):
        msgs = [Message(role="user", content="hello")]
        result = trim_context(msgs, 1000)
        assert result == msgs

    def test_zero_budget_returns_last(self):
        msgs = [
            Message(role="user", content="first"),
            Message(role="assistant", content="second"),
        ]
        result = trim_context(msgs, 0)
        assert result == [msgs[-1]]

    def test_trims_middle_messages(self):
        """When over budget, middle messages are dropped, first and tail kept."""
        # Create context that's too large: first + 5 big middle + 1 recent
        first = Message(role="user", content="a" * 40)     # 10 tokens
        middle = [Message(role="assistant", content="b" * 400) for _ in range(5)]  # 100 each
        recent = Message(role="user", content="c" * 40)   # 10 tokens

        context = [first] + middle + [recent]

        # Budget: 30 tokens — only fits first (10) + recent (10) = 20
        result = trim_context(context, 30)

        assert result[0] == first
        assert result[-1] == recent
        # Middle messages should be dropped
        for m in middle:
            assert m not in result

    def test_reserved_tokens_reduce_budget(self):
        msgs = [Message(role="user", content="a" * 40)]  # 10 tokens
        # Budget 100, reserved 95 → effective 5; 10 > 5
        result = trim_context(msgs, 100, reserved_tokens=95)
        # Should fall back to last message
        assert len(result) <= 1

    def test_keeps_first_and_tail_when_no_middle_fits(self):
        first = Message(role="user", content="a" * 40)   # 10 tokens
        last = Message(role="user", content="b" * 40)    # 10 tokens
        context = [first, last]
        # Budget 25: first (10) + last (10) = 20 ≤ 25 → both fit
        result = trim_context(context, 25)
        assert first in result
        assert last in result


# ============================================================================
# hybrid_router.py — routing logic (no real backends called)
# ============================================================================

class TestHybridRouterInit:
    def test_creates_with_backends(self):
        local = make_backend()
        api = make_backend()
        router = HybridRouter(local_backend=local, api_backend=api)
        assert router._local is local
        assert router._api is api

    def test_default_fallback_config(self):
        router = HybridRouter(make_backend(), make_backend())
        assert router._fallback_to_local is True
        assert router._fallback_to_api is False

    def test_custom_config(self):
        config = {"fallback_to_local": False, "fallback_to_api": True}
        router = HybridRouter(make_backend(), make_backend(), config=config)
        assert router._fallback_to_local is False
        assert router._fallback_to_api is True


class TestHybridRouterPatterns:
    def test_build_pattern_empty(self):
        assert HybridRouter._build_pattern([]) is None

    def test_build_pattern_matches(self):
        pattern = HybridRouter._build_pattern(["CVE", "exploit"])
        assert pattern is not None
        assert pattern.search("found a CVE")
        assert pattern.search("exploit this")
        assert not pattern.search("nothing here")

    def test_build_pattern_case_insensitive(self):
        pattern = HybridRouter._build_pattern(["exploit"])
        assert pattern.search("EXPLOIT")
        assert pattern.search("Exploit")
        assert pattern.search("exploit")

    def test_prompt_hash_consistent(self):
        router = HybridRouter(make_backend(), make_backend())
        h1 = router._prompt_hash("hello world")
        h2 = router._prompt_hash("hello world")
        assert h1 == h2

    def test_prompt_hash_different(self):
        router = HybridRouter(make_backend(), make_backend())
        h1 = router._prompt_hash("hello")
        h2 = router._prompt_hash("world")
        assert h1 != h2


class TestHybridRouterClassification:
    def test_complex_keyword_routes_complex(self):
        router = HybridRouter(make_backend(), make_backend())
        result = asyncio.run(
            router.classify_complexity("Plan a CVE exploit")
        )
        assert result == "complex"

    def test_simple_keyword_routes_simple(self):
        router = HybridRouter(make_backend(), make_backend())
        result = asyncio.run(
            router.classify_complexity("summarize the banner grab results")
        )
        assert result == "simple"

    def test_complex_takes_priority_over_simple(self):
        """If both keywords match, complex wins (safety-first)."""
        router = HybridRouter(make_backend(), make_backend())
        # "summarize" is simple, "CVE" is complex
        result = asyncio.run(
            router.classify_complexity("summarize the CVE findings")
        )
        assert result == "complex"

    def test_cache_used_on_second_call(self):
        local = make_backend()
        router = HybridRouter(local, make_backend())

        # First call — keyword match, no LLM needed
        asyncio.run(
            router.classify_complexity("summarize the output")
        )
        initial_call_count = local.analyze.call_count

        # Second call — should hit cache, no new LLM call
        asyncio.run(
            router.classify_complexity("summarize the output")
        )
        assert local.analyze.call_count == initial_call_count

    def test_llm_fallback_for_unknown_prompt(self):
        """Ambiguous prompts trigger a local LLM classification call."""
        local = make_backend(complexity_answer="SIMPLE")
        router = HybridRouter(local, make_backend())

        # Clear keyword lists so nothing matches
        router._simple_re = None
        router._complex_re = None

        result = asyncio.run(
            router.classify_complexity("do something interesting")
        )
        assert local.analyze.call_count == 1
        assert result == "simple"

    def test_llm_fallback_defaults_complex_on_error(self):
        """If LLM classification fails, defaults to complex (safe)."""
        local = make_backend()
        local.analyze = AsyncMock(side_effect=RuntimeError("connection failed"))
        router = HybridRouter(local, make_backend())

        router._simple_re = None
        router._complex_re = None

        result = asyncio.run(
            router.classify_complexity("unclear task")
        )
        assert result == "complex"


class TestHybridRouterBackendSelection:
    def test_simple_routes_to_local(self):
        local = make_backend()
        api = make_backend()
        router = HybridRouter(local, api, config={"fallback_to_api": False})
        primary, secondary = router._select_backends("simple")
        assert primary is local
        assert secondary is None

    def test_complex_routes_to_api(self):
        local = make_backend()
        api = make_backend()
        router = HybridRouter(local, api, config={"fallback_to_local": True})
        primary, secondary = router._select_backends("complex")
        assert primary is api
        assert secondary is local

    def test_complex_no_fallback(self):
        local = make_backend()
        api = make_backend()
        router = HybridRouter(local, api, config={"fallback_to_local": False})
        primary, secondary = router._select_backends("complex")
        assert primary is api
        assert secondary is None


class TestHybridRouterAnalyze:
    def test_analyze_routes_to_correct_backend(self):
        local = make_backend()
        api_response = make_response("api result")
        api = make_backend()
        api.analyze = AsyncMock(return_value=api_response)
        api.max_context_tokens = MagicMock(return_value=200_000)

        router = HybridRouter(local, api)
        # Force complex routing via keyword
        result = asyncio.run(
            router.analyze("Plan a CVE exploit", [])
        )
        assert api.analyze.called
        assert result.content == "api result"

    def test_analyze_falls_back_on_error(self):
        local_response = make_response("local fallback")
        local = make_backend()
        local.analyze = AsyncMock(return_value=local_response)

        api = make_backend()
        api.analyze = AsyncMock(side_effect=ConnectionError("API down"))
        api.max_context_tokens = MagicMock(return_value=200_000)

        router = HybridRouter(local, api, config={"fallback_to_local": True})
        # Force complex routing
        router._cache[router._prompt_hash("test")] = "complex"

        result = asyncio.run(
            router.analyze("test", [])
        )
        assert result.content == "local fallback"

    def test_analyze_raises_when_no_fallback(self):
        local = make_backend()
        api = make_backend()
        api.analyze = AsyncMock(side_effect=ConnectionError("API down"))
        api.max_context_tokens = MagicMock(return_value=200_000)

        router = HybridRouter(local, api, config={"fallback_to_local": False})
        router._cache[router._prompt_hash("test")] = "complex"

        with pytest.raises(ConnectionError):
            asyncio.run(
                router.analyze("test", [])
            )


class TestHybridRouterProtocolMethods:
    def setup_method(self):
        api = make_backend()
        api.max_context_tokens = MagicMock(return_value=200_000)
        api.last_usage = MagicMock(return_value=(100, 50))
        api.estimated_cost = MagicMock(return_value=0.001)
        self.router = HybridRouter(make_backend(), api)
        self.router._last_backend = api

    def test_supports_vision_always_true(self):
        assert self.router.supports_vision() is True

    def test_max_context_tokens_delegates_to_api(self):
        assert self.router.max_context_tokens() == 200_000

    def test_last_usage_delegates_to_last_backend(self):
        assert self.router.last_usage() == (100, 50)

    def test_estimated_cost_delegates_to_last_backend(self):
        cost = self.router.estimated_cost(100, 50)
        assert cost == 0.001


# ============================================================================
# prompts.py — system prompt content
# ============================================================================

class TestBugBountySystemPrompt:
    def test_prompt_exists(self):
        assert BUG_BOUNTY_SYSTEM_PROMPT
        assert len(BUG_BOUNTY_SYSTEM_PROMPT) > 500

    def test_prompt_has_core_sections(self):
        assert "Authorization" in BUG_BOUNTY_SYSTEM_PROMPT or "authorization" in BUG_BOUNTY_SYSTEM_PROMPT
        assert "CVE" in BUG_BOUNTY_SYSTEM_PROMPT
        assert "<cmd>" in BUG_BOUNTY_SYSTEM_PROMPT

    def test_prompt_mentions_severity(self):
        assert "Critical" in BUG_BOUNTY_SYSTEM_PROMPT
        assert "High" in BUG_BOUNTY_SYSTEM_PROMPT

    def test_prompt_mentions_report(self):
        assert "report" in BUG_BOUNTY_SYSTEM_PROMPT.lower()

    def test_prompt_mentions_scope(self):
        assert "scope" in BUG_BOUNTY_SYSTEM_PROMPT.lower()


# ============================================================================
# Imports smoke test — all new modules importable without side effects
# ============================================================================

class TestModuleImports:
    def test_import_backend(self):
        from kestrel.llm.backend import LLMBackend, Message, LLMResponse
        assert LLMBackend
        assert Message
        assert LLMResponse

    def test_import_context_trimmer(self):
        from kestrel.llm.context_trimmer import trim_context, estimate_messages_tokens
        assert trim_context
        assert estimate_messages_tokens

    def test_import_hybrid_router(self):
        from kestrel.llm.hybrid_router import HybridRouter
        assert HybridRouter

    def test_import_prompts_system_prompt(self):
        from kestrel.llm.prompts import BUG_BOUNTY_SYSTEM_PROMPT
        assert BUG_BOUNTY_SYSTEM_PROMPT

    def test_import_backend_factory(self):
        from kestrel.llm.backend_factory import create_backend, _create_local_backend
        assert create_backend
        assert _create_local_backend

    def test_import_mlx_backend_no_mlx_installed(self):
        """MLXBackend class should import fine even without mlx-lm installed."""
        from kestrel.llm.mlx_backend import MLXBackend, is_apple_silicon
        assert MLXBackend
        assert is_apple_silicon

    def test_import_ollama_backend(self):
        from kestrel.llm.ollama_backend import OllamaBackend
        assert OllamaBackend

    def test_import_anthropic_backend_no_key(self):
        """AnthropicBackend class should import; instantiation requires key."""
        from kestrel.llm.anthropic_backend import AnthropicBackend, _PRICING
        assert AnthropicBackend
        assert "claude-sonnet-4-6" in _PRICING

    def test_llm_package_exports(self):
        """kestrel.llm __init__ should export all expected names."""
        import kestrel.llm as llm
        assert hasattr(llm, "LLMBackend")
        assert hasattr(llm, "Message")
        assert hasattr(llm, "LLMResponse")
        assert hasattr(llm, "create_backend")
        assert hasattr(llm, "HybridRouter")
        assert hasattr(llm, "trim_context")
        assert hasattr(llm, "BUG_BOUNTY_SYSTEM_PROMPT")
        # Legacy exports still present
        assert hasattr(llm, "AnthropicClient")
        assert hasattr(llm, "build_translation_prompt")


# ============================================================================
# backend_factory.py — create_backend routing
# ============================================================================

class TestBackendFactory:
    def test_create_backend_api_mode(self):
        """'api' mode should instantiate AnthropicBackend (mocked)."""
        with patch("kestrel.llm.backend_factory.get_platform") as mock_plat, \
             patch("kestrel.llm.anthropic_backend.AnthropicBackend.__init__",
                   return_value=None) as mock_init, \
             patch("kestrel.llm.anthropic_backend._resolve_api_key",
                   return_value="fake-key"):
            from kestrel.llm.backend_factory import create_backend
            from kestrel.llm.anthropic_backend import AnthropicBackend
            backend = create_backend(mode="api")
            assert isinstance(backend, AnthropicBackend)

    def test_create_backend_unknown_mode_raises(self):
        from kestrel.llm.backend_factory import create_backend
        with pytest.raises(ValueError, match="Unknown LLM mode"):
            create_backend(mode="bogus")

    def test_create_local_backend_mlx_on_apple_silicon(self):
        """On Apple Silicon, _create_local_backend should return MLXBackend."""
        from kestrel.core.platform import PlatformInfo, ExecutionMode, LLMBackendType
        from kestrel.llm.backend_factory import _create_local_backend

        fake_info = PlatformInfo(
            os_name="darwin", arch="arm64", os_version="Darwin 25.0",
            is_apple_silicon=True, is_kali=False,
            has_cuda=False, has_vulkan=False, has_docker=True,
            ram_gb=16,
            execution_mode=ExecutionMode.DOCKER,
            llm_backend=LLMBackendType.MLX,
            recommended_model="mlx-community/Mistral-7B-Instruct-v0.3-4bit",
            fallback_model="mlx-community/Mistral-7B-Instruct-v0.3-4bit",
        )

        with patch("kestrel.llm.mlx_backend.get_platform", return_value=fake_info):
            backend = _create_local_backend(fake_info)
            from kestrel.llm.mlx_backend import MLXBackend
            assert isinstance(backend, MLXBackend)

    def test_create_local_backend_ollama_on_linux(self):
        """On non-Apple platforms, _create_local_backend should return OllamaBackend."""
        from kestrel.core.platform import PlatformInfo, ExecutionMode, LLMBackendType
        from kestrel.llm.backend_factory import _create_local_backend

        fake_info = PlatformInfo(
            os_name="linux", arch="x86_64", os_version="Kali GNU/Linux Rolling",
            is_apple_silicon=False, is_kali=True,
            has_cuda=False, has_vulkan=False, has_docker=False,
            ram_gb=16,
            execution_mode=ExecutionMode.NATIVE,
            llm_backend=LLMBackendType.OLLAMA_CPU,
            recommended_model="llama3.1:8b",
            fallback_model="llama3.2:3b",
        )

        with patch("kestrel.llm.ollama_backend.get_platform", return_value=fake_info):
            backend = _create_local_backend(fake_info)
            from kestrel.llm.ollama_backend import OllamaBackend
            assert isinstance(backend, OllamaBackend)

    def test_create_local_backend_anthropic_only_raises(self):
        """ANTHROPIC_ONLY backend type should raise RuntimeError."""
        from kestrel.core.platform import PlatformInfo, ExecutionMode, LLMBackendType
        from kestrel.llm.backend_factory import _create_local_backend

        fake_info = PlatformInfo(
            os_name="linux", arch="x86_64", os_version="Ubuntu 22.04",
            is_apple_silicon=False, is_kali=False,
            has_cuda=False, has_vulkan=False, has_docker=False,
            ram_gb=4,
            execution_mode=ExecutionMode.UNAVAILABLE,
            llm_backend=LLMBackendType.ANTHROPIC_ONLY,
            recommended_model="llama3.2:3b",
            fallback_model="llama3.2:3b",
        )

        with pytest.raises(RuntimeError, match="No local LLM backend available"):
            _create_local_backend(fake_info)


# ============================================================================
# AnthropicBackend pricing
# ============================================================================

class TestAnthropicBackendPricing:
    def test_cost_calculation_sonnet(self):
        from kestrel.llm.anthropic_backend import AnthropicBackend, _PRICING

        # Instantiate without API key by mocking
        with patch("kestrel.llm.anthropic_backend._resolve_api_key", return_value="fake"):
            with patch("anthropic.Anthropic"), patch("anthropic.AsyncAnthropic"):
                backend = AnthropicBackend()
                # 1M input tokens at $3.00 = $3.00
                cost = backend.estimated_cost(1_000_000, 0)
                assert abs(cost - 3.00) < 0.001

    def test_cost_zero_tokens(self):
        with patch("kestrel.llm.anthropic_backend._resolve_api_key", return_value="fake"):
            with patch("anthropic.Anthropic"), patch("anthropic.AsyncAnthropic"):
                from kestrel.llm.anthropic_backend import AnthropicBackend
                backend = AnthropicBackend()
                assert backend.estimated_cost(0, 0) == 0.0

    def test_unknown_model_uses_default_pricing(self):
        with patch("kestrel.llm.anthropic_backend._resolve_api_key", return_value="fake"):
            with patch("anthropic.Anthropic"), patch("anthropic.AsyncAnthropic"):
                from kestrel.llm.anthropic_backend import AnthropicBackend
                backend = AnthropicBackend(model="unknown-model-xyz")
                # Should not raise — falls back to _DEFAULT_PRICING
                cost = backend.estimated_cost(1_000_000, 0)
                assert cost > 0

    def test_supports_vision(self):
        with patch("kestrel.llm.anthropic_backend._resolve_api_key", return_value="fake"):
            with patch("anthropic.Anthropic"), patch("anthropic.AsyncAnthropic"):
                from kestrel.llm.anthropic_backend import AnthropicBackend
                backend = AnthropicBackend()
                assert backend.supports_vision() is True

    def test_max_context_tokens(self):
        with patch("kestrel.llm.anthropic_backend._resolve_api_key", return_value="fake"):
            with patch("anthropic.Anthropic"), patch("anthropic.AsyncAnthropic"):
                from kestrel.llm.anthropic_backend import AnthropicBackend
                backend = AnthropicBackend()
                assert backend.max_context_tokens() == 200_000


# ============================================================================
# OllamaBackend — unit tests (no real Ollama server)
# ============================================================================

class TestOllamaBackend:
    def _make_ollama(self, model="llama3.2:3b") -> "OllamaBackend":
        from kestrel.core.platform import PlatformInfo, ExecutionMode, LLMBackendType
        fake_info = PlatformInfo(
            os_name="linux", arch="x86_64", os_version="Kali",
            is_apple_silicon=False, is_kali=True,
            has_cuda=False, has_vulkan=False, has_docker=False,
            ram_gb=16,
            execution_mode=ExecutionMode.NATIVE,
            llm_backend=LLMBackendType.OLLAMA_CPU,
            recommended_model=model,
            fallback_model="llama3.2:3b",
        )
        from kestrel.llm.ollama_backend import OllamaBackend
        with patch("kestrel.llm.ollama_backend.get_platform", return_value=fake_info):
            return OllamaBackend()

    def test_build_messages_includes_system(self):
        backend = self._make_ollama()
        msgs = backend._build_messages("hello", [])
        assert msgs[0]["role"] == "system"
        assert msgs[-1] == {"role": "user", "content": "hello"}

    def test_build_messages_with_context(self):
        backend = self._make_ollama()
        context = [
            Message(role="user", content="first"),
            Message(role="assistant", content="reply"),
        ]
        msgs = backend._build_messages("second", context)
        assert msgs[0]["role"] == "system"
        assert {"role": "user", "content": "first"} in msgs
        assert {"role": "assistant", "content": "reply"} in msgs
        assert msgs[-1] == {"role": "user", "content": "second"}

    def test_supports_vision_false(self):
        backend = self._make_ollama()
        assert backend.supports_vision() is False

    def test_estimated_cost_zero(self):
        backend = self._make_ollama()
        assert backend.estimated_cost(1000, 1000) == 0.0

    def test_last_usage_returns_zeros(self):
        backend = self._make_ollama()
        assert backend.last_usage() == (0, 0)

    def test_sync_request_raises_on_connection_error(self):
        import urllib.request
        backend = self._make_ollama()
        req = urllib.request.Request("http://localhost:11434/api/chat")
        with pytest.raises(RuntimeError, match="Cannot connect to Ollama"):
            backend._sync_request(req)
