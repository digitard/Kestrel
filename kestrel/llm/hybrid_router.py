# Kestrel — LLM-assisted bug bounty hunting platform
# Copyright (C) 2026 David Kuznicki and Kestrel Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Hybrid router — classifies task complexity and routes between backends.

Routes simple recon tasks (banner parsing, port scan summarization) to the
fast local backend, and complex tasks (CVE correlation, exploit planning,
report generation) to the Anthropic API.

Classification pipeline:
  1. Fast keyword scan — regex patterns match known simple/complex tasks.
  2. LLM fallback — if no keyword hits, ask the local backend to classify.
  3. Cache — identical prompts within a session are not reclassified.

Fallback:
  - Complex task → API backend fails → falls back to local (configurable).
  - Simple task → local backend fails → falls back to API (configurable).
"""

import hashlib
import logging
import re
from typing import AsyncIterator

from kestrel.llm.backend import LLMResponse, Message


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Classification prompt — sent to local LLM for ambiguous tasks
# ---------------------------------------------------------------------------

_CLASSIFY_PROMPT = (
    "Classify this bug bounty task as SIMPLE or COMPLEX. Reply with one word only.\n"
    "SIMPLE = quick lookup, banner parsing, port summary, encoding, identification\n"
    "COMPLEX = multi-step exploit planning, CVE correlation, vulnerability analysis, "
    "report generation, scope risk assessment\n"
    "Task: {prompt}"
)

# Keywords that force SIMPLE routing (fast, local)
_DEFAULT_SIMPLE_KEYWORDS = [
    "summarize", "parse", "identify", "fingerprint",
    "what port", "what service", "encode", "decode", "base64",
    "banner", "version string",
]

# Keywords that force COMPLEX routing (powerful, API)
_DEFAULT_COMPLEX_KEYWORDS = [
    "CVE", "exploit", "vulnerability", "report", "submission",
    "proof of concept", "poc", "attack chain", "privilege escalation",
    "RCE", "SQL injection", "XSS", "SSRF", "IDOR", "LFI", "RFI",
    "plan", "correlate", "remediation", "impact assessment",
]


class HybridRouter:
    """Routes prompts between local and API backends based on complexity.

    Implements the LLMBackend protocol so it can be used as a drop-in
    replacement in the orchestrator.
    """

    def __init__(
        self,
        local_backend: object,
        api_backend: object,
        config: dict | None = None,
    ) -> None:
        self._local = local_backend
        self._api = api_backend
        self._config = config or {}

        simple_kw = self._config.get("simple_keywords", _DEFAULT_SIMPLE_KEYWORDS)
        complex_kw = self._config.get("complex_keywords", _DEFAULT_COMPLEX_KEYWORDS)
        self._simple_re = self._build_pattern(simple_kw)
        self._complex_re = self._build_pattern(complex_kw)

        self._fallback_to_local = self._config.get("fallback_to_local", True)
        self._fallback_to_api = self._config.get("fallback_to_api", False)

        # Cache: prompt hash -> "simple" | "complex"
        self._cache: dict[str, str] = {}
        self._last_backend: object = self._api

    @staticmethod
    def _build_pattern(keywords: list[str]) -> re.Pattern | None:
        """Build a compiled regex that matches any keyword (case-insensitive)."""
        if not keywords:
            return None
        escaped = [re.escape(kw) for kw in keywords]
        return re.compile("|".join(escaped), re.IGNORECASE)

    def _prompt_hash(self, prompt: str) -> str:
        """Return a short hash for caching classification results."""
        return hashlib.sha256(prompt.encode()).hexdigest()[:16]

    async def classify_complexity(self, prompt: str) -> str:
        """Classify a prompt as ``"simple"`` or ``"complex"``.

        1. Check cache.
        2. Check keyword patterns.
        3. Fall back to local LLM classification.
        """
        key = self._prompt_hash(prompt)
        if key in self._cache:
            return self._cache[key]

        # Complex keywords take priority (safety: prefer capable backend)
        if self._complex_re and self._complex_re.search(prompt):
            self._cache[key] = "complex"
            return "complex"
        if self._simple_re and self._simple_re.search(prompt):
            self._cache[key] = "simple"
            return "simple"

        # LLM fallback — ask local backend
        try:
            classify_prompt = _CLASSIFY_PROMPT.format(prompt=prompt[:500])
            response = await self._local.analyze(classify_prompt, [])
            answer = response.content.strip().upper()
            result = "simple" if "SIMPLE" in answer else "complex"
        except Exception as exc:
            logger.warning("Classification LLM call failed: %s — defaulting to complex", exc)
            result = "complex"

        self._cache[key] = result
        return result

    def _select_backends(self, complexity: str) -> tuple:
        """Return (primary, secondary) backends based on complexity."""
        if complexity == "simple":
            primary = self._local
            secondary = self._api if self._fallback_to_api else None
        else:
            primary = self._api
            secondary = self._local if self._fallback_to_local else None
        return primary, secondary

    async def analyze(self, prompt: str, context: list[Message]) -> LLMResponse:
        """Classify, route, and optionally fall back."""
        complexity = await self.classify_complexity(prompt)
        primary, secondary = self._select_backends(complexity)

        logger.info("Hybrid routing: %s -> %s", complexity, type(primary).__name__)

        try:
            response = await primary.analyze(prompt, context)
            self._last_backend = primary
            return response
        except (ConnectionError, TimeoutError, RuntimeError, OSError) as exc:
            if secondary is not None:
                logger.warning(
                    "Fallback: %s -> %s (error: %s)",
                    type(primary).__name__,
                    type(secondary).__name__,
                    exc,
                )
                response = await secondary.analyze(prompt, context)
                self._last_backend = secondary
                return response
            raise

    async def stream(self, prompt: str, context: list[Message]) -> AsyncIterator[str]:
        """Classify, route, and optionally fall back (streaming)."""
        complexity = await self.classify_complexity(prompt)
        primary, secondary = self._select_backends(complexity)

        logger.info("Hybrid routing (stream): %s -> %s", complexity, type(primary).__name__)

        try:
            async for chunk in primary.stream(prompt, context):
                self._last_backend = primary
                yield chunk
        except (ConnectionError, TimeoutError, RuntimeError, OSError) as exc:
            if secondary is not None:
                logger.warning(
                    "Fallback (stream): %s -> %s (error: %s)",
                    type(primary).__name__,
                    type(secondary).__name__,
                    exc,
                )
                self._last_backend = secondary
                async for chunk in secondary.stream(prompt, context):
                    yield chunk
            else:
                raise

    def supports_vision(self) -> bool:
        """Delegate vision capability to API backend."""
        return True

    def max_context_tokens(self) -> int:
        """Return the API backend's context window (largest available)."""
        return self._api.max_context_tokens()

    def last_usage(self) -> tuple[int, int]:
        """Delegate to whichever backend handled the last request."""
        return self._last_backend.last_usage()

    def estimated_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Cost of whichever backend handled the last request."""
        return self._last_backend.estimated_cost(input_tokens, output_tokens)
