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

"""Anthropic (Claude) LLM backend — cloud API backend for complex tasks."""

import os
import sys
from typing import AsyncIterator

import anthropic

from kestrel.llm.backend import LLMResponse, Message
from kestrel.llm.prompts import BUG_BOUNTY_SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Pricing per million tokens (USD) — update as models change
# ---------------------------------------------------------------------------

_PRICING = {
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5-20251001": {"input": 1.00, "output": 5.00},
    "claude-opus-4-6": {"input": 5.00, "output": 25.00},
}

_DEFAULT_PRICING = {"input": 3.00, "output": 15.00}


def _resolve_api_key(api_key: str | None) -> str | None:
    """Resolve API key from argument, env var, or ~/.kestrel/credentials.yaml."""
    if api_key:
        return api_key

    # Environment variable takes precedence over credential file
    env_key = os.environ.get("ANTHROPIC_API_KEY")
    if env_key:
        return env_key

    # Fall back to ~/.kestrel/credentials.yaml
    try:
        from kestrel.platforms.credentials import CredentialManager
        mgr = CredentialManager()
        return mgr.get("anthropic_api_key")
    except Exception:
        return None


class AnthropicBackend:
    """LLM backend using the Anthropic Claude API.

    Used for complex tasks: multi-step exploit planning, CVE correlation
    analysis, report generation, and any task the HybridRouter classifies
    as needing cloud-level reasoning.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> None:
        resolved_key = _resolve_api_key(api_key)
        if not resolved_key:
            print(
                "ERROR: No Anthropic API key found.\n"
                "Set ANTHROPIC_API_KEY or add it to ~/.kestrel/credentials.yaml",
                file=sys.stderr,
            )
            sys.exit(1)

        self._client = anthropic.Anthropic(api_key=resolved_key)
        self._async_client = anthropic.AsyncAnthropic(api_key=resolved_key)
        self._model = model or "claude-sonnet-4-6"
        self._max_tokens = max_tokens or 8192
        self._temperature = temperature if temperature is not None else 0.1
        self._system_prompt = BUG_BOUNTY_SYSTEM_PROMPT
        self._last_usage: tuple[int, int] = (0, 0)

    async def analyze(self, prompt: str, context: list[Message]) -> LLMResponse:
        """Send a prompt and return the complete response."""
        messages = self._build_messages(prompt, context)

        response = await self._async_client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            system=self._system_prompt,
            messages=messages,
        )

        content = ""
        for block in response.content:
            if block.type == "text":
                content += block.text

        self._last_usage = (response.usage.input_tokens, response.usage.output_tokens)

        return LLMResponse(
            content=content,
            model=response.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            stop_reason=response.stop_reason or "",
        )

    async def stream(self, prompt: str, context: list[Message]) -> AsyncIterator[str]:
        """Stream response text chunks as they arrive."""
        messages = self._build_messages(prompt, context)

        async with self._async_client.messages.stream(
            model=self._model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            system=self._system_prompt,
            messages=messages,
        ) as stream:
            async for text in stream.text_stream:
                yield text
            final = await stream.get_final_message()
            self._last_usage = (final.usage.input_tokens, final.usage.output_tokens)

    def supports_vision(self) -> bool:
        """Claude supports image inputs."""
        return True

    def max_context_tokens(self) -> int:
        """Claude Sonnet supports 200k context."""
        return 200_000

    def last_usage(self) -> tuple[int, int]:
        """Return (input_tokens, output_tokens) from the most recent call."""
        return self._last_usage

    def estimated_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost in USD based on current model pricing."""
        pricing = _PRICING.get(self._model, _DEFAULT_PRICING)
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        return input_cost + output_cost

    def _build_messages(
        self, prompt: str, context: list[Message]
    ) -> list[dict[str, str]]:
        """Convert Message objects to Anthropic API format."""
        messages: list[dict[str, str]] = []
        for msg in context:
            if msg.role in ("user", "assistant"):
                messages.append({"role": msg.role, "content": msg.content})
        messages.append({"role": "user", "content": prompt})
        return messages
