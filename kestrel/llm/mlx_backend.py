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

"""MLX Apple Silicon local LLM backend.

Uses the MLX framework for native inference on Apple Silicon (M1/M2/M3/M4).
Leverages the Neural Engine and unified memory for maximum throughput.
"""

import asyncio
import platform
from typing import AsyncIterator

from kestrel.core.platform import get_platform
from kestrel.llm.backend import LLMResponse, Message
from kestrel.llm.prompts import BUG_BOUNTY_SYSTEM_PROMPT


def is_apple_silicon() -> bool:
    """Return True if running on Apple Silicon (arm64 macOS)."""
    return platform.machine() == "arm64" and platform.system() == "Darwin"


class MLXBackend:
    """LLM backend using MLX for native Apple Silicon inference."""

    def __init__(
        self,
        model: str | None = None,
        context_length: int | None = None,
    ) -> None:
        info = get_platform()

        self._model_id = model or info.recommended_model
        self._context_length = context_length or 4096
        self._system_prompt = BUG_BOUNTY_SYSTEM_PROMPT

        # Lazy-loaded on first use
        self._model = None
        self._tokenizer = None

    def _ensure_loaded(self) -> None:
        """Load model and tokenizer on first use (lazy initialization)."""
        if self._model is not None:
            return

        try:
            from mlx_lm import load
        except ImportError:
            raise RuntimeError(
                "mlx-lm is not installed. Run: pip3 install mlx-lm"
            )

        self._model, self._tokenizer = load(self._model_id)

    async def analyze(self, prompt: str, context: list[Message]) -> LLMResponse:
        """Send a prompt and return the complete response."""
        return await asyncio.to_thread(self._sync_generate, prompt, context)

    async def stream(self, prompt: str, context: list[Message]) -> AsyncIterator[str]:
        """Stream response text chunks as they arrive."""
        queue: asyncio.Queue[str | None] = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def _stream_worker() -> None:
            try:
                from mlx_lm import stream_generate

                self._ensure_loaded()
                chat_prompt = self._build_prompt(prompt, context)

                for response in stream_generate(
                    self._model,
                    self._tokenizer,
                    prompt=chat_prompt,
                    max_tokens=8192,
                ):
                    if response.text:
                        loop.call_soon_threadsafe(queue.put_nowait, response.text)
            except Exception as exc:
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    f"\n[MLX error: {exc}]",
                )
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        asyncio.get_event_loop().run_in_executor(None, _stream_worker)

        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            yield chunk

    def supports_vision(self) -> bool:
        """MLX text models do not support vision."""
        return False

    def max_context_tokens(self) -> int:
        """Return the configured context length."""
        return self._context_length

    def last_usage(self) -> tuple[int, int]:
        """Local inference does not track token usage."""
        return (0, 0)

    def estimated_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Local inference is free."""
        return 0.0

    def _build_prompt(self, prompt: str, context: list[Message]) -> str:
        """Build a formatted prompt using the tokenizer's chat template."""
        self._ensure_loaded()

        messages: list[dict[str, str]] = [
            {"role": "system", "content": self._system_prompt}
        ]
        for msg in context:
            if msg.role in ("user", "assistant"):
                messages.append({"role": msg.role, "content": msg.content})
        messages.append({"role": "user", "content": prompt})

        return self._tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )

    def _sync_generate(self, prompt: str, context: list[Message]) -> LLMResponse:
        """Run non-streaming generation synchronously."""
        from mlx_lm import generate

        self._ensure_loaded()
        chat_prompt = self._build_prompt(prompt, context)
        text = generate(
            self._model,
            self._tokenizer,
            prompt=chat_prompt,
            max_tokens=8192,
        )

        return LLMResponse(
            content=text,
            model=self._model_id,
            input_tokens=0,
            output_tokens=0,
            stop_reason="stop",
        )
