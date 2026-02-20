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

"""Ollama local LLM backend.

Works on all non-Apple-Silicon platforms. Automatically uses CUDA or Vulkan
acceleration when available (configured via Ollama itself — no code changes
needed here).
"""

import asyncio
import json
import urllib.error
import urllib.request
from typing import AsyncIterator

from kestrel.core.platform import get_platform
from kestrel.llm.backend import LLMResponse, Message
from kestrel.llm.prompts import BUG_BOUNTY_SYSTEM_PROMPT


class OllamaBackend:
    """LLM backend using a local Ollama server.

    Ollama handles GPU acceleration (CUDA, Vulkan) automatically based on
    system configuration. This backend just speaks the Ollama chat API.
    """

    def __init__(
        self,
        model: str | None = None,
        context_length: int | None = None,
        ollama_host: str | None = None,
    ) -> None:
        info = get_platform()

        self._model = model or info.recommended_model
        self._context_length = context_length or 4096
        self._host = ollama_host or "http://localhost:11434"
        self._system_prompt = BUG_BOUNTY_SYSTEM_PROMPT

    async def analyze(self, prompt: str, context: list[Message]) -> LLMResponse:
        """Send a prompt and return the complete response."""
        messages = self._build_messages(prompt, context)
        payload = json.dumps({
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": {"num_ctx": self._context_length},
        }).encode()

        req = urllib.request.Request(
            f"{self._host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        response_data = await asyncio.to_thread(self._sync_request, req)
        body = json.loads(response_data)

        content = body.get("message", {}).get("content", "")
        input_tokens = body.get("prompt_eval_count", 0)
        output_tokens = body.get("eval_count", 0)
        done_reason = body.get("done_reason", "")

        return LLMResponse(
            content=content,
            model=body.get("model", self._model),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            stop_reason=done_reason,
        )

    async def stream(self, prompt: str, context: list[Message]) -> AsyncIterator[str]:
        """Stream response text chunks as they arrive."""
        messages = self._build_messages(prompt, context)
        payload = json.dumps({
            "model": self._model,
            "messages": messages,
            "stream": True,
            "options": {"num_ctx": self._context_length},
        }).encode()

        req = urllib.request.Request(
            f"{self._host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        queue: asyncio.Queue[str | None] = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def _stream_reader() -> None:
            try:
                resp = urllib.request.urlopen(req, timeout=300)
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    chunk = obj.get("message", {}).get("content", "")
                    if chunk:
                        loop.call_soon_threadsafe(queue.put_nowait, chunk)
                    if obj.get("done", False):
                        break
                resp.close()
            except Exception as exc:
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    f"\n[Ollama error: {exc}]",
                )
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        asyncio.get_event_loop().run_in_executor(None, _stream_reader)

        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            yield chunk

    def supports_vision(self) -> bool:
        """Ollama vision support depends on model; assume False for text models."""
        return False

    def max_context_tokens(self) -> int:
        """Return the configured context length."""
        return self._context_length

    def last_usage(self) -> tuple[int, int]:
        """Local inference does not track token usage reliably."""
        return (0, 0)

    def estimated_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Local inference is free."""
        return 0.0

    def _build_messages(
        self, prompt: str, context: list[Message]
    ) -> list[dict[str, str]]:
        """Convert Message objects to Ollama chat API format."""
        messages: list[dict[str, str]] = [
            {"role": "system", "content": self._system_prompt}
        ]
        for msg in context:
            if msg.role in ("user", "assistant"):
                messages.append({"role": msg.role, "content": msg.content})
        messages.append({"role": "user", "content": prompt})
        return messages

    @staticmethod
    def _sync_request(req: urllib.request.Request) -> bytes:
        """Execute a blocking HTTP request and return the response body."""
        try:
            resp = urllib.request.urlopen(req, timeout=300)
            data = resp.read()
            resp.close()
            return data
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama API error {e.code}: {body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"Cannot connect to Ollama at {req.full_url}: {e.reason}\n"
                "Is Ollama running? Start it with: ollama serve"
            ) from e
