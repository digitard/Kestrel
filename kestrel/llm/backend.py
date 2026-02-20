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

"""Abstract LLM backend interface.

All LLM backends implement the LLMBackend Protocol. The orchestrator never
imports a specific backend directly — it receives one via dependency injection
or the BackendFactory.
"""

from dataclasses import dataclass, field
from typing import AsyncIterator, Literal, Protocol


@dataclass
class Message:
    """A single message in a conversation context."""
    role: Literal["user", "assistant", "system"]
    content: str


@dataclass
class LLMResponse:
    """Structured response from an LLM call."""
    content: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    stop_reason: str = ""


class LLMBackend(Protocol):
    """Protocol that all LLM backends must implement.

    The orchestrator interacts with any backend through this interface,
    enabling hot-swapping between API, local, and hybrid modes.
    """

    async def analyze(self, prompt: str, context: list[Message]) -> LLMResponse:
        """Send a prompt with context and return the complete response.

        Args:
            prompt: The user's current message or analysis request.
            context: Prior conversation messages for continuity.

        Returns:
            LLMResponse with the model's complete reply and metadata.
        """
        ...

    async def stream(self, prompt: str, context: list[Message]) -> AsyncIterator[str]:
        """Stream a response token-by-token.

        Args:
            prompt: The user's current message or analysis request.
            context: Prior conversation messages for continuity.

        Yields:
            Text chunks as they are generated.
        """
        ...

    def supports_vision(self) -> bool:
        """Whether this backend can process image inputs."""
        ...

    def max_context_tokens(self) -> int:
        """Maximum context window size in tokens."""
        ...

    def estimated_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost in USD for a given token count."""
        ...

    def last_usage(self) -> tuple[int, int]:
        """Return (input_tokens, output_tokens) from the most recent call."""
        ...
