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

"""Context window trimmer for LLM backends.

Prevents unbounded context growth by trimming conversation history to fit
within a backend's token budget. Uses a char-based heuristic (1 token ~ 4 chars)
to avoid external tokenizer dependencies.

Strategy: keep the first user message (initial hunt prompt) and the most
recent messages, dropping from the middle when over budget.
"""

from __future__ import annotations

from kestrel.llm.backend import Message


def _estimate_tokens(text: str) -> int:
    """Rough token count: 1 token ~ 4 characters.

    Conservative for English text; matches OpenAI/Anthropic tokenizer averages.
    """
    return max(1, len(text) // 4)


def estimate_messages_tokens(messages: list[Message]) -> int:
    """Total estimated tokens across all messages."""
    return sum(_estimate_tokens(m.content) for m in messages)


def trim_context(
    context: list[Message],
    max_tokens: int,
    reserved_tokens: int = 0,
) -> list[Message]:
    """Trim context to fit within max_tokens budget.

    Strategy:
      - Keep the first message (initial hunt prompt — essential for coherence)
      - Keep the most recent messages (active analysis thread)
      - Drop middle messages oldest-first when over budget

    Args:
        context: Full conversation history.
        max_tokens: Maximum token budget for the context.
        reserved_tokens: Tokens to reserve for system prompt, current prompt,
            and expected output. Subtracted from max_tokens.

    Returns:
        A (potentially shorter) list of messages fitting the budget.
        Returns an empty list if context is empty.
    """
    if not context:
        return []

    budget = max_tokens - reserved_tokens
    if budget <= 0:
        return context[-1:] if context else []

    total = estimate_messages_tokens(context)
    if total <= budget:
        return list(context)

    # Always keep the first message
    first = context[0]
    first_cost = _estimate_tokens(first.content)

    if first_cost >= budget:
        return context[-1:]

    remaining_budget = budget - first_cost

    # Fill from the end (most recent messages) until budget exhausted
    tail: list[Message] = []
    tail_cost = 0
    for msg in reversed(context[1:]):
        msg_cost = _estimate_tokens(msg.content)
        if tail_cost + msg_cost > remaining_budget:
            break
        tail.insert(0, msg)
        tail_cost += msg_cost

    if not tail:
        return [first, context[-1]]

    return [first] + tail
