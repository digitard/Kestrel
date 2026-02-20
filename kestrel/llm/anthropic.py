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

"""
Kestrel Anthropic LLM Client

Provides integration with Claude for intent translation and analysis.
"""

import os
from typing import Optional, Any
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Response from LLM."""
    success: bool = True
    content: str = ""
    error_message: Optional[str] = None
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    
    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class AnthropicClient:
    """
    Client for Anthropic Claude API.
    
    Handles:
    - Message completion
    - Token tracking
    - Error handling
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ):
        """
        Initialize the Anthropic client.
        
        Args:
            api_key: API key (uses ANTHROPIC_API_KEY env var if not provided)
            model: Model to use
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature (0 = deterministic)
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        
        self._client = None
        self._available = None
    
    @property
    def available(self) -> bool:
        """Check if the client is available (has API key)."""
        if self._available is None:
            self._available = bool(self.api_key)
        return self._available
    
    def _get_client(self):
        """Get or create the Anthropic client."""
        if self._client is None:
            if not self.available:
                raise ValueError("ANTHROPIC_API_KEY not set")
            
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError("anthropic package not installed. Run: pip install anthropic")
        
        return self._client
    
    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> LLMResponse:
        """
        Send a completion request to Claude.
        
        Args:
            prompt: User message
            system_prompt: System prompt (optional)
            max_tokens: Override default max tokens
            temperature: Override default temperature
            
        Returns:
            LLMResponse with content or error
        """
        if not self.available:
            return LLMResponse(
                success=False,
                error_message="ANTHROPIC_API_KEY not configured",
            )
        
        try:
            client = self._get_client()
            
            # Build messages
            messages = [{"role": "user", "content": prompt}]
            
            # Make request
            response = client.messages.create(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature if temperature is not None else self.temperature,
                system=system_prompt or "",
                messages=messages,
            )
            
            # Extract content
            content = ""
            if response.content:
                for block in response.content:
                    if hasattr(block, "text"):
                        content += block.text
            
            return LLMResponse(
                success=True,
                content=content,
                model=response.model,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            )
            
        except Exception as e:
            return LLMResponse(
                success=False,
                error_message=str(e),
            )
    
    def analyze(
        self,
        data: str,
        analysis_type: str,
        context: Optional[str] = None,
    ) -> LLMResponse:
        """
        Analyze data using Claude.
        
        Args:
            data: Data to analyze
            analysis_type: Type of analysis (e.g., "vulnerability", "fingerprint", "exploit")
            context: Additional context
            
        Returns:
            LLMResponse with analysis
        """
        system_prompts = {
            "vulnerability": """You are a security analyst. Analyze the provided data for potential vulnerabilities.
Be specific about CVEs, severity, and exploitation potential.
Format your response as structured findings.""",
            
            "fingerprint": """You are a security analyst. Analyze the provided service fingerprint data.
Identify the software, version, and any known vulnerabilities.
Be precise about version numbers and CVE matches.""",
            
            "exploit": """You are a security researcher. Based on the provided vulnerability data,
suggest potential exploitation approaches. Be specific about techniques and tools.
Always emphasize that authorization is required before testing.""",
            
            "report": """You are a security report writer. Generate a clear, professional vulnerability report
based on the provided findings. Include severity, impact, and remediation recommendations.""",
        }
        
        system = system_prompts.get(analysis_type, "You are a helpful security assistant.")
        
        prompt = data
        if context:
            prompt = f"Context:\n{context}\n\nData to analyze:\n{data}"
        
        return self.complete(prompt, system_prompt=system)


# Singleton instance
_client: Optional[AnthropicClient] = None


def get_llm_client() -> AnthropicClient:
    """Get the global LLM client instance."""
    global _client
    if _client is None:
        _client = AnthropicClient()
    return _client


def reset_llm_client() -> None:
    """Reset the global LLM client (for testing)."""
    global _client
    _client = None
