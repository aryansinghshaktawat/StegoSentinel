"""
LLM Provider registry for StegoSentinel.
"""

from app.ai.llm.mock_provider import MockLLMProvider
from app.ai.llm.openai_provider import OpenAIProvider
from app.ai.llm.provider import LLMProvider
from app.core.config import settings


def get_llm_provider() -> LLMProvider:
    """Return active LLM provider based on settings."""
    if settings.LLM_PROVIDER == "openai" and settings.LLM_API_KEY:
        return OpenAIProvider(api_key=settings.LLM_API_KEY, model=settings.LLM_MODEL)
    return MockLLMProvider()


__all__ = ["LLMProvider", "MockLLMProvider", "OpenAIProvider", "get_llm_provider"]
