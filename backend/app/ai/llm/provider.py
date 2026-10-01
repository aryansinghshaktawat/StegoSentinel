"""
LLM Provider abstract interface for StegoSentinel.
Decouples report explanation generation from concrete model providers.
"""

from abc import ABC, abstractmethod
from typing import Any


class LLMProvider(ABC):
    @abstractmethod
    def generate_summary(self, evidence_summary: dict[str, Any]) -> dict[str, Any]:
        """Generate structured forensic explanation and executive briefing."""

    @abstractmethod
    def generate_markdown_report(self, evidence_summary: dict[str, Any]) -> str:
        """Render complete Markdown forensic report."""
