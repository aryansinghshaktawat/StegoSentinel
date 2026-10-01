"""
Base analyzer contract and analysis context for StegoSentinel.
"""

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FindingData:
    type: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: dict[str, Any] | None = None
    analyzer: str = "BaseAnalyzer"
    analyzer_version: str = "1.0.0"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class AnalysisContext:
    file_path: Path
    file_bytes: bytes
    filename: str
    mime_type: str
    sha256: str
    recursion_depth: int = 0
    max_candidates: int = 100
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseAnalyzer(ABC):
    name: str = "BaseAnalyzer"
    version: str = "1.0.0"

    @abstractmethod
    def can_analyze(self, context: AnalysisContext) -> bool:
        """Return True if this analyzer handles the given file context."""

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> list[FindingData]:
        """Execute forensic analysis and return list of standardized findings."""
