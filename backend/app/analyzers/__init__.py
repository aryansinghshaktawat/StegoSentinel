"""
Forensic analyzers registry for StegoSentinel.
"""

from app.analyzers.archive import ArchiveAnalyzer
from app.analyzers.audio import AudioAnalyzer
from app.analyzers.base import AnalysisContext, BaseAnalyzer, FindingData
from app.analyzers.document import DocumentAnalyzer
from app.analyzers.external import (
    BinwalkWrapper,
    ExifToolWrapper,
    SteghideWrapper,
    ZstegWrapper,
)
from app.analyzers.general import GeneralForensicAnalyzer
from app.analyzers.image import ImageAnalyzer
from app.analyzers.text import TextAnalyzer
from app.analyzers.video import VideoAnalyzer

ALL_ANALYZERS: list[BaseAnalyzer] = [
    GeneralForensicAnalyzer(),
    ImageAnalyzer(),
    TextAnalyzer(),
    ArchiveAnalyzer(),
    AudioAnalyzer(),
    DocumentAnalyzer(),
    VideoAnalyzer(),
    ExifToolWrapper(),
    ZstegWrapper(),
    SteghideWrapper(),
    BinwalkWrapper(),
]


def run_all_analyzers(context: AnalysisContext) -> list[FindingData]:
    """Execute all compatible analyzers against the target context."""
    all_findings: list[FindingData] = []
    for analyzer in ALL_ANALYZERS:
        try:
            if analyzer.can_analyze(context):
                findings = analyzer.analyze(context)
                all_findings.extend(findings)
        except Exception as e:
            all_findings.append(
                FindingData(
                    type="ANALYZER_EXECUTION_FAULT",
                    severity="LOW",
                    confidence=0.5,
                    description=f"Analyzer '{analyzer.name}' encountered an error: {e!s}",
                    evidence={"analyzer": analyzer.name, "error": str(e)},
                    analyzer=analyzer.name,
                    analyzer_version=analyzer.version,
                )
            )
    return all_findings


__all__ = [
    "ALL_ANALYZERS",
    "AnalysisContext",
    "ArchiveAnalyzer",
    "AudioAnalyzer",
    "BaseAnalyzer",
    "BinwalkWrapper",
    "DocumentAnalyzer",
    "ExifToolWrapper",
    "FindingData",
    "GeneralForensicAnalyzer",
    "ImageAnalyzer",
    "SteghideWrapper",
    "TextAnalyzer",
    "VideoAnalyzer",
    "ZstegWrapper",
    "run_all_analyzers",
]
