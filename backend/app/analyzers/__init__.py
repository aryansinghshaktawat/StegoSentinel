"""
Forensic analyzers registry for StegoSentinel.
"""
from typing import List
from app.analyzers.base import BaseAnalyzer, AnalysisContext, FindingData
from app.analyzers.general import GeneralForensicAnalyzer
from app.analyzers.image import ImageAnalyzer
from app.analyzers.text import TextAnalyzer
from app.analyzers.archive import ArchiveAnalyzer
from app.analyzers.audio import AudioAnalyzer
from app.analyzers.document import DocumentAnalyzer
from app.analyzers.video import VideoAnalyzer
from app.analyzers.external import (
    ExifToolWrapper,
    ZstegWrapper,
    SteghideWrapper,
    BinwalkWrapper,
)

ALL_ANALYZERS: List[BaseAnalyzer] = [
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


def run_all_analyzers(context: AnalysisContext) -> List[FindingData]:
    """Execute all compatible analyzers against the target context."""
    all_findings: List[FindingData] = []
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
                    description=f"Analyzer '{analyzer.name}' encountered an error: {str(e)}",
                    evidence={"analyzer": analyzer.name, "error": str(e)},
                    analyzer=analyzer.name,
                    analyzer_version=analyzer.version,
                )
            )
    return all_findings


__all__ = [
    "BaseAnalyzer",
    "AnalysisContext",
    "FindingData",
    "GeneralForensicAnalyzer",
    "ImageAnalyzer",
    "TextAnalyzer",
    "ArchiveAnalyzer",
    "AudioAnalyzer",
    "DocumentAnalyzer",
    "VideoAnalyzer",
    "ExifToolWrapper",
    "ZstegWrapper",
    "SteghideWrapper",
    "BinwalkWrapper",
    "ALL_ANALYZERS",
    "run_all_analyzers",
]
