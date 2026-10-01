"""
External forensic tool wrappers for StegoSentinel.
Wraps exiftool, zsteg, steghide, and binwalk with defensive execution and graceful fallbacks.
"""
import shutil
import subprocess
from pathlib import Path
from typing import List
from app.analyzers.base import BaseAnalyzer, AnalysisContext, FindingData


class ExternalToolWrapper(BaseAnalyzer):
    tool_binary: str = ""

    def is_available(self) -> bool:
        return bool(shutil.which(self.tool_binary))

    def run_command(self, args: List[str], timeout: int = 15) -> str:
        """Execute command safely without shell=True."""
        cmd = [self.tool_binary] + args
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return res.stdout[:32768]  # Bound output to 32KB
        except Exception as e:
            return f"ERROR: {str(e)}"


class ExifToolWrapper(ExternalToolWrapper):
    name = "ExifToolWrapper"
    version = "1.0.0"
    tool_binary = "exiftool"

    def can_analyze(self, context: AnalysisContext) -> bool:
        return context.mime_type.startswith("image/") or context.mime_type in [
            "application/pdf",
            "audio/wav",
        ]

    def analyze(self, context: AnalysisContext) -> List[FindingData]:
        if not self.is_available():
            return [
                FindingData(
                    type="TOOL_UNAVAILABLE",
                    severity="INFO",
                    confidence=1.0,
                    description="ExifTool is not installed on this host. Falling back to native metadata extraction.",
                    evidence={"tool": self.tool_binary, "status": "NOT_INSTALLED"},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            ]

        output = self.run_command(["-j", str(context.file_path)])
        return [
            FindingData(
                type="EXIF_METADATA_EXTRACTED",
                severity="INFO",
                confidence=1.0,
                description="Extracted metadata fields via ExifTool.",
                evidence={"raw_metadata_sample": output[:2048]},
                analyzer=self.name,
                analyzer_version=self.version,
            )
        ]


class ZstegWrapper(ExternalToolWrapper):
    name = "ZstegWrapper"
    version = "1.0.0"
    tool_binary = "zsteg"

    def can_analyze(self, context: AnalysisContext) -> bool:
        return context.mime_type in ["image/png", "image/bmp"]

    def analyze(self, context: AnalysisContext) -> List[FindingData]:
        if not self.is_available():
            return [
                FindingData(
                    type="TOOL_UNAVAILABLE",
                    severity="INFO",
                    confidence=1.0,
                    description="zsteg is not installed on this host. Utilizing StegoSentinel native LSB analyzer.",
                    evidence={"tool": self.tool_binary, "status": "NOT_INSTALLED"},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            ]

        output = self.run_command([str(context.file_path)])
        findings = []
        if output and "ERROR" not in output:
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            findings.append(
                FindingData(
                    type="ZSTEG_INDICATORS",
                    severity="HIGH" if len(lines) > 2 else "MEDIUM",
                    confidence=0.9,
                    description=f"zsteg identified {len(lines)} potential steganography signatures.",
                    evidence={"output_lines": lines[:15]},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )
        return findings


class SteghideWrapper(ExternalToolWrapper):
    name = "SteghideWrapper"
    version = "1.0.0"
    tool_binary = "steghide"

    def can_analyze(self, context: AnalysisContext) -> bool:
        return context.mime_type in ["image/jpeg", "image/bmp", "audio/wav"]

    def analyze(self, context: AnalysisContext) -> List[FindingData]:
        if not self.is_available():
            return [
                FindingData(
                    type="TOOL_UNAVAILABLE",
                    severity="INFO",
                    confidence=1.0,
                    description="steghide is not installed on this host.",
                    evidence={"tool": self.tool_binary, "status": "NOT_INSTALLED"},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            ]
        # Attempt info query with blank passphrase
        output = self.run_command(["info", str(context.file_path), "-p", ""])
        return [
            FindingData(
                type="STEGHIDE_INFO",
                severity="INFO",
                confidence=0.8,
                description="Queried file with steghide header check.",
                evidence={"output": output[:1024]},
                analyzer=self.name,
                analyzer_version=self.version,
            )
        ]


class BinwalkWrapper(ExternalToolWrapper):
    name = "BinwalkWrapper"
    version = "1.0.0"
    tool_binary = "binwalk"

    def can_analyze(self, context: AnalysisContext) -> bool:
        return True  # Can scan any binary

    def analyze(self, context: AnalysisContext) -> List[FindingData]:
        if not self.is_available():
            return [
                FindingData(
                    type="TOOL_UNAVAILABLE",
                    severity="INFO",
                    confidence=1.0,
                    description="binwalk is not installed on this host. Using native magic byte scanner.",
                    evidence={"tool": self.tool_binary, "status": "NOT_INSTALLED"},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            ]

        output = self.run_command(["-B", str(context.file_path)])
        return [
            FindingData(
                type="BINWALK_SIGNATURE_SCAN",
                severity="MEDIUM",
                confidence=0.85,
                description="Scanned file offsets for embedded signatures with binwalk.",
                evidence={"output": output[:2048]},
                analyzer=self.name,
                analyzer_version=self.version,
            )
        ]
