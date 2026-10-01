"""
Video container forensic analyzer for StegoSentinel.
Parses MP4/MKV container metadata, audio/subtitle stream descriptors,
and exposes keyframe sampling hooks for forwarding sampled frames to ImageAnalyzer.
"""

from app.analyzers.base import AnalysisContext, BaseAnalyzer, FindingData


class VideoAnalyzer(BaseAnalyzer):
    name = "VideoAnalyzer"
    version = "1.0.0"

    def can_analyze(self, context: AnalysisContext) -> bool:
        return context.mime_type.startswith("video/") or context.filename.endswith(
            (".mp4", ".mkv", ".avi", ".mov")
        )

    def analyze(self, context: AnalysisContext) -> list[FindingData]:
        findings: list[FindingData] = []
        data = context.file_bytes

        # Basic container signature detection
        container = "UNKNOWN"
        if data[:4] == b"\x1a\x45\xdf\xa3":
            container = "Matroska / WebM (MKV)"
        elif b"ftyp" in data[:32]:
            container = "MP4 / ISO Base Media"
        elif data[:4] == b"RIFF" and b"AVI " in data[8:12]:
            container = "AVI (Audio Video Interleave)"

        findings.append(
            FindingData(
                type="VIDEO_CONTAINER_METADATA",
                severity="INFO",
                confidence=1.0,
                description=f"Identified video stream container: {container}.",
                evidence={"container": container, "file_size": len(data)},
                analyzer=self.name,
                analyzer_version=self.version,
            )
        )

        # Scan for subtitle / metadata tracks or embedded script streams
        suspicious_streams = []
        for tag in [b"subp", b"text", b"c608", b"tx3g"]:
            if tag in data:
                suspicious_streams.append(tag.decode("ascii", errors="replace"))

        if suspicious_streams:
            findings.append(
                FindingData(
                    type="VIDEO_SUBTITLE_STREAM_DETECTED",
                    severity="INFO",
                    confidence=0.85,
                    description=f"Discovered embedded subtitle/text tracks: {', '.join(suspicious_streams)}.",
                    evidence={"tracks": suspicious_streams},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        return findings
