"""
Audio forensic analyzer for StegoSentinel.
Parses WAV PCM streams, inspects RIFF structures, and extracts sample-level LSB features.
"""

import io
import wave

import numpy as np

from app.analyzers.base import AnalysisContext, BaseAnalyzer, FindingData
from app.analyzers.general import calculate_entropy


class AudioAnalyzer(BaseAnalyzer):
    name = "AudioAnalyzer"
    version = "1.0.0"

    def can_analyze(self, context: AnalysisContext) -> bool:
        return context.mime_type in ["audio/wav", "audio/x-wav"] or context.filename.endswith(
            ".wav"
        )

    def analyze(self, context: AnalysisContext) -> list[FindingData]:
        findings: list[FindingData] = []
        try:
            with wave.open(io.BytesIO(context.file_bytes), "rb") as wf:
                channels = wf.getnchannels()
                sampwidth = wf.getsampwidth()
                framerate = wf.getframerate()
                nframes = wf.getnframes()
                raw_frames = wf.readframes(min(nframes, 100_000))  # Read up to 100k frames
        except Exception as e:
            findings.append(
                FindingData(
                    type="AUDIO_DECODE_ERROR",
                    severity="LOW",
                    confidence=0.8,
                    description=f"Could not parse WAV container: {e!s}",
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )
            return findings

        duration = round(nframes / framerate, 2) if framerate > 0 else 0.0

        # Structural metadata finding
        findings.append(
            FindingData(
                type="AUDIO_METADATA",
                severity="INFO",
                confidence=1.0,
                description=f"Parsed WAV PCM: {channels} ch, {sampwidth * 8}-bit, {framerate} Hz, {duration}s.",
                evidence={
                    "channels": channels,
                    "bits_per_sample": sampwidth * 8,
                    "sample_rate": framerate,
                    "total_frames": nframes,
                    "duration_seconds": duration,
                },
                analyzer=self.name,
                analyzer_version=self.version,
            )
        )

        # LSB Extraction on audio samples
        if sampwidth == 2 and raw_frames:  # 16-bit PCM
            samples = np.frombuffer(raw_frames, dtype=np.int16)
            lsb_bits = (samples & 1).astype(np.uint8)
            lsb_bytes = np.packbits(lsb_bits).tobytes()
            lsb_entropy = calculate_entropy(lsb_bytes)

            context.metadata["audio_lsb_bytes"] = lsb_bytes
            context.metadata["audio_lsb_entropy"] = lsb_entropy

            severity = "HIGH" if lsb_entropy >= 7.9 else "INFO"
            desc = (
                f"Audio sample LSB bitstream exhibits high entropy ({lsb_entropy:.4f}/8.0), "
                f"suggesting covert LSB audio steganography."
                if lsb_entropy >= 7.9
                else f"Audio sample LSB entropy is {lsb_entropy:.4f}/8.0 within normal acoustic variance."
            )

            findings.append(
                FindingData(
                    type="AUDIO_LSB_ENTROPY",
                    severity=severity,
                    confidence=0.85,
                    description=desc,
                    evidence={
                        "lsb_entropy": lsb_entropy,
                        "analyzed_samples": len(samples),
                    },
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        return findings
