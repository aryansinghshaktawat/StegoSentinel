"""
Text steganalysis engine for StegoSentinel.
Detects zero-width Unicode characters, bidirectional control markers,
whitespace steganography (SNOW), and encoded blobs.
"""

import re

from app.analyzers.base import AnalysisContext, BaseAnalyzer, FindingData


class TextAnalyzer(BaseAnalyzer):
    name = "TextAnalyzer"
    version = "1.0.0"

    # Suspicious invisible Unicode characters
    ZERO_WIDTH_CHARS = {
        "\u200b": "Zero-Width Space",
        "\u200c": "Zero-Width Non-Joiner",
        "\u200d": "Zero-Width Joiner",
        "\ufeff": "Zero-Width No-Break Space (BOM)",
        "\u2060": "Word Joiner",
        "\u200e": "Left-to-Right Mark",
        "\u200f": "Right-to-Left Mark",
    }

    # Directional overrides (Trojan Source / RTL spoofing)
    BIDI_CHARS = {
        "\u202a": "Left-to-Right Embedding",
        "\u202b": "Right-to-Left Embedding",
        "\u202c": "Pop Directional Formatting",
        "\u202d": "Left-to-Right Override",
        "\u202e": "Right-to-Left Override",
        "\u2066": "Left-to-Right Isolate",
        "\u2067": "Right-to-Left Isolate",
        "\u2068": "First Strong Isolate",
        "\u2069": "Pop Directional Isolate",
    }

    def can_analyze(self, context: AnalysisContext) -> bool:
        return context.mime_type.startswith("text/") or context.filename.endswith(
            (".txt", ".md", ".csv", ".json", ".xml", ".html", ".log")
        )

    def analyze(self, context: AnalysisContext) -> list[FindingData]:
        findings: list[FindingData] = []
        try:
            text = context.file_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            findings.append(
                FindingData(
                    type="TEXT_DECODE_ERROR",
                    severity="LOW",
                    confidence=0.8,
                    description=f"Could not decode text stream: {e!s}",
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )
            return findings

        # 1. Zero-Width Character Detection
        zw_counts: dict[str, int] = {}
        for char, name in self.ZERO_WIDTH_CHARS.items():
            cnt = text.count(char)
            if cnt > 0:
                zw_counts[name] = cnt

        if zw_counts:
            total_zw = sum(zw_counts.values())
            # Attempt to decode binary if zero-width space and non-joiner are present
            decoded_snippet = self._attempt_zw_decode(text)
            context.metadata["zero_width_payload"] = decoded_snippet

            findings.append(
                FindingData(
                    type="ZERO_WIDTH_UNICODE_STEGANOGRAPHY",
                    severity="CRITICAL" if total_zw > 16 else "HIGH",
                    confidence=0.98,
                    description=(
                        f"Detected {total_zw} hidden zero-width invisible Unicode characters "
                        f"indicative of covert text steganography."
                    ),
                    evidence={
                        "character_counts": zw_counts,
                        "decoded_sample": decoded_snippet if decoded_snippet else None,
                    },
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        # 2. Bidirectional Control Markers Detection
        bidi_counts: dict[str, int] = {}
        for char, name in self.BIDI_CHARS.items():
            cnt = text.count(char)
            if cnt > 0:
                bidi_counts[name] = cnt

        if bidi_counts:
            findings.append(
                FindingData(
                    type="BIDI_OVERRIDE_SPOOFING",
                    severity="HIGH",
                    confidence=0.95,
                    description="Detected bidirectional Unicode control characters used for visual spoofing or evasion.",
                    evidence={"bidi_counts": bidi_counts},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        # 3. Trailing Whitespace Analysis (SNOW steganography)
        trailing_lines = []
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            # Check trailing spaces and tabs
            m = re.search(r"[ \t]{2,}$", line)
            if m:
                trailing_lines.append(
                    {
                        "line": idx + 1,
                        "spaces": line.count(" ", m.start()),
                        "tabs": line.count("\t", m.start()),
                    }
                )

        if len(trailing_lines) >= 2:
            findings.append(
                FindingData(
                    type="WHITESPACE_STEGANOGRAPHY_INDICATOR",
                    severity="MEDIUM",
                    confidence=0.85,
                    description=(
                        f"Found {len(trailing_lines)} lines with trailing tabs and spaces, "
                        f"a pattern characteristic of SNOW whitespace steganography."
                    ),
                    evidence={"affected_lines_sample": trailing_lines[:10]},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        # 4. Base64 & Hex Blobs Detection
        b64_pattern = re.compile(
            r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        )
        b64_matches = b64_pattern.findall(text)
        if b64_matches:
            findings.append(
                FindingData(
                    type="EMBEDDED_BASE64_PAYLOAD",
                    severity="LOW",
                    confidence=0.9,
                    description=f"Identified {len(b64_matches)} large Base64-encoded strings.",
                    evidence={"samples": [m[:64] + "..." for m in b64_matches[:5]]},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        return findings

    def _attempt_zw_decode(self, text: str) -> str:
        """Attempt to decode binary stream encoded with \u200b (0) and \u200c (1)."""
        bits = []
        for ch in text:
            if ch == "\u200b":
                bits.append("0")
            elif ch == "\u200c":
                bits.append("1")
        if len(bits) >= 8 and len(bits) % 8 == 0:
            try:
                bit_str = "".join(bits)
                byte_vals = [int(bit_str[i : i + 8], 2) for i in range(0, len(bit_str), 8)]
                return bytes(byte_vals).decode("utf-8", errors="replace")
            except Exception:
                pass
        return ""
