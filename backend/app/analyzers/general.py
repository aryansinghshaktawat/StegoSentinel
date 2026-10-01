"""
General forensic analyzer for StegoSentinel.
Performs cryptographic hashing, magic-byte MIME identification, extension mismatch detection,
Shannon entropy calculation, printable character ratio, string extraction, and trailing data detection.
"""
import hashlib
import math
import re
from pathlib import Path
from typing import Dict, List, Tuple
from app.analyzers.base import BaseAnalyzer, AnalysisContext, FindingData

# Comprehensive magic byte signatures table
MAGIC_SIGNATURES: List[Tuple[bytes, int, str, str]] = [
    # (magic_bytes, offset, mime_type, standard_extension)
    (b"\x89PNG\r\n\x1a\n", 0, "image/png", ".png"),
    (b"BM", 0, "image/bmp", ".bmp"),
    (b"\xff\xd8\xff", 0, "image/jpeg", ".jpg"),
    (b"GIF87a", 0, "image/gif", ".gif"),
    (b"GIF89a", 0, "image/gif", ".gif"),
    (b"RIFF", 0, "audio/wav", ".wav"),  # Will verify "WAVE" at offset 8
    (b"PK\x03\x04", 0, "application/zip", ".zip"),
    (b"%PDF-", 0, "application/pdf", ".pdf"),
    (b"\x7fELF", 0, "application/x-executable", ".elf"),
    (b"MZ", 0, "application/x-dosexec", ".exe"),
    (b"7z\xbc\xaf\x27\x1c", 0, "application/x-7z-compressed", ".7z"),
    (b"Rar!\x1a\x07", 0, "application/x-rar-compressed", ".rar"),
]


def detect_magic(data: bytes, filename: str) -> Tuple[str, str, bool]:
    """
    Detect actual MIME type and extension from magic bytes.
    Returns: (detected_mime, expected_ext, is_mismatch)
    """
    detected_mime = "application/octet-stream"
    expected_ext = ""

    # Check magic byte table
    for magic, offset, mime, ext in MAGIC_SIGNATURES:
        if len(data) >= offset + len(magic) and data[offset : offset + len(magic)] == magic:
            # Special check for WAV (needs "WAVE" at offset 8)
            if magic == b"RIFF" and (len(data) < 12 or data[8:12] != b"WAVE"):
                continue
            detected_mime = mime
            expected_ext = ext
            break

    # If no binary magic match, check if it's UTF-8 / plain text
    if detected_mime == "application/octet-stream":
        try:
            data[:4096].decode("utf-8")
            detected_mime = "text/plain"
            expected_ext = ".txt"
        except UnicodeDecodeError:
            pass

    # Check extension mismatch
    file_ext = Path(filename).suffix.lower()
    is_mismatch = False
    if expected_ext and file_ext:
        # Standardize .jpeg and .jpg
        norm_file = ".jpg" if file_ext in [".jpeg", ".jpg"] else file_ext
        norm_exp = ".jpg" if expected_ext in [".jpeg", ".jpg"] else expected_ext
        if norm_file != norm_exp:
            is_mismatch = True

    return detected_mime, expected_ext, is_mismatch


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (range 0.0 - 8.0)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_sliding_window_entropy(data: bytes, window_size: int = 512, step: int = 256) -> List[float]:
    """Calculate entropy across sliding windows to detect localized injected data."""
    if len(data) < window_size:
        return [calculate_entropy(data)]
    entropies = []
    for i in range(0, len(data) - window_size + 1, step):
        chunk = data[i : i + window_size]
        entropies.append(calculate_entropy(chunk))
    return entropies


def extract_strings_and_ratios(data: bytes, min_len: int = 4) -> Tuple[float, float, List[str]]:
    """
    Calculate printable character ratio, null byte ratio, and extract ASCII strings.
    """
    if not data:
        return 0.0, 0.0, []

    printable_count = 0
    null_count = 0
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            printable_count += 1
        elif b == 0:
            null_count += 1

    printable_ratio = round(printable_count / len(data), 4)
    null_ratio = round(null_count / len(data), 4)

    # Extract strings
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    matches = [m.group(0).decode("ascii", errors="replace") for m in pattern.finditer(data[:65536])]

    return printable_ratio, null_ratio, matches[:50]


def detect_trailing_data(data: bytes, mime_type: str) -> Tuple[bool, int, bytes]:
    """
    Detect appended overlay data past format end-of-file markers.
    Returns (has_trailing_data, offset, trailing_bytes).
    """
    if mime_type == "image/jpeg":
        # JPEG ends with EOI: 0xFF 0xD9
        eoi = data.rfind(b"\xff\xd9")
        if eoi != -1 and eoi + 2 < len(data):
            trailing = data[eoi + 2 :]
            return True, eoi + 2, trailing
    elif mime_type == "image/png":
        # PNG ends with IEND chunk: 4-byte length (00 00 00 00) + "IEND" + 4-byte CRC
        iend = data.rfind(b"IEND")
        if iend != -1 and iend + 8 < len(data):
            trailing = data[iend + 8 :]
            return True, iend + 8, trailing

    return False, 0, b""


class GeneralForensicAnalyzer(BaseAnalyzer):
    name = "GeneralForensicAnalyzer"
    version = "1.0.0"

    def can_analyze(self, context: AnalysisContext) -> bool:
        return True  # Applies to all files

    def analyze(self, context: AnalysisContext) -> List[FindingData]:
        findings: List[FindingData] = []
        data = context.file_bytes

        # 1. Cryptographic Hashes
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()

        findings.append(
            FindingData(
                type="CRYPTOGRAPHIC_HASHES",
                severity="INFO",
                confidence=1.0,
                description="Computed cryptographic hash identifiers for chain of custody.",
                evidence={
                    "sha256": sha256,
                    "sha512": sha512,
                    "md5": md5,
                    "file_size": len(data),
                },
                analyzer=self.name,
                analyzer_version=self.version,
            )
        )

        # 2. Magic byte detection & extension mismatch
        detected_mime, expected_ext, is_mismatch = detect_magic(data, context.filename)
        context.mime_type = detected_mime

        findings.append(
            FindingData(
                type="FILE_IDENTIFICATION",
                severity="INFO",
                confidence=1.0,
                description=f"Identified file signature as {detected_mime}.",
                evidence={
                    "detected_mime": detected_mime,
                    "expected_extension": expected_ext,
                    "actual_filename": context.filename,
                },
                analyzer=self.name,
                analyzer_version=self.version,
            )
        )

        if is_mismatch:
            findings.append(
                FindingData(
                    type="EXTENSION_MISMATCH",
                    severity="HIGH",
                    confidence=0.95,
                    description=(
                        f"File extension '{Path(context.filename).suffix}' does not match "
                        f"detected binary magic type '{detected_mime}' (expected {expected_ext})."
                    ),
                    evidence={
                        "filename": context.filename,
                        "expected_extension": expected_ext,
                        "detected_mime": detected_mime,
                    },
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        # 3. Shannon Entropy
        entropy = calculate_entropy(data)
        context.metadata["entropy"] = entropy
        sliding_entropies = calculate_sliding_window_entropy(data)
        max_sliding = max(sliding_entropies) if sliding_entropies else entropy

        entropy_severity = "INFO"
        if entropy > 7.9:
            entropy_severity = "HIGH"
            desc = f"Extremely high Shannon entropy ({entropy:.4f}/8.0). High probability of encryption or compressed/encrypted stego payload."
        elif entropy > 7.5:
            entropy_severity = "MEDIUM"
            desc = f"High Shannon entropy ({entropy:.4f}/8.0). Indicates compressed or packed content."
        else:
            desc = f"Measured standard Shannon entropy of {entropy:.4f}/8.0."

        findings.append(
            FindingData(
                type="ENTROPY_ANALYSIS",
                severity=entropy_severity,
                confidence=0.85,
                description=desc,
                evidence={
                    "global_entropy": entropy,
                    "max_window_entropy": max_sliding,
                    "window_samples_count": len(sliding_entropies),
                },
                analyzer=self.name,
                analyzer_version=self.version,
            )
        )

        # 4. Printable character & string extraction
        printable_ratio, null_ratio, strings = extract_strings_and_ratios(data)
        context.metadata["printable_ratio"] = printable_ratio

        # Suspicious string search
        suspicious_patterns = [
            (r"(?:powershell|cmd\.exe|/bin/sh|/bin/bash)", "SUSPICIOUS_SHELL_COMMAND"),
            (r"(?:http://|https://|ftp://)[^\s\"'>]+", "EMBEDDED_URL"),
            (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "EMBEDDED_IPV4"),
        ]
        found_suspicious = []
        for s in strings:
            for pat, ptype in suspicious_patterns:
                if re.search(pat, s, re.IGNORECASE):
                    found_suspicious.append({"pattern_type": ptype, "match": s[:100]})

        if found_suspicious:
            findings.append(
                FindingData(
                    type="SUSPICIOUS_STRINGS_DETECTED",
                    severity="MEDIUM",
                    confidence=0.8,
                    description=f"Discovered {len(found_suspicious)} suspicious indicator strings in binary data.",
                    evidence={"matches": found_suspicious[:10]},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        # 5. Trailing / Overlay Data Detection
        has_trailing, offset, trailing_bytes = detect_trailing_data(data, detected_mime)
        if has_trailing:
            context.metadata["trailing_data"] = trailing_bytes
            context.metadata["trailing_offset"] = offset
            findings.append(
                FindingData(
                    type="TRAILING_DATA_OVERLAY",
                    severity="HIGH",
                    confidence=0.98,
                    description=(
                        f"Detected {len(trailing_bytes)} bytes of unparsed appended overlay data "
                        f"past the standard end-of-file marker (offset 0x{offset:X})."
                    ),
                    evidence={
                        "offset": offset,
                        "trailing_size": len(trailing_bytes),
                        "trailing_entropy": calculate_entropy(trailing_bytes),
                        "sample_hex": trailing_bytes[:32].hex(),
                    },
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        return findings
