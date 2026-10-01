"""
Hard limits and forensic boundaries for StegoSentinel.
Guards against algorithmic DoS, decompression bombs, and excessive recursion.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ForensicLimits:
    # Maximum size of initial uploaded file (100 MB)
    MAX_UPLOAD_SIZE: int = 100 * 1024 * 1024

    # Maximum file size per extracted evidence object (50 MB)
    MAX_FILE_SIZE_PER_OBJECT: int = 50 * 1024 * 1024

    # Maximum cumulative size of all extracted objects in an analysis (250 MB)
    MAX_TOTAL_EXTRACTED_SIZE: int = 250 * 1024 * 1024

    # Maximum recursion depth for nested archives or payloads
    MAX_RECURSION_DEPTH: int = 3

    # Maximum number of child evidence objects permitted
    MAX_EXTRACTED_OBJECTS: int = 20

    # Hard timeout in seconds for analyzing a single file
    MAX_ANALYSIS_SECONDS: int = 60

    # Hard cap on steganographic candidates generated per file
    MAX_CANDIDATES: int = 1000

    # Maximum archive decompression expansion ratio before triggering zip bomb alert (100:1)
    MAX_DECOMPRESSION_RATIO: float = 100.0


LIMITS = ForensicLimits()
