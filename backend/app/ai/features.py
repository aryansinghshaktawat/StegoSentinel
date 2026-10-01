"""
Feature extraction vector for StegoSentinel candidate ranking.
Extracts 8-dimensional statistical and structural features from candidate bitstreams.
"""
from typing import Any, Dict
import numpy as np
from app.analyzers.general import calculate_entropy, extract_strings_and_ratios, MAGIC_SIGNATURES


def extract_candidate_features(data: bytes, chi_square_p: float = 0.5) -> Dict[str, float]:
    """Extract tabular feature vector from extracted candidate bytes."""
    if not data:
        return {
            "shannon_entropy": 0.0,
            "printable_ratio": 0.0,
            "chi_square_p": chi_square_p,
            "magic_match_score": 0.0,
            "byte_repetition_rate": 0.0,
            "utf8_validity": 0.0,
            "null_byte_ratio": 0.0,
            "compression_indicator": 0.0,
        }

    sample = data[:2048]
    entropy = calculate_entropy(sample)
    printable_ratio, null_ratio, _ = extract_strings_and_ratios(sample)

    # Magic byte match check
    magic_match = 0.0
    for magic, offset, _, _ in MAGIC_SIGNATURES:
        if len(sample) >= offset + len(magic) and sample[offset : offset + len(magic)] == magic:
            magic_match = 1.0
            break

    # UTF-8 validity ratio
    try:
        sample.decode("utf-8")
        utf8_validity = 1.0
    except UnicodeDecodeError as e:
        valid_bytes = e.start
        utf8_validity = round(valid_bytes / len(sample), 4)

    # Byte repetition rate (measure of compressibility / non-randomness)
    arr = np.frombuffer(sample, dtype=np.uint8)
    diffs = np.diff(arr)
    repetition_rate = round(float(np.mean(diffs == 0)), 4) if len(diffs) > 0 else 0.0

    # Compression header indicator (Deflate, gzip, zlib, zip)
    compression = 1.0 if sample.startswith((b"\x1f\x8b", b"\x78\x9c", b"\x78\x01", b"PK\x03\x04")) else 0.0

    return {
        "shannon_entropy": round(entropy, 4),
        "printable_ratio": round(printable_ratio, 4),
        "chi_square_p": round(chi_square_p, 4),
        "magic_match_score": magic_match,
        "byte_repetition_rate": repetition_rate,
        "utf8_validity": utf8_validity,
        "null_byte_ratio": round(null_ratio, 4),
        "compression_indicator": compression,
    }
