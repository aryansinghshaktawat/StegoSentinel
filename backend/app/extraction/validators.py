"""
Candidate payload validation engine for StegoSentinel.
Determines whether an extracted bitstream represents valid text, structured binary,
an archive, or random noise.
"""
from dataclasses import dataclass
from typing import Optional, Tuple
from app.analyzers.general import MAGIC_SIGNATURES, calculate_entropy, extract_strings_and_ratios


@dataclass
class ValidationResult:
    status: str  # VALID, PARTIAL, INVALID, UNKNOWN
    extracted_type: str
    validation_score: float  # 0.0 to 1.0
    printable_ratio: float
    description: str
    is_known_format: bool


def validate_candidate_bytes(data: bytes) -> ValidationResult:
    """Validate an extracted bitstream candidate."""
    if not data or len(data) < 4:
        return ValidationResult(
            status="INVALID",
            extracted_type="empty",
            validation_score=0.0,
            printable_ratio=0.0,
            description="Extracted candidate contains insufficient bytes.",
            is_known_format=False,
        )

    # 1. Check Known Binary Signatures
    for magic, offset, mime, ext in MAGIC_SIGNATURES:
        if len(data) >= offset + len(magic) and data[offset : offset + len(magic)] == magic:
            return ValidationResult(
                status="VALID",
                extracted_type=mime,
                validation_score=1.0,
                printable_ratio=0.1,
                description=f"Identified valid binary magic signature: {mime} ({ext}).",
                is_known_format=True,
            )

    # 2. Check Text Validity
    printable_ratio, null_ratio, _ = extract_strings_and_ratios(data[:1024])
    entropy = calculate_entropy(data[:1024])

    try:
        sample_text = data[:1024].decode("utf-8")
        if printable_ratio >= 0.85:
            # Check for common flag or readable markers
            has_flag = any(k in sample_text for k in ["FLAG{", "flag{", "CONFIDENTIAL", "SECRET", "http"])
            score = 0.95 if has_flag else 0.85
            return ValidationResult(
                status="VALID",
                extracted_type="text/plain",
                validation_score=score,
                printable_ratio=printable_ratio,
                description=f"Valid UTF-8 plain text extracted ({printable_ratio * 100:.1f}% printable).",
                is_known_format=True,
            )
        elif printable_ratio >= 0.60:
            return ValidationResult(
                status="PARTIAL",
                extracted_type="text/partial",
                validation_score=0.5,
                printable_ratio=printable_ratio,
                description="Partially readable text stream with interspersed binary tokens.",
                is_known_format=False,
            )
    except UnicodeDecodeError:
        pass

    # 3. Check for high-entropy encrypted/compressed payload vs noise
    if entropy >= 7.8 and null_ratio < 0.05:
        return ValidationResult(
            status="PARTIAL",
            extracted_type="application/octet-stream-high-entropy",
            validation_score=0.4,
            printable_ratio=printable_ratio,
            description=f"High entropy bitstream ({entropy:.2f}/8.0), possible encrypted or compressed payload.",
            is_known_format=False,
        )

    return ValidationResult(
        status="INVALID",
        extracted_type="application/octet-stream",
        validation_score=0.05,
        printable_ratio=printable_ratio,
        description="Candidate bitstream lacks structural or textual cohesion.",
        is_known_format=False,
    )
