"""
Candidate payload validation and decoding engine for StegoSentinel.

Interpretation pipeline (static only; payloads are never executed):
    extracted bytes -> magic signature -> delimited text -> text encodings -> entropy -> verdict

Validation (is this stream structured?) and decoding (can we render it as text?) are
reported separately so a candidate can be VALID yet undecodable (e.g. a ZIP payload).
"""

import base64
import binascii
import re
from dataclasses import dataclass, field

from app.analyzers.general import MAGIC_SIGNATURES, calculate_entropy, extract_strings_and_ratios


class DecodeStatus:
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    IDENTIFIED = "IDENTIFIED"
    UNKNOWN_BINARY = "UNKNOWN_BINARY"
    ENCRYPTED_OR_UNKNOWN = "ENCRYPTED_OR_UNKNOWN"
    INVALID = "INVALID"
    FAILED = "FAILED"


MAX_DECODED_TEXT_BYTES = 64 * 1024

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


@dataclass
class ValidationResult:
    status: str  # VALID, PARTIAL, INVALID, UNKNOWN
    extracted_type: str
    validation_score: float  # 0.0 to 1.0
    printable_ratio: float
    description: str
    is_known_format: bool
    payload_size: int = 0
    encoding: str | None = None
    decoded_text: str | None = None
    decode_status: str = DecodeStatus.NOT_ATTEMPTED
    # Bytes the payload verdict refers to. For delimited text this excludes the terminator
    # and trailing carrier noise; otherwise it is the full extracted stream.
    payload_bytes: bytes = field(default=b"", repr=False)


def _utf8_prefix(data: bytes) -> tuple[str, bool]:
    """Decode the longest valid UTF-8 prefix. Returns (text, decoded_entire_input)."""
    try:
        return data.decode("utf-8"), True
    except UnicodeDecodeError as exc:
        return data[: exc.start].decode("utf-8"), False


def _text_representation_note(text: str) -> str:
    """
    Flag text that looks like a transport encoding. We only report the resemblance;
    secondary decoding is left to the analyst so ordinary words are never "decoded".
    """
    compact = text.strip()
    if len(compact) < 16 or any(c.isspace() for c in compact):
        return ""
    if _HEX_RE.match(compact):
        try:
            binascii.unhexlify(compact)
            return " Content resembles hexadecimal encoding; secondary decoding not applied."
        except binascii.Error:
            return ""
    if len(compact) % 4 == 0 and _BASE64_RE.match(compact):
        try:
            base64.b64decode(compact, validate=True)
            return " Content resembles Base64 encoding; secondary decoding not applied."
        except binascii.Error:
            return ""
    return ""


def validate_candidate_bytes(data: bytes) -> ValidationResult:
    """Validate and, where appropriate, decode an extracted bitstream candidate."""
    if not data or len(data) < 4:
        return ValidationResult(
            status="INVALID",
            extracted_type="empty",
            validation_score=0.0,
            printable_ratio=0.0,
            description="Extracted candidate contains insufficient bytes.",
            is_known_format=False,
            payload_size=len(data or b""),
            decode_status=DecodeStatus.INVALID,
            payload_bytes=data or b"",
        )

    # 1. Known binary signatures: identified, never rendered as text.
    for magic, offset, mime, ext in MAGIC_SIGNATURES:
        if len(data) >= offset + len(magic) and data[offset : offset + len(magic)] == magic:
            return ValidationResult(
                status="VALID",
                extracted_type=mime,
                validation_score=1.0,
                printable_ratio=0.1,
                description=f"Identified valid binary magic signature: {mime} ({ext}).",
                is_known_format=True,
                payload_size=len(data),
                decode_status=DecodeStatus.IDENTIFIED,
                payload_bytes=data,
            )

    # 2. Null-terminated text: the terminator marks the embedded payload's end, and
    # everything after it is untouched carrier LSB noise, so the payload is the prefix.
    first_null = data.find(b"\x00")
    if first_null != -1 and first_null >= 6:
        prefix = data[:first_null]
        p_prefix, _, _ = extract_strings_and_ratios(prefix)
        if p_prefix >= 0.80:
            try:
                decoded_prefix = prefix.decode("utf-8")
            except UnicodeDecodeError:
                decoded_prefix = None
            if decoded_prefix is not None:
                return ValidationResult(
                    status="VALID",
                    extracted_type="text/plain",
                    validation_score=0.95,
                    printable_ratio=p_prefix,
                    description=(
                        f"Extracted null-terminated UTF-8 text payload ({len(prefix)} bytes)."
                        + _text_representation_note(decoded_prefix)
                    ),
                    is_known_format=True,
                    payload_size=len(prefix),
                    encoding="UTF-8",
                    decoded_text=decoded_prefix,
                    decode_status=DecodeStatus.SUCCESS,
                    payload_bytes=prefix,
                )

    # 3. Undelimited text across a sample window.
    printable_ratio, null_ratio, _ = extract_strings_and_ratios(data[:1024])
    entropy = calculate_entropy(data[:1024])

    try:
        sample_text = data[:1024].decode("utf-8")
    except UnicodeDecodeError:
        sample_text = None

    if sample_text is not None:
        if printable_ratio >= 0.85:
            has_flag = any(
                k in sample_text for k in ["FLAG{", "flag{", "CONFIDENTIAL", "SECRET", "http"]
            )
            score = 0.95 if has_flag else 0.85
            capped = data[:MAX_DECODED_TEXT_BYTES]
            text, complete = _utf8_prefix(capped)
            complete = complete and len(capped) == len(data)
            payload = text.encode("utf-8")
            return ValidationResult(
                status="VALID",
                extracted_type="text/plain",
                validation_score=score,
                printable_ratio=printable_ratio,
                description=(
                    f"Valid UTF-8 plain text extracted ({printable_ratio * 100:.1f}% printable)."
                    + ("" if complete else " Decoded text is truncated at the first invalid byte.")
                    + _text_representation_note(text)
                ),
                is_known_format=True,
                payload_size=len(payload),
                encoding="UTF-8",
                decoded_text=text,
                decode_status=DecodeStatus.SUCCESS if complete else DecodeStatus.PARTIAL,
                payload_bytes=payload,
            )
        if printable_ratio >= 0.60:
            # Readable fragments mixed with binary: do not present it as a decoded message.
            return ValidationResult(
                status="PARTIAL",
                extracted_type="text/partial",
                validation_score=0.5,
                printable_ratio=printable_ratio,
                description="Partially readable text stream with interspersed binary tokens.",
                is_known_format=False,
                payload_size=len(data),
                decode_status=DecodeStatus.FAILED,
                payload_bytes=data,
            )

    # 4. High-entropy stream: could be ciphertext/compressed data. Never brute-forced.
    if entropy >= 7.8 and null_ratio < 0.05:
        return ValidationResult(
            status="PARTIAL",
            extracted_type="application/octet-stream-high-entropy",
            validation_score=0.4,
            printable_ratio=printable_ratio,
            description=f"High entropy bitstream ({entropy:.2f}/8.0), possible encrypted or compressed payload.",
            is_known_format=False,
            payload_size=len(data),
            decode_status=DecodeStatus.ENCRYPTED_OR_UNKNOWN,
            payload_bytes=data,
        )

    return ValidationResult(
        status="INVALID",
        extracted_type="application/octet-stream",
        validation_score=0.05,
        printable_ratio=printable_ratio,
        description="Candidate bitstream lacks structural or textual cohesion.",
        is_known_format=False,
        payload_size=len(data),
        decode_status=DecodeStatus.INVALID,
        payload_bytes=data,
    )
