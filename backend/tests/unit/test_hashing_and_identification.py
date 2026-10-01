"""
Unit tests for cryptographic hashing, magic-byte identification, entropy, and string metrics.
"""

import hashlib

from app.analyzers.general import (
    calculate_entropy,
    calculate_sliding_window_entropy,
    detect_magic,
    detect_trailing_data,
    extract_strings_and_ratios,
)


def test_cryptographic_hashes():
    data = b"STEGOSENTINEL_FORENSIC_EVIDENCE_SAMPLE_BYTES"
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    assert len(sha256) == 64
    assert len(sha512) == 128
    assert len(md5) == 32
    assert sha256 == hashlib.sha256(data).hexdigest()


def test_magic_byte_identification():
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    mime, ext, mismatch = detect_magic(png_header, "image.png")
    assert mime == "image/png"
    assert ext == ".png"
    assert not mismatch

    # Extension mismatch: ELF binary named .png
    elf_data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32
    mime, ext, mismatch = detect_magic(elf_data, "suspicious.png")
    assert mime == "application/x-executable"
    assert mismatch is True


def test_shannon_entropy():
    # Uniform repetitive data: entropy should be near 0
    zero_data = b"\x00" * 1000
    assert calculate_entropy(zero_data) == 0.0

    # Structured English text: typical entropy 3.5 - 4.5
    text_data = b"The quick brown fox jumps over the lazy dog. Digital forensics investigation."
    ent = calculate_entropy(text_data)
    assert 3.0 <= ent <= 5.0

    # High randomness data (simulating encrypted/stego stream)
    random_bytes = bytes([i % 256 for i in range(10000)])
    ent_rand = calculate_entropy(random_bytes)
    assert ent_rand > 7.9


def test_sliding_window_entropy():
    # Half flat, half high-entropy
    flat = b"\x00" * 512
    random_chunk = bytes([i % 256 for i in range(512)])
    composite = flat + random_chunk

    windows = calculate_sliding_window_entropy(composite, window_size=512, step=256)
    assert len(windows) >= 2
    assert windows[0] == 0.0
    assert windows[-1] > 7.0


def test_printable_and_string_extraction():
    data = b"Normal Header\x00\x01\x02SecretMessageHere\x03\x04\x05http://malicious-c2.local/drop"
    p_ratio, null_ratio, strings = extract_strings_and_ratios(data)

    assert p_ratio > 0.5
    assert null_ratio > 0.0
    assert any("SecretMessageHere" in s for s in strings)
    assert any("http://malicious-c2.local/drop" in s for s in strings)


def test_trailing_data_detection():
    # JPEG EOI is 0xFF 0xD9
    jpeg_with_overlay = b"\xff\xd8\xff\xe0JFIF\x00\x00\xff\xd9TRAILING_SECRET_PAYLOAD_HERE"
    has_trailing, offset, trailing_bytes = detect_trailing_data(jpeg_with_overlay, "image/jpeg")

    assert has_trailing is True
    assert trailing_bytes == b"TRAILING_SECRET_PAYLOAD_HERE"
    assert offset == len(jpeg_with_overlay) - len(b"TRAILING_SECRET_PAYLOAD_HERE")
