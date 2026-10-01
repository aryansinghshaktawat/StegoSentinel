#!/usr/bin/env python3
"""
Generate safe, synthetic forensic test fixtures for StegoSentinel.
No live malware. Fully reproducible, deterministic synthetic artifacts.
"""
import io
import math
import os
import struct
import wave
import zipfile
import zlib
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
CLEAN_DIR = FIXTURES_DIR / "clean"
STEGO_DIR = FIXTURES_DIR / "stego"
MALFORMED_DIR = FIXTURES_DIR / "malformed"
NESTED_DIR = FIXTURES_DIR / "nested"


def create_png_bytes(width: int, height: int, pixels: list) -> bytes:
    """Create a valid PNG file from a list of RGB pixel tuples [(r,g,b), ...]."""
    raw_scanlines = bytearray()
    for y in range(height):
        raw_scanlines.append(0)  # Filter type 0: None
        for x in range(width):
            idx = y * width + x
            r, g, b = pixels[idx]
            raw_scanlines.extend((r & 0xFF, g & 0xFF, b & 0xFF))

    compressed = zlib.compress(bytes(raw_scanlines), level=9)

    def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
        length = len(data)
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", length) + chunk_type + data + struct.pack(">I", crc)

    header = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr = png_chunk(b"IHDR", ihdr_data)
    idat = png_chunk(b"IDAT", compressed)
    iend = png_chunk(b"IEND", b"")
    return header + ihdr + idat + iend


def create_bmp_bytes(width: int, height: int, pixels: list) -> bytes:
    """Create a valid 24-bit uncompressed BMP file."""
    row_size = (width * 3 + 3) & ~3
    image_size = row_size * height
    file_size = 54 + image_size

    # File Header (14 bytes)
    header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
    # DIB Header (40 bytes, BITMAPINFOHEADER)
    dib = struct.pack(
        "<IIIHHIIIIII",
        40, width, height, 1, 24, 0, image_size, 2835, 2835, 0, 0
    )

    pixel_data = bytearray(image_size)
    # BMP is bottom-to-top
    for y in range(height):
        row_idx = (height - 1 - y) * row_size
        for x in range(width):
            r, g, b = pixels[y * width + x]
            offset = row_idx + x * 3
            pixel_data[offset] = b & 0xFF
            pixel_data[offset + 1] = g & 0xFF
            pixel_data[offset + 2] = r & 0xFF

    return header + dib + bytes(pixel_data)


def create_minimal_jpeg(extra_trailing_bytes: bytes = b"") -> bytes:
    """Create a minimal valid baseline JPEG with optional trailing overlay."""
    # SOI (FF D8) + APP0 (JFIF) + DQT + SOF0 + DHT + SOS + Data + EOI (FF D9)
    soi = b"\xff\xd8"
    app0 = (
        b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00"
    )
    # Minimal 1x1 white pixel JPEG bytes
    jpeg_body = bytes([
        0xFF, 0xDB, 0x00, 0x43, 0x00,
        0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
        0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19,
        0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C,
        0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C,
        0x28, 0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27,
        0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32,
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01,
        0x11, 0x00,
        0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7F,
        0x00,
        0xFF, 0xD9  # EOI
    ])
    return soi + app0 + jpeg_body + extra_trailing_bytes


def generate_all_fixtures():
    """Build and write all synthetic test fixtures."""
    for d in [CLEAN_DIR, STEGO_DIR, MALFORMED_DIR, NESTED_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    print("[*] Generating clean and stego images...")
    width, height = 64, 64
    base_pixels = []
    for y in range(height):
        for x in range(width):
            r = int((x / width) * 200 + 20)
            g = int((y / height) * 200 + 20)
            b = int(((x + y) / (width + height)) * 200 + 20)
            base_pixels.append((r, g, b))

    # 1. Clean PNG
    clean_png = create_png_bytes(width, height, base_pixels)
    (CLEAN_DIR / "clean_image.png").write_bytes(clean_png)

    # 2. Stego LSB PNG (Embed message into LSB of R, G, B channels in Plane 0)
    secret_msg = b"FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}" + b"\x00"
    stego_pixels = list(base_pixels)
    bit_stream = []
    for byte in secret_msg:
        for bit_idx in range(8):
            bit_stream.append((byte >> (7 - bit_idx)) & 1)

    bit_cursor = 0
    for i in range(len(stego_pixels)):
        r, g, b = stego_pixels[i]
        if bit_cursor < len(bit_stream):
            r = (r & ~1) | bit_stream[bit_cursor]
            bit_cursor += 1
        if bit_cursor < len(bit_stream):
            g = (g & ~1) | bit_stream[bit_cursor]
            bit_cursor += 1
        if bit_cursor < len(bit_stream):
            b = (b & ~1) | bit_stream[bit_cursor]
            bit_cursor += 1
        stego_pixels[i] = (r, g, b)

    stego_png = create_png_bytes(width, height, stego_pixels)
    (STEGO_DIR / "stego_lsb_rgb_p0.png").write_bytes(stego_png)

    # 3. Stego Blue Channel PNG
    blue_pixels = list(base_pixels)
    bit_cursor = 0
    for i in range(len(blue_pixels)):
        r, g, b = blue_pixels[i]
        if bit_cursor < len(bit_stream):
            b = (b & ~1) | bit_stream[bit_cursor]
            bit_cursor += 1
        blue_pixels[i] = (r, g, b)
    (STEGO_DIR / "stego_blue_channel.png").write_bytes(
        create_png_bytes(width, height, blue_pixels)
    )

    # 4. Clean BMP
    clean_bmp = create_bmp_bytes(width, height, base_pixels)
    (CLEAN_DIR / "clean_sample.bmp").write_bytes(clean_bmp)

    # 5. Stego BMP
    stego_bmp = create_bmp_bytes(width, height, stego_pixels)
    (STEGO_DIR / "stego_lsb_sample.bmp").write_bytes(stego_bmp)

    # 6. Clean JPEG
    (CLEAN_DIR / "clean_sample.jpg").write_bytes(create_minimal_jpeg())

    # 7. Appended Payload JPEG (overlay past EOI)
    appended_overlay = b"STEGO_OVERLAY_DATA_PAST_EOI_OFFSET_DETECTED_0x4A10"
    (STEGO_DIR / "appended_payload.jpg").write_bytes(
        create_minimal_jpeg(extra_trailing_bytes=appended_overlay)
    )

    print("[*] Generating text steganography fixtures...")
    # 8. Clean text
    clean_text = (
        "Forensic analysis report for incident case 2026-X9.\n"
        "The preliminary triage shows normal operational log events.\n"
        "No anomalous data transfers observed on standard ports.\n"
    )
    (CLEAN_DIR / "clean_text.txt").write_text(clean_text, encoding="utf-8")

    # 9. Zero-width Unicode stego
    # Encode 'SECRET' into zero-width space (\u200B = 0) and zero-width non-joiner (\u200C = 1)
    secret_text = "SECRET"
    zw_bits = ""
    for char in secret_text:
        zw_bits += format(ord(char), "08b")
    zw_encoded = "".join("\u200b" if b == "0" else "\u200c" for b in zw_bits)
    zw_full_text = f"Forensic analysis report {zw_encoded}for incident case 2026-X9.\n"
    (STEGO_DIR / "zero_width_text.txt").write_text(zw_full_text, encoding="utf-8")

    # 10. Whitespace SNOW stego (spaces and tabs at line ends)
    whitespace_text = (
        "Line one of legitimate report.   \t \n"
        "Line two with trailing spaces.  \t\t\n"
        "Line three conclusion.\n"
    )
    (STEGO_DIR / "whitespace_snow.txt").write_text(whitespace_text, encoding="utf-8")

    # 11. Encoded text
    encoded_text = (
        "System Log Header\n"
        "PAYLOAD_BLOB: U1RFR09TRU5USU5FTF9EQVRBX0JBU0U2NF9FTkNPREVECg==\n"
        "End of log.\n"
    )
    (STEGO_DIR / "encoded_text.txt").write_text(encoded_text, encoding="utf-8")

    print("[*] Generating audio fixtures...")
    # 12. Clean WAV (1 sec 440 Hz sine wave)
    sample_rate = 8000
    duration = 0.5
    clean_audio_buf = io.BytesIO()
    with wave.open(clean_audio_buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)  # 16-bit
        wf.setframerate(sample_rate)
        total_samples = int(sample_rate * duration)
        raw_samples = bytearray()
        for s in range(total_samples):
            val = int(10000 * math.sin(2 * math.pi * 440 * s / sample_rate))
            raw_samples.extend(struct.pack("<h", val))
        wf.writeframes(raw_samples)
    clean_wav_bytes = clean_audio_buf.getvalue()
    (CLEAN_DIR / "clean_audio.wav").write_bytes(clean_wav_bytes)

    # 13. Stego WAV (Embed into LSB of 16-bit audio samples)
    stego_audio_buf = io.BytesIO()
    with wave.open(stego_audio_buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        stego_raw = bytearray()
        for s in range(total_samples):
            val = int(10000 * math.sin(2 * math.pi * 440 * s / sample_rate))
            if s < len(bit_stream):
                val = (val & ~1) | bit_stream[s]
            stego_raw.extend(struct.pack("<h", val))
        wf.writeframes(stego_raw)
    (STEGO_DIR / "stego_audio.wav").write_bytes(stego_audio_buf.getvalue())

    print("[*] Generating archive fixtures...")
    # 14. Safe ZIP
    safe_zip_path = CLEAN_DIR / "safe_archive.zip"
    with zipfile.ZipFile(safe_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("document1.txt", "Legitimate internal memo.")
        zf.writestr("config.json", '{"status": "active", "security": true}')

    # 15. Nested ZIP
    inner_zip_buf = io.BytesIO()
    with zipfile.ZipFile(inner_zip_buf, "w", zipfile.ZIP_DEFLATED) as izf:
        izf.writestr("confidential_payload.txt", "TOP SECRET PAYLOAD CONTENT")
    with zipfile.ZipFile(NESTED_DIR / "nested_test.zip", "w", zipfile.ZIP_DEFLATED) as nzf:
        nzf.writestr("readme.txt", "Outer archive containing inner archive.")
        nzf.writestr("inner_archive.zip", inner_zip_buf.getvalue())

    print("[*] Generating malformed & security test fixtures...")
    # 16. Extension Mismatch (ELF executable disguised as PNG)
    elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
    (MALFORMED_DIR / "extension_mismatch.png").write_bytes(elf_header)

    # 17. Zip Slip Traversal Attack fixture
    zip_slip_path = MALFORMED_DIR / "zip_slip_traversal.zip"
    with zipfile.ZipFile(zip_slip_path, "w") as zf:
        # Intentionally create entry with directory traversal path
        zf.writestr("../../traversal_target.txt", "MALICIOUS TRAVERSAL CONTENT")

    print("[+] All synthetic forensic fixtures successfully generated in fixtures/")


if __name__ == "__main__":
    generate_all_fixtures()
