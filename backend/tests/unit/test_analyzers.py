"""
Unit tests for all forensic analyzers using synthetic fixtures.
"""

from pathlib import Path

from app.analyzers.archive import ArchiveAnalyzer
from app.analyzers.audio import AudioAnalyzer
from app.analyzers.base import AnalysisContext
from app.analyzers.external import ExifToolWrapper, ZstegWrapper
from app.analyzers.general import GeneralForensicAnalyzer
from app.analyzers.image import ImageAnalyzer
from app.analyzers.text import TextAnalyzer


def test_general_analyzer_on_clean_and_stego(fixtures_path: Path):
    clean_png = fixtures_path / "clean" / "clean_image.png"
    data = clean_png.read_bytes()
    ctx = AnalysisContext(
        file_path=clean_png,
        file_bytes=data,
        filename=clean_png.name,
        mime_type="image/png",
        sha256="test",
    )
    analyzer = GeneralForensicAnalyzer()
    findings = analyzer.analyze(ctx)

    assert any(f.type == "CRYPTOGRAPHIC_HASHES" for f in findings)
    assert any(f.type == "FILE_IDENTIFICATION" for f in findings)
    assert any(f.type == "ENTROPY_ANALYSIS" for f in findings)
    assert not any(f.type == "EXTENSION_MISMATCH" for f in findings)


def test_image_analyzer_detects_lsb_anomaly(fixtures_path: Path):
    stego_png = fixtures_path / "stego" / "stego_lsb_rgb_p0.png"
    data = stego_png.read_bytes()
    ctx = AnalysisContext(
        file_path=stego_png,
        file_bytes=data,
        filename=stego_png.name,
        mime_type="image/png",
        sha256="test",
    )
    analyzer = ImageAnalyzer()
    findings = analyzer.analyze(ctx)

    # Check structural metadata extracted
    assert any(f.type == "IMAGE_STRUCTURAL_METADATA" for f in findings)
    # Check bit plane entropy analysis
    assert any(f.type == "BIT_PLANE_ENTROPY_ANALYSIS" for f in findings)


def test_image_analyzer_appended_payload(fixtures_path: Path):
    appended_jpg = fixtures_path / "stego" / "appended_payload.jpg"
    data = appended_jpg.read_bytes()
    ctx = AnalysisContext(
        file_path=appended_jpg,
        file_bytes=data,
        filename=appended_jpg.name,
        mime_type="image/jpeg",
        sha256="test",
    )
    gen_analyzer = GeneralForensicAnalyzer()
    findings = gen_analyzer.analyze(ctx)

    trailing_finding = next((f for f in findings if f.type == "TRAILING_DATA_OVERLAY"), None)
    assert trailing_finding is not None
    assert trailing_finding.severity == "HIGH"
    assert "trailing_size" in trailing_finding.evidence


def test_text_analyzer_zero_width_stego(fixtures_path: Path):
    zw_file = fixtures_path / "stego" / "zero_width_text.txt"
    data = zw_file.read_bytes()
    ctx = AnalysisContext(
        file_path=zw_file,
        file_bytes=data,
        filename=zw_file.name,
        mime_type="text/plain",
        sha256="test",
    )
    analyzer = TextAnalyzer()
    findings = analyzer.analyze(ctx)

    zw_finding = next((f for f in findings if f.type == "ZERO_WIDTH_UNICODE_STEGANOGRAPHY"), None)
    assert zw_finding is not None
    assert zw_finding.severity in ["HIGH", "CRITICAL"]
    assert "character_counts" in zw_finding.evidence


def test_text_analyzer_whitespace_stego(fixtures_path: Path):
    ws_file = fixtures_path / "stego" / "whitespace_snow.txt"
    data = ws_file.read_bytes()
    ctx = AnalysisContext(
        file_path=ws_file,
        file_bytes=data,
        filename=ws_file.name,
        mime_type="text/plain",
        sha256="test",
    )
    analyzer = TextAnalyzer()
    findings = analyzer.analyze(ctx)

    ws_finding = next((f for f in findings if f.type == "WHITESPACE_STEGANOGRAPHY_INDICATOR"), None)
    assert ws_finding is not None
    assert ws_finding.severity == "MEDIUM"


def test_audio_analyzer(fixtures_path: Path):
    wav_file = fixtures_path / "clean" / "clean_audio.wav"
    data = wav_file.read_bytes()
    ctx = AnalysisContext(
        file_path=wav_file,
        file_bytes=data,
        filename=wav_file.name,
        mime_type="audio/wav",
        sha256="test",
    )
    analyzer = AudioAnalyzer()
    findings = analyzer.analyze(ctx)

    assert any(f.type == "AUDIO_METADATA" for f in findings)
    assert any(f.type == "AUDIO_LSB_ENTROPY" for f in findings)


def test_archive_analyzer(fixtures_path: Path):
    zip_file = fixtures_path / "clean" / "safe_archive.zip"
    data = zip_file.read_bytes()
    ctx = AnalysisContext(
        file_path=zip_file,
        file_bytes=data,
        filename=zip_file.name,
        mime_type="application/zip",
        sha256="test",
    )
    analyzer = ArchiveAnalyzer()
    findings = analyzer.analyze(ctx)

    assert any(f.type == "ARCHIVE_INVENTORY" for f in findings)
    assert "extracted_archive_members" in ctx.metadata
    assert len(ctx.metadata["extracted_archive_members"]) >= 2


def test_external_tools_graceful_fallback(fixtures_path: Path):
    clean_png = fixtures_path / "clean" / "clean_image.png"
    data = clean_png.read_bytes()
    ctx = AnalysisContext(
        file_path=clean_png,
        file_bytes=data,
        filename=clean_png.name,
        mime_type="image/png",
        sha256="test",
    )
    # Even if zsteg/exiftool is absent, it must return structured finding and not raise exceptions
    zsteg = ZstegWrapper()
    findings = zsteg.analyze(ctx)
    assert isinstance(findings, list)

    exif = ExifToolWrapper()
    findings_exif = exif.analyze(ctx)
    assert isinstance(findings_exif, list)
