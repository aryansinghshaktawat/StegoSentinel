"""
Unit tests for coarse-to-fine candidate generation, ML scoring, and validation.
"""

from pathlib import Path

from app.ai.features import extract_candidate_features
from app.ai.scorer import ranker
from app.analyzers.base import AnalysisContext
from app.candidates.generator import candidate_generator
from app.extraction.validators import validate_candidate_bytes


def test_feature_vector_extraction():
    # Plain text sample
    text_data = b"FLAG{FORENSIC_VALIDATION_STRING_12345}"
    features = extract_candidate_features(text_data)

    assert "shannon_entropy" in features
    assert "printable_ratio" in features
    assert "magic_match_score" in features
    assert "utf8_validity" in features
    assert features["printable_ratio"] > 0.95
    assert features["utf8_validity"] == 1.0


def test_candidate_scorer_ranking():
    # Valid text should score high
    text_data = b"FLAG{CONFIDENTIAL_COMMUNICATION_FOUND}"
    ml_score, features, importances = ranker.score_candidate(text_data)

    assert ml_score > 0.50
    assert "printable_text" in importances
    assert "entropy_distribution" in importances

    # Null bytes or random noise should score lower
    noise_data = b"\x00\x00\x00\x00" * 32
    noise_score, _, _ = ranker.score_candidate(noise_data)
    assert noise_score < ml_score


def test_candidate_validator_types():
    # 1. Text payload
    res_text = validate_candidate_bytes(b"FLAG{CONFIDENTIAL_MESSAGE_BODY}")
    assert res_text.status == "VALID"
    assert res_text.extracted_type == "text/plain"

    # 2. ZIP payload
    res_zip = validate_candidate_bytes(b"PK\x03\x04\x14\x00\x00\x00\x08\x00")
    assert res_zip.status == "VALID"
    assert res_zip.extracted_type == "application/zip"

    # 3. Empty payload
    res_empty = validate_candidate_bytes(b"")
    assert res_empty.status == "INVALID"


def test_rgb_lsb_extraction_returns_bytes(fixtures_path: Path):
    import io

    import numpy as np
    from PIL import Image

    from app.candidates.generator import extract_image_bitstream

    stego_png = fixtures_path / "stego" / "stego_lsb_rgb_p0.png"
    img = Image.open(io.BytesIO(stego_png.read_bytes())).convert("RGB")
    arr = np.array(img)
    extracted = extract_image_bitstream(arr, channel_mode="RGB", bit_plane=0, order="sequential", stride=1, max_bytes=2048)
    assert isinstance(extracted, bytes)
    assert len(extracted) > 0
    assert b"FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}" in extracted


def test_utf8_text_candidate_recognized_and_decoded():
    # 2. UTF-8 text candidate recognized
    # 3. decoded_text populated
    # 4. payload size is correct
    # 5. encoding is UTF-8
    # 6. decode_status is SUCCESS
    sample_text = b"FLAG{FORENSIC_DECODED_PAYLOAD_TEST_12345}\x00extra_carrier_noise_bits"
    res = validate_candidate_bytes(sample_text)
    assert res.status == "VALID"
    assert res.extracted_type == "text/plain"
    assert res.decode_status == "SUCCESS"
    assert res.encoding == "UTF-8"
    assert res.decoded_text == "FLAG{FORENSIC_DECODED_PAYLOAD_TEST_12345}"
    assert res.payload_size == len(b"FLAG{FORENSIC_DECODED_PAYLOAD_TEST_12345}")


def test_invalid_candidate_produces_no_decoded_text():
    # 7. invalid candidate produces no decoded_text
    garbage_bytes = bytes([0xFF, 0xFE, 0xFD, 0xFC, 0x01, 0x02, 0x03, 0x80, 0x81, 0x82, 0x83])
    res = validate_candidate_bytes(garbage_bytes)
    assert res.decoded_text is None
    assert res.decode_status in ["INVALID", "UNKNOWN_BINARY", "ENCRYPTED_OR_UNKNOWN"]
    assert res.status != "VALID"


def test_binary_candidate_identified_correctly():
    # 8. binary candidate is identified correctly
    zip_bytes = b"PK\x03\x04" + b"\x00" * 30
    res_zip = validate_candidate_bytes(zip_bytes)
    assert res_zip.status == "VALID"
    assert res_zip.extracted_type == "application/zip"
    assert res_zip.decode_status == "IDENTIFIED"
    assert res_zip.decoded_text is None
    assert res_zip.payload_size == len(zip_bytes)

    # High entropy binary
    high_entropy_bytes = bytes(range(256)) * 4
    res_high_entropy = validate_candidate_bytes(high_entropy_bytes)
    assert res_high_entropy.decode_status in ["ENCRYPTED_OR_UNKNOWN", "UNKNOWN_BINARY", "INVALID"]
    assert res_high_entropy.decoded_text is None


def test_candidate_generator_on_stego_image(fixtures_path: Path):
    stego_png = fixtures_path / "stego" / "stego_lsb_rgb_p0.png"
    data = stego_png.read_bytes()
    ctx = AnalysisContext(
        file_path=stego_png,
        file_bytes=data,
        filename=stego_png.name,
        mime_type="image/png",
        sha256="test",
        max_candidates=50,
    )

    candidates = candidate_generator.generate_candidates(ctx, budget=50)
    assert len(candidates) > 0

    # Top candidate should be LSB RGB Plane 0 Sequential
    top_cand = candidates[0]
    assert top_cand.parameters["bit_plane"] == 0
    assert top_cand.parameters["channel"] == "RGB"
    assert top_cand.final_score > 0.60
    assert top_cand.status == "VALID"
    assert top_cand.decode_status == "SUCCESS"
    assert top_cand.decoded_text == "FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}"
    assert top_cand.payload_size == 45
    assert top_cand.encoding == "UTF-8"

