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
    assert b"FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}" in top_cand.extracted_bytes
