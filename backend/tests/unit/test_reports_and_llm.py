"""
Unit tests for forensic report generation, calibration, and LLM explanation layer.
"""

from app.ai.llm.mock_provider import MockLLMProvider
from app.models.base import Candidate, Finding
from app.reports.generator import calculate_overall_stego_likelihood


def test_stego_likelihood_calibration():
    # 1. No findings -> low likelihood (e.g. 0.05)
    score_clean = calculate_overall_stego_likelihood([], [])
    assert score_clean <= 0.10

    # 2. High severity finding -> elevated likelihood
    f_high = Finding(
        type="CHI_SQUARE_LSB_ANOMALY", severity="HIGH", confidence=0.88, description="PoV anomaly"
    )
    score_f = calculate_overall_stego_likelihood([f_high], [])
    assert score_f >= 0.45

    # 3. Valid candidate extracted -> high confidence likelihood
    c_valid = Candidate(technique="LSB_RGB_P0", status="VALID", final_score=0.92, parameters={})
    score_valid = calculate_overall_stego_likelihood([f_high], [c_valid])
    assert score_valid >= 0.85


def test_mock_llm_provider_defensibility():
    provider = MockLLMProvider()
    evidence_summary = {
        "original_filename": "evidence.png",
        "sha256": "abcdef1234567890",
        "detected_type": "image/png",
        "stego_likelihood": 0.88,
        "findings": [
            {"type": "CHI_SQUARE_LSB_ANOMALY", "severity": "HIGH", "description": "PoV anomaly"}
        ],
        "candidates": [
            {"technique": "LSB_RGB_P0", "extracted_type": "text/plain", "final_score": 0.94}
        ],
        "top_candidate": {"technique": "LSB_RGB_P0", "extracted_type": "text/plain"},
        "extracted_objects_count": 1,
    }

    summary = provider.generate_summary(evidence_summary)
    assert "executive_summary" in summary
    assert "Steganography likelihood: 88%" in summary["executive_summary"]
    # Verify defensive disclaimers are present
    assert len(summary["forensic_limitations"]) >= 2

    # Markdown report output
    md = provider.generate_markdown_report(evidence_summary)
    assert "# StegoSentinel Forensic Analysis Report" in md
    assert "88%" in md
    assert "Forensic Limitations" in md
