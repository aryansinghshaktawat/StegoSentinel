"""
Interpretable ML candidate ranking engine for StegoSentinel.
Evaluates candidate feature vectors using calibrated scoring weights,
producing defensible probabilities and feature importance metrics.
"""
from typing import Any, Dict, Tuple
from app.ai.features import extract_candidate_features


class CandidateRanker:
    """Interpretable Tabular Candidate Ranker."""

    # Hand-calibrated ground-truth feature weights based on DFIR stego analysis
    WEIGHTS: Dict[str, float] = {
        "magic_match_score": 0.40,
        "printable_ratio": 0.25,
        "utf8_validity": 0.15,
        "compression_indicator": 0.10,
        "chi_square_p": 0.05,
        "shannon_entropy": 0.05,  # Normalized 0-8 to 0-1
    }

    def score_candidate(
        self, candidate_bytes: bytes, chi_square_p: float = 0.5
    ) -> Tuple[float, Dict[str, float], Dict[str, float]]:
        """
        Evaluate candidate bitstream.
        Returns: (ml_score, feature_vector, feature_importances)
        """
        features = extract_candidate_features(candidate_bytes, chi_square_p=chi_square_p)

        # Normalize shannon entropy (0 to 8 scaled to 0 to 1, optimal stego range is 4.0 - 7.9)
        norm_entropy = min(1.0, features["shannon_entropy"] / 8.0)

        # Linear combination of features
        raw_score = (
            features["magic_match_score"] * self.WEIGHTS["magic_match_score"]
            + features["printable_ratio"] * self.WEIGHTS["printable_ratio"]
            + features["utf8_validity"] * self.WEIGHTS["utf8_validity"]
            + features["compression_indicator"] * self.WEIGHTS["compression_indicator"]
            + (1.0 - features["chi_square_p"]) * self.WEIGHTS["chi_square_p"]
            + norm_entropy * self.WEIGHTS["shannon_entropy"]
        )

        ml_score = max(0.0, min(1.0, round(raw_score, 4)))

        # Feature importances reflecting contribution
        feature_importances = {
            "magic_signature": self.WEIGHTS["magic_match_score"],
            "printable_text": self.WEIGHTS["printable_ratio"],
            "utf8_validity": self.WEIGHTS["utf8_validity"],
            "compression_headers": self.WEIGHTS["compression_indicator"],
            "chi_square_anomaly": self.WEIGHTS["chi_square_p"],
            "entropy_distribution": self.WEIGHTS["shannon_entropy"],
        }

        return ml_score, features, feature_importances


# Global ranker instance
ranker = CandidateRanker()
