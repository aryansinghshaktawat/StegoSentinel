"""
Coarse-to-fine steganographic candidate generation engine for StegoSentinel.
Systematically generates, filters, validates, and ranks extraction hypotheses.
"""

import io
from dataclasses import dataclass
from typing import Any

import numpy as np
from PIL import Image

from app.ai.scorer import ranker
from app.analyzers.base import AnalysisContext
from app.candidates.search_space import CandidateParameters
from app.core.limits import LIMITS
from app.extraction.validators import ValidationResult, validate_candidate_bytes


@dataclass
class CandidateResult:
    technique: str
    parameters: dict[str, Any]
    feature_vector: dict[str, float]
    raw_score: float
    ml_score: float
    validation_score: float
    final_score: float
    status: str
    extracted_type: str
    printable_ratio: float
    extracted_bytes: bytes


def extract_image_bitstream(
    img_arr: np.ndarray,
    channel_mode: str,
    bit_plane: int,
    order: str = "sequential",
    stride: int = 1,
    max_bytes: int = 4096,
) -> bytes:
    """Extract raw bits from numpy image array given candidate parameters."""
    # Select channels
    if channel_mode == "RGB":
        channels = [0, 1, 2]
    elif channel_mode == "BGR":
        channels = [2, 1, 0]
    elif channel_mode == "R":
        channels = [0]
    elif channel_mode == "G":
        channels = [1]
    elif channel_mode == "B":
        channels = [2]
    elif channel_mode == "RGBA" and img_arr.shape[2] >= 4:
        channels = [0, 1, 2, 3]
    else:
        channels = [0]

    height, width, _ = img_arr.shape
    bits = []

    if order == "sequential":
        for y in range(0, height, stride):
            for x in range(0, width, stride):
                for c in channels:
                    bit = (int(img_arr[y, x, c]) >> bit_plane) & 1
                    bits.append(bit)
                    if len(bits) >= max_bytes * 8:
                        break
                if len(bits) >= max_bytes * 8:
                    break
            if len(bits) >= max_bytes * 8:
                break
    else:  # column-major
        for x in range(0, width, stride):
            for y in range(0, height, stride):
                for c in channels:
                    bit = (int(img_arr[y, x, c]) >> bit_plane) & 1
                    bits.append(bit)
                    if len(bits) >= max_bytes * 8:
                        break
                if len(bits) >= max_bytes * 8:
                    break
            if len(bits) >= max_bytes * 8:
                break

    if not bits or len(bits) < 8:
        return b""

    # Convert bit list to bytes (MSB first)
    byte_vals = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for b in range(8):
            byte_val = (byte_val << 1) | bits[i + b]
        byte_vals.append(byte_val)

    return bytes(byte_vals)


class CandidateGenerator:
    """Generates extraction hypotheses across supported media formats."""

    def generate_candidates(
        self, context: AnalysisContext, budget: int = 100
    ) -> list[CandidateResult]:
        hard_limit = min(budget, context.max_candidates, LIMITS.MAX_CANDIDATES)
        candidates: list[CandidateResult] = []

        if context.mime_type.startswith("image/"):
            candidates.extend(self._generate_image_candidates(context, hard_limit))

        # Sort candidates descending by final_score
        candidates.sort(key=lambda c: c.final_score, reverse=True)
        return candidates[:hard_limit]

    def _generate_image_candidates(
        self, context: AnalysisContext, hard_limit: int
    ) -> list[CandidateResult]:
        results: list[CandidateResult] = []
        try:
            img = Image.open(io.BytesIO(context.file_bytes)).convert("RGB")
            img_arr = np.array(img)
        except Exception:
            return results

        # Parameter permutations (Coarse-to-fine search space)
        channel_options = ["RGB", "R", "G", "B", "BGR"]
        plane_options = [0, 1]  # LSB and second LSB
        order_options = ["sequential", "column"]
        stride_options = [1, 2]

        evaluated_count = 0

        for plane in plane_options:
            for ch in channel_options:
                for order in order_options:
                    for stride in stride_options:
                        if evaluated_count >= hard_limit:
                            break

                        evaluated_count += 1
                        params = CandidateParameters(
                            channel=ch,
                            bit_plane=plane,
                            order=order,
                            stride=stride,
                            endian="msb_first",
                        )

                        # Extract candidate stream
                        extracted = extract_image_bitstream(
                            img_arr,
                            channel_mode=ch,
                            bit_plane=plane,
                            order=order,
                            stride=stride,
                            max_bytes=2048,
                        )

                        # Validate candidate payload
                        val_res: ValidationResult = validate_candidate_bytes(extracted)

                        # ML Score & Feature extraction
                        ml_score, features, _ = ranker.score_candidate(extracted)

                        # Raw score based on printable ratio & entropy
                        raw_score = round(
                            (val_res.printable_ratio * 0.7)
                            + (0.3 if val_res.is_known_format else 0.0),
                            4,
                        )

                        # Final ensemble score
                        final_score = round(
                            (0.40 * ml_score)
                            + (0.45 * val_res.validation_score)
                            + (0.15 * raw_score),
                            4,
                        )

                        results.append(
                            CandidateResult(
                                technique=f"LSB_{ch}_P{plane}_{order[:3].upper()}",
                                parameters=params.to_dict(),
                                feature_vector=features,
                                raw_score=raw_score,
                                ml_score=ml_score,
                                validation_score=val_res.validation_score,
                                final_score=final_score,
                                status=val_res.status,
                                extracted_type=val_res.extracted_type,
                                printable_ratio=val_res.printable_ratio,
                                extracted_bytes=extracted,
                            )
                        )

        return results


candidate_generator = CandidateGenerator()
