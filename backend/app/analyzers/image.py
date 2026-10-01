"""
Native image steganalysis engine for StegoSentinel.
Performs channel separation, bit-plane decomposition (planes 0-7),
Shannon entropy per plane, Chi-square (PoV) statistical tests, and chunk validation.
Supports PNG, BMP, JPEG, GIF.
"""

import io
import math

import numpy as np
from PIL import Image

from app.analyzers.base import AnalysisContext, BaseAnalyzer, FindingData
from app.analyzers.general import calculate_entropy


def perform_chi_square_test(channel_data: np.ndarray) -> tuple[float, float]:
    """
    Perform Chi-Square attack on Pairs of Values (PoVs 2k, 2k+1).
    Sequential LSB embedding equalizes frequencies of 2k and 2k+1.
    Returns: (chi_square_stat, p_value_estimate)
    """
    flat = channel_data.flatten()
    counts = np.bincount(flat, minlength=256)

    chi_sq = 0.0
    degrees_of_freedom = 0

    for k in range(128):
        y_2k = counts[2 * k]
        y_2k1 = counts[2 * k + 1]
        expected = (y_2k + y_2k1) / 2.0
        if expected > 5.0:  # Valid frequency bucket
            chi_sq += ((y_2k - expected) ** 2) / expected
            chi_sq += ((y_2k1 - expected) ** 2) / expected
            degrees_of_freedom += 1

    # Approximate p-value based on chi-square statistic
    # Low chi-square when expected is large indicates artificial PoV equalization
    if degrees_of_freedom > 0:
        norm_chi = chi_sq / degrees_of_freedom
        p_val = max(0.0, min(1.0, 1.0 - math.erf(norm_chi / math.sqrt(2))))
    else:
        norm_chi = 0.0
        p_val = 0.5

    return round(float(chi_sq), 3), round(float(p_val), 4)


class ImageAnalyzer(BaseAnalyzer):
    name = "ImageAnalyzer"
    version = "1.0.0"

    def can_analyze(self, context: AnalysisContext) -> bool:
        return context.mime_type.startswith("image/")

    def analyze(self, context: AnalysisContext) -> list[FindingData]:
        findings: list[FindingData] = []
        try:
            img = Image.open(io.BytesIO(context.file_bytes))
        except Exception as e:
            findings.append(
                FindingData(
                    type="IMAGE_DECODE_ERROR",
                    severity="LOW",
                    confidence=0.9,
                    description=f"Unable to parse image structure: {e!s}",
                    evidence={"error": str(e)},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )
            return findings

        # Basic image metadata
        width, height = img.size
        mode = img.mode
        img_format = img.format or "UNKNOWN"

        findings.append(
            FindingData(
                type="IMAGE_STRUCTURAL_METADATA",
                severity="INFO",
                confidence=1.0,
                description=f"Decoded {img_format} image: {width}x{height} pixels, Mode: {mode}.",
                evidence={
                    "width": width,
                    "height": height,
                    "mode": mode,
                    "format": img_format,
                    "info_keys": list(img.info.keys()),
                },
                analyzer=self.name,
                analyzer_version=self.version,
            )
        )

        # Convert image to RGB numpy array for bit-plane and channel inspection
        rgb_img = img.convert("RGB")
        img_arr = np.array(rgb_img)

        channels = {"Red": img_arr[:, :, 0], "Green": img_arr[:, :, 1], "Blue": img_arr[:, :, 2]}

        bit_plane_metrics: dict[str, dict[int, float]] = {}
        high_entropy_planes: list[dict[str, str]] = []

        for ch_name, ch_data in channels.items():
            bit_plane_metrics[ch_name] = {}
            for plane in range(8):
                # Extract bit plane (plane 0 = LSB, plane 7 = MSB)
                plane_bits = ((ch_data >> plane) & 1).astype(np.uint8)
                # Compute entropy of bit plane
                bit_bytes = np.packbits(plane_bits).tobytes()
                p_entropy = calculate_entropy(bit_bytes)
                bit_plane_metrics[ch_name][plane] = p_entropy

                # In natural images, bit plane 0 entropy is usually structured and below 7.9.
                # An injected stego payload typically drives entropy very close to 8.0 (>= 7.92).
                if plane == 0 and p_entropy >= 7.90:
                    high_entropy_planes.append(
                        {
                            "channel": ch_name,
                            "plane": "Plane 0 (LSB)",
                            "entropy": str(p_entropy),
                        }
                    )

            # Perform Chi-Square test on the channel
            chi_stat, p_val = perform_chi_square_test(ch_data)
            if p_val < 0.05 and chi_stat > 100:
                findings.append(
                    FindingData(
                        type="CHI_SQUARE_LSB_ANOMALY",
                        severity="HIGH",
                        confidence=0.88,
                        description=(
                            f"{ch_name} channel exhibits statistically significant Pairs of Values (PoV) "
                            f"equalization (p={p_val}, chi2={chi_stat}), indicating potential sequential LSB embedding."
                        ),
                        evidence={
                            "channel": ch_name,
                            "chi_square_stat": chi_stat,
                            "p_value": p_val,
                        },
                        analyzer=self.name,
                        analyzer_version=self.version,
                    )
                )

        # Record bit-plane entropy finding
        severity = "HIGH" if high_entropy_planes else "INFO"
        desc = (
            f"Detected {len(high_entropy_planes)} bit-planes with anomalous high entropy (stego indicator)."
            if high_entropy_planes
            else "Bit-plane entropy distribution matches expected natural photographic variance."
        )

        findings.append(
            FindingData(
                type="BIT_PLANE_ENTROPY_ANALYSIS",
                severity=severity,
                confidence=0.85,
                description=desc,
                evidence={
                    "anomalous_planes": high_entropy_planes,
                    "plane_entropies": bit_plane_metrics,
                },
                analyzer=self.name,
                analyzer_version=self.version,
            )
        )

        # PNG specific chunk inspection
        if img_format == "PNG":
            png_findings = self._inspect_png_chunks(context.file_bytes)
            findings.extend(png_findings)

        return findings

    def _inspect_png_chunks(self, data: bytes) -> list[FindingData]:
        """Inspect PNG chunk signatures for anomalies or non-standard private chunks."""
        findings = []
        offset = 8  # Skip 8-byte PNG header
        standard_chunks = {
            b"IHDR",
            b"PLTE",
            b"IDAT",
            b"IEND",
            b"tRNS",
            b"cHRM",
            b"gAMA",
            b"iCCP",
            b"sBIT",
            b"sRGB",
            b"tEXt",
            b"zTXt",
            b"iTXt",
            b"bKGD",
            b"hIST",
            b"pHYs",
            b"sPLT",
            b"tIME",
        }
        anomalous_chunks = []

        while offset + 8 <= len(data):
            try:
                length = int.from_bytes(data[offset : offset + 4], "big")
                chunk_type = data[offset + 4 : offset + 8]
                offset += 8 + length + 4  # Length + Type + Data + CRC
                if chunk_type not in standard_chunks:
                    anomalous_chunks.append(
                        {
                            "type": chunk_type.decode("latin-1", errors="replace"),
                            "length": length,
                        }
                    )
                if chunk_type == b"IEND":
                    break
            except Exception:
                break

        if anomalous_chunks:
            findings.append(
                FindingData(
                    type="NON_STANDARD_PNG_CHUNKS",
                    severity="MEDIUM",
                    confidence=0.85,
                    description=f"Identified {len(anomalous_chunks)} non-standard or private PNG chunks.",
                    evidence={"chunks": anomalous_chunks},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        return findings
