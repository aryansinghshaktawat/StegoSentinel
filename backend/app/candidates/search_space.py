"""
Steganographic hypothesis parameter definitions for StegoSentinel.
"""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CandidateParameters:
    channel: str  # "RGB", "R", "G", "B", "RGBA", "BGR"
    bit_plane: int  # 0 to 7 (0 = LSB)
    order: str  # "sequential" (row-major) or "column" (col-major)
    stride: int  # 1, 2, 4
    endian: str  # "msb_first" or "lsb_first"

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "bit_plane": self.bit_plane,
            "order": self.order,
            "stride": self.stride,
            "endian": self.endian,
        }
