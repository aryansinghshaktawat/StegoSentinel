from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class CandidateBase(BaseModel):
    technique: str
    parameters: dict[str, Any]
    feature_vector: dict[str, Any] | None = None
    raw_score: float = 0.0
    ml_score: float = 0.0
    validation_score: float = 0.0
    final_score: float = 0.0
    status: str = "UNKNOWN"
    extracted_type: str | None = None
    printable_ratio: float | None = None
    validation_description: str | None = None
    payload_size: int | None = None
    encoding: str | None = None
    decode_status: str = "NOT_ATTEMPTED"
    decoded_text: str | None = None
    evidence_object_id: str | None = None


class CandidateCreate(CandidateBase):
    analysis_id: str


class CandidateRead(CandidateBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    created_at: datetime


class CandidatePayloadEvidence(BaseModel):
    id: str
    name: str
    sha256: str
    size: int
    detected_type: str
    download_url: str


class CandidatePayload(BaseModel):
    """Recovered payload view. Binary content is referenced via evidence, never inlined."""

    candidate_id: str
    analysis_id: str
    technique: str
    status: str
    type: str | None = None
    payload_size: int | None = None
    encoding: str | None = None
    decode_status: str
    decoded_text: str | None = None
    evidence_object_id: str | None = None
    evidence: CandidatePayloadEvidence | None = None
