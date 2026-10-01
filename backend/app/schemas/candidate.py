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


class CandidateCreate(CandidateBase):
    analysis_id: str


class CandidateRead(CandidateBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    created_at: datetime
