from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.schemas.candidate import CandidateRead
from app.schemas.evidence import EvidenceObjectRead
from app.schemas.finding import FindingRead


class AnalysisBase(BaseModel):
    original_filename: str


class AnalysisCreate(AnalysisBase):
    generate_report: bool = True
    max_candidates: int = 100


class AnalysisSummary(AnalysisBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str | None = None
    status: str
    sha256: str
    sha512: str | None = None
    size: int
    detected_type: str
    entropy: float | None = None
    stego_likelihood: float | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None


class AnalysisDetail(AnalysisSummary):
    findings: list[FindingRead] = []
    candidates: list[CandidateRead] = []
    evidence_objects: list[EvidenceObjectRead] = []
