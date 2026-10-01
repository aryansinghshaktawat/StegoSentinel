from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict
from app.schemas.finding import FindingRead
from app.schemas.candidate import CandidateRead
from app.schemas.evidence import EvidenceObjectRead


class AnalysisBase(BaseModel):
    original_filename: str


class AnalysisCreate(AnalysisBase):
    generate_report: bool = True
    max_candidates: int = 100


class AnalysisSummary(AnalysisBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: Optional[str] = None
    status: str
    sha256: str
    sha512: Optional[str] = None
    size: int
    detected_type: str
    entropy: Optional[float] = None
    stego_likelihood: Optional[float] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class AnalysisDetail(AnalysisSummary):
    findings: List[FindingRead] = []
    candidates: List[CandidateRead] = []
    evidence_objects: List[EvidenceObjectRead] = []
