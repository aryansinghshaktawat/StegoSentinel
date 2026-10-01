from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict


class FindingBase(BaseModel):
    type: str
    severity: str
    confidence: float
    description: str
    evidence: Optional[Dict[str, Any]] = None
    analyzer: str
    analyzer_version: str = "1.0.0"


class FindingCreate(FindingBase):
    analysis_id: str


class FindingRead(FindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    created_at: datetime
