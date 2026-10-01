from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class EvidenceObjectBase(BaseModel):
    name: str
    sha256: str
    size: int
    detected_type: str
    storage_reference: str
    extraction_method: str
    source_offset: int = 0
    recursion_depth: int = 0
    parent_id: Optional[str] = None


class EvidenceObjectCreate(EvidenceObjectBase):
    analysis_id: str


class EvidenceObjectRead(EvidenceObjectBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    created_at: datetime


class EvidenceTreeNode(EvidenceObjectRead):
    children: List["EvidenceTreeNode"] = []
