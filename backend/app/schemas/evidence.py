from datetime import datetime

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
    parent_id: str | None = None


class EvidenceObjectCreate(EvidenceObjectBase):
    analysis_id: str


class EvidenceObjectRead(EvidenceObjectBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    created_at: datetime


class EvidenceTreeNode(EvidenceObjectRead):
    # Derived from the Candidate that produced this object, when it came from stego extraction.
    candidate_id: str | None = None
    decode_status: str | None = None
    decoded_text: str | None = None
    children: list["EvidenceTreeNode"] = []
