from datetime import datetime
from typing import Any, Dict
from pydantic import BaseModel, ConfigDict


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    model: str
    prompt_version: int
    result: Dict[str, Any]
    markdown_content: str
    created_at: datetime
