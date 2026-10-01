from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    model: str
    prompt_version: int
    result: dict[str, Any]
    markdown_content: str
    created_at: datetime
