"""
Reports API endpoints for StegoSentinel.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.v1.analyses import verify_analysis_access
from app.core.database import get_db
from app.core.security import get_current_user_payload
from app.models.base import Analysis, LLMReport
from app.schemas.report import ReportRead

router = APIRouter(prefix="/analyses/{analysis_id}/report", tags=["Reports"])


@router.get("", response_model=Optional[ReportRead])
def get_analysis_report(
    analysis_id: str,
    format: str = Query("json", enum=["json", "markdown"]),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user_payload),
):
    """Retrieve comprehensive forensic report in JSON or Markdown."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found",
        )
    verify_analysis_access(analysis, current_user)

    report = (
        db.query(LLMReport)
        .filter(LLMReport.analysis_id == analysis_id)
        .order_by(LLMReport.created_at.desc())
        .first()
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not yet generated for this analysis",
        )

    if format == "markdown":
        return Response(content=report.markdown_content, media_type="text/markdown")

    return report
