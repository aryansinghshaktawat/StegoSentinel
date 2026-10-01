"""
Audit events API endpoints for StegoSentinel.
"""
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.api.v1.analyses import verify_analysis_access
from app.core.database import get_db
from app.core.security import get_current_user_payload
from app.models.base import Analysis, AuditEvent

router = APIRouter(prefix="/analyses/{analysis_id}/events", tags=["Audit Events"])


@router.get("", response_model=List[Dict[str, Any]])
def get_analysis_audit_events(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user_payload),
):
    """Retrieve verifiable audit event log for the analysis."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found",
        )
    verify_analysis_access(analysis, current_user)

    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.object_id == analysis_id)
        .order_by(AuditEvent.timestamp.asc())
        .all()
    )
    return [
        {
            "id": e.id,
            "actor": e.actor,
            "action": e.action,
            "object_id": e.object_id,
            "timestamp": e.timestamp.isoformat(),
            "metadata": e.metadata_json,
        }
        for e in events
    ]
