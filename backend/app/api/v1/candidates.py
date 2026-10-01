"""
Candidates API endpoints for StegoSentinel.
"""


from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.v1.analyses import verify_analysis_access
from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_current_user_payload
from app.models.base import Analysis, Candidate, EvidenceObject
from app.schemas.candidate import CandidatePayload, CandidatePayloadEvidence, CandidateRead

router = APIRouter(prefix="/analyses/{analysis_id}/candidates", tags=["Candidates"])


def _get_accessible_analysis(db: Session, analysis_id: str, current_user: dict) -> Analysis:
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found",
        )
    verify_analysis_access(analysis, current_user)
    return analysis


@router.get("", response_model=list[CandidateRead])
def get_analysis_candidates(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user_payload),
):
    """Retrieve all ranked extraction candidates for an analysis."""
    _get_accessible_analysis(db, analysis_id, current_user)

    candidates = (
        db.query(Candidate)
        .filter(Candidate.analysis_id == analysis_id)
        .order_by(Candidate.final_score.desc())
        .all()
    )
    return candidates


@router.get("/{candidate_id}/payload", response_model=CandidatePayload)
def get_candidate_payload(
    analysis_id: str,
    candidate_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user_payload),
):
    """Recovered payload for a candidate: decoded text where available, else evidence metadata."""
    _get_accessible_analysis(db, analysis_id, current_user)

    candidate = (
        db.query(Candidate)
        .filter(Candidate.id == candidate_id, Candidate.analysis_id == analysis_id)
        .first()
    )
    if not candidate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Candidate {candidate_id} not found",
        )

    evidence = None
    if candidate.evidence_object_id:
        eo = (
            db.query(EvidenceObject)
            .filter(
                EvidenceObject.id == candidate.evidence_object_id,
                EvidenceObject.analysis_id == analysis_id,
            )
            .first()
        )
        if eo:
            evidence = CandidatePayloadEvidence(
                id=eo.id,
                name=eo.name,
                sha256=eo.sha256,
                size=eo.size,
                detected_type=eo.detected_type,
                download_url=f"{settings.API_V1_PREFIX}/evidence/{eo.id}/download",
            )

    return CandidatePayload(
        candidate_id=candidate.id,
        analysis_id=analysis_id,
        technique=candidate.technique,
        status=candidate.status,
        type=candidate.extracted_type,
        payload_size=candidate.payload_size,
        encoding=candidate.encoding,
        decode_status=candidate.decode_status,
        decoded_text=candidate.decoded_text,
        evidence_object_id=candidate.evidence_object_id,
        evidence=evidence,
    )
