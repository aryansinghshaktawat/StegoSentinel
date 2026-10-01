"""
Analysis management API endpoints for StegoSentinel.
Enforces untrusted upload sanitization, quarantine isolation, and IDOR protection.
"""
import hashlib
import os
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session
from app.analyzers.general import detect_magic
from app.core.config import settings
from app.core.database import get_db
from app.core.limits import LIMITS
from app.core.security import get_current_user_payload
from app.core.storage import storage
from app.models.base import Analysis
from app.schemas.analysis import AnalysisDetail, AnalysisSummary
from app.services.audit_service import audit_service
from app.worker import dispatch_analysis_job

router = APIRouter(prefix="/analyses", tags=["Analyses"])


def verify_analysis_access(analysis: Analysis, current_user: dict):
    """Enforce IDOR/BOLA protection: only owner or ADMIN can access analysis."""
    user_id = current_user.get("sub")
    role = current_user.get("role", "ANALYST")
    if role != "ADMIN" and analysis.user_id and analysis.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to access this analysis case.",
        )


@router.post("", response_model=AnalysisSummary, status_code=status.HTTP_202_ACCEPTED)
async def create_analysis(
    file: UploadFile = File(...),
    generate_report: bool = Form(True),
    max_candidates: int = Form(100),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user_payload),
):
    """
    Intake an untrusted file, allocate secure quarantine, calculate cryptographic hashes,
    and dispatch an isolated background analysis job.
    """
    # 1. Read file bytes with size check
    content = await file.read()
    if len(content) > LIMITS.MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowable upload size ({LIMITS.MAX_UPLOAD_SIZE // (1024 * 1024)}MB)",
        )

    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot analyze empty file",
        )

    # 2. Sanitize filename against path traversal
    raw_name = file.filename or "unknown.bin"
    clean_filename = Path(raw_name).name.replace("\x00", "")

    # 3. Cryptographic Hashes & Magic bytes
    sha256 = hashlib.sha256(content).hexdigest()
    sha512 = hashlib.sha512(content).hexdigest()
    detected_mime, _, _ = detect_magic(content, clean_filename)

    # 4. Quarantine storage
    storage_ref, _ = storage.store_file(content, clean_filename)

    # 5. Insert Analysis record
    analysis = Analysis(
        user_id=current_user.get("sub"),
        status="PENDING",
        original_filename=clean_filename,
        sha256=sha256,
        sha512=sha512,
        size=len(content),
        detected_type=detected_mime,
        storage_reference=storage_ref,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # Audit logging
    audit_service.log_event(
        db,
        actor=current_user.get("username", "anonymous"),
        action="FILE_UPLOAD_QUARANTINED",
        object_id=analysis.id,
        metadata={"filename": clean_filename, "sha256": sha256, "size": len(content)},
    )
    db.commit()

    # 6. Dispatch asynchronous analysis job
    dispatch_analysis_job(analysis.id)

    return analysis


@router.get("", response_model=List[AnalysisSummary])
def list_analyses(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user_payload),
):
    """List forensic analyses with tenancy filtering."""
    query = db.query(Analysis).order_by(Analysis.created_at.desc())
    if current_user.get("role") != "ADMIN":
        query = query.filter(
            (Analysis.user_id == current_user.get("sub")) | (Analysis.user_id == None)  # noqa: E711
        )
    return query.offset(skip).limit(limit).all()


@router.get("/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user_payload),
):
    """Retrieve full analysis status, findings, candidates, and evidence."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found",
        )
    verify_analysis_access(analysis, current_user)
    return analysis


@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user_payload),
):
    """Delete an analysis case and associated forensic records."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found",
        )
    verify_analysis_access(analysis, current_user)

    db.delete(analysis)
    db.commit()
    return None
