"""
Evidence hierarchy and artifact retrieval API endpoints for StegoSentinel.
"""

import io

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.v1.analyses import verify_analysis_access
from app.core.database import get_db
from app.core.security import get_current_user_payload
from app.core.storage import storage
from app.models.base import Analysis, EvidenceObject
from app.schemas.evidence import EvidenceTreeNode

router = APIRouter(tags=["Evidence"])


def build_evidence_tree(objects: list[EvidenceObject]) -> list[EvidenceTreeNode]:
    """Assemble flat list of EvidenceObjects into a parent-child DAG."""
    nodes: dict[str, EvidenceTreeNode] = {}
    roots: list[EvidenceTreeNode] = []

    # First pass: Create all nodes
    for obj in objects:
        node = EvidenceTreeNode(
            id=obj.id,
            analysis_id=obj.analysis_id,
            parent_id=obj.parent_id,
            name=obj.name,
            sha256=obj.sha256,
            size=obj.size,
            detected_type=obj.detected_type,
            storage_reference=obj.storage_reference,
            extraction_method=obj.extraction_method,
            source_offset=obj.source_offset,
            recursion_depth=obj.recursion_depth,
            created_at=obj.created_at,
            children=[],
        )
        nodes[obj.id] = node

    # Second pass: Link children to parents
    for obj in objects:
        node = nodes[obj.id]
        if obj.parent_id and obj.parent_id in nodes:
            nodes[obj.parent_id].children.append(node)
        else:
            roots.append(node)

    return roots


@router.get("/analyses/{analysis_id}/evidence", response_model=list[EvidenceTreeNode])
def get_analysis_evidence_tree(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user_payload),
):
    """Retrieve hierarchical DAG of all extracted evidence objects."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found",
        )
    verify_analysis_access(analysis, current_user)

    objects = (
        db.query(EvidenceObject)
        .filter(EvidenceObject.analysis_id == analysis_id)
        .order_by(EvidenceObject.recursion_depth.asc(), EvidenceObject.created_at.asc())
        .all()
    )
    return build_evidence_tree(objects)


@router.get("/evidence/{evidence_id}/download")
def download_evidence_payload(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user_payload),
):
    """Safely stream quarantined evidence payload without executing."""
    evidence = db.query(EvidenceObject).filter(EvidenceObject.id == evidence_id).first()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence object not found",
        )

    analysis = db.query(Analysis).filter(Analysis.id == evidence.analysis_id).first()
    if analysis:
        verify_analysis_access(analysis, current_user)

    try:
        data = storage.read_file(evidence.storage_reference)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quarantined payload file not found on disk",
        )

    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="evidence_{evidence.name}"'},
    )
