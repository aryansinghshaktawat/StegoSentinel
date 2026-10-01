"""
Recursive payload extraction and evidence DAG management for StegoSentinel.
Safely extracts embedded payloads, saves them to quarantine, and recursively
analyzes child artifacts up to hard depth and count budgets.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.analyzers import run_all_analyzers
from app.analyzers.base import AnalysisContext, FindingData
from app.analyzers.general import detect_magic
from app.candidates.generator import CandidateResult, candidate_generator
from app.core.limits import LIMITS
from app.core.storage import storage
from app.models.base import Analysis, Candidate, EvidenceObject, Finding


@dataclass
class ExtractionNode:
    name: str
    data: bytes
    extraction_method: str
    source_offset: int = 0


class RecursiveForensicEngine:
    """Manages the safe extraction and recursive analysis pipeline."""

    def __init__(self, db: Session, analysis: Analysis):
        self.db = db
        self.analysis = analysis
        self.total_extracted_objects = 0
        self.cumulative_extracted_bytes = 0

    def process_file_recursive(
        self,
        file_bytes: bytes,
        filename: str,
        parent_id: str | None = None,
        depth: int = 0,
        extraction_method: str = "ORIGINAL_UPLOAD",
        source_offset: int = 0,
    ) -> EvidenceObject:
        """
        Quarantine and analyze a file, recursively extracting and processing child evidence.
        """
        # Store quarantined object
        ref, file_path_str = storage.store_file(file_bytes, filename)
        file_path = Path(file_path_str)
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        detected_mime, _, _ = detect_magic(file_bytes, filename)

        # Create EvidenceObject record
        evidence_obj = EvidenceObject(
            analysis_id=self.analysis.id,
            parent_id=parent_id,
            name=filename,
            sha256=sha256,
            size=len(file_bytes),
            detected_type=detected_mime,
            storage_reference=ref,
            extraction_method=extraction_method,
            source_offset=source_offset,
            recursion_depth=depth,
        )
        self.db.add(evidence_obj)
        self.db.flush()

        # Build analysis context
        context = AnalysisContext(
            file_path=file_path,
            file_bytes=file_bytes,
            filename=filename,
            mime_type=detected_mime,
            sha256=sha256,
            recursion_depth=depth,
        )

        # 1. Run all compatible forensic analyzers
        findings: list[FindingData] = run_all_analyzers(context)
        for f in findings:
            db_finding = Finding(
                analysis_id=self.analysis.id,
                type=f.type,
                severity=f.severity,
                confidence=f.confidence,
                description=f.description,
                evidence=f.evidence or {},
                analyzer=f.analyzer,
                analyzer_version=f.analyzer_version,
            )
            self.db.add(db_finding)

        # 2. Run candidate generation if image or media format
        candidates: list[CandidateResult] = []
        if depth == 0 or detected_mime.startswith("image/"):
            candidates = candidate_generator.generate_candidates(context)
            for c in candidates:
                db_candidate = Candidate(
                    analysis_id=self.analysis.id,
                    technique=c.technique,
                    parameters=c.parameters,
                    feature_vector=c.feature_vector,
                    raw_score=c.raw_score,
                    ml_score=c.ml_score,
                    validation_score=c.validation_score,
                    final_score=c.final_score,
                    status=c.status,
                    extracted_type=c.extracted_type,
                    printable_ratio=c.printable_ratio,
                )
                self.db.add(db_candidate)

        self.db.flush()

        # Check recursion budget
        if depth >= LIMITS.MAX_RECURSION_DEPTH:
            return evidence_obj

        # 3. Identify child payloads for safe recursive extraction
        children_to_extract: list[ExtractionNode] = []

        # A. Trailing overlay data (if detected by general analyzer)
        if "trailing_data" in context.metadata:
            t_data = context.metadata["trailing_data"]
            t_offset = context.metadata.get("trailing_offset", 0)
            if len(t_data) >= 16:
                children_to_extract.append(
                    ExtractionNode(
                        name=f"overlay_offset_0x{t_offset:X}.bin",
                        data=t_data,
                        extraction_method="TRAILING_OVERLAY_EXTRACTION",
                        source_offset=t_offset,
                    )
                )

        # B. Archive members (if safely unpacked by ArchiveAnalyzer)
        if "extracted_archive_members" in context.metadata:
            members: list[tuple[Any, bytes]] = context.metadata["extracted_archive_members"]
            for info, member_data in members:
                children_to_extract.append(
                    ExtractionNode(
                        name=Path(info.filename).name or "archive_member.bin",
                        data=member_data,
                        extraction_method="ZIP_DECOMPRESSION",
                        source_offset=0,
                    )
                )

        # C. High-confidence stego candidates (VALID status or final_score >= 0.70)
        for cand in candidates:
            if cand.status == "VALID" and len(cand.extracted_bytes) >= 16:
                ext = ".bin"
                if cand.extracted_type == "text/plain":
                    ext = ".txt"
                elif cand.extracted_type == "application/zip":
                    ext = ".zip"

                children_to_extract.append(
                    ExtractionNode(
                        name=f"candidate_{cand.technique}{ext}",
                        data=cand.extracted_bytes,
                        extraction_method=cand.technique,
                        source_offset=0,
                    )
                )
                break  # Extract top candidate to avoid redundancy

        # Recursively process identified child nodes
        for child in children_to_extract:
            if self.total_extracted_objects >= LIMITS.MAX_EXTRACTED_OBJECTS:
                break
            if self.cumulative_extracted_bytes + len(child.data) > LIMITS.MAX_TOTAL_EXTRACTED_SIZE:
                break

            self.total_extracted_objects += 1
            self.cumulative_extracted_bytes += len(child.data)

            self.process_file_recursive(
                file_bytes=child.data,
                filename=child.name,
                parent_id=evidence_obj.id,
                depth=depth + 1,
                extraction_method=child.extraction_method,
                source_offset=child.source_offset,
            )

        return evidence_obj
