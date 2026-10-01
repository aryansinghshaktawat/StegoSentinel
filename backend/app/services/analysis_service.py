"""
Core analysis orchestration service for StegoSentinel.
Executes end-to-end pipeline from quarantine through recursive analysis and report generation.
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.core.storage import storage
from app.extraction.recursion import RecursiveForensicEngine
from app.models.base import Analysis
from app.reports.generator import generate_forensic_report
from app.services.audit_service import audit_service


class AnalysisService:
    @staticmethod
    def execute_analysis(db: Session, analysis_id: str, actor: str = "SYSTEM") -> Analysis:
        analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            raise ValueError(f"Analysis {analysis_id} not found.")

        # Update status to RUNNING
        analysis.status = "RUNNING"
        analysis.started_at = datetime.now(timezone.utc)
        db.commit()

        audit_service.log_event(
            db,
            actor=actor,
            action="ANALYSIS_STARTED",
            object_id=analysis_id,
            metadata={"filename": analysis.original_filename, "sha256": analysis.sha256},
        )
        db.commit()

        try:
            # Read quarantined file
            file_bytes = storage.read_file(analysis.storage_reference)

            # Instantiate recursive forensic engine
            engine = RecursiveForensicEngine(db, analysis)
            engine.process_file_recursive(
                file_bytes=file_bytes,
                filename=analysis.original_filename,
                parent_id=None,
                depth=0,
                extraction_method="ORIGINAL_UPLOAD",
                source_offset=0,
            )

            # Generate final forensic report
            generate_forensic_report(db, analysis)

            # Mark as COMPLETED
            analysis.status = "COMPLETED"
            analysis.completed_at = datetime.now(timezone.utc)
            db.commit()

            audit_service.log_event(
                db,
                actor=actor,
                action="ANALYSIS_COMPLETED",
                object_id=analysis_id,
                metadata={
                    "stego_likelihood": analysis.stego_likelihood,
                    "extracted_objects": engine.total_extracted_objects,
                },
            )
            db.commit()

        except Exception as e:
            analysis.status = "FAILED"
            analysis.completed_at = datetime.now(timezone.utc)
            analysis.error_message = str(e)
            db.commit()

            audit_service.log_event(
                db,
                actor=actor,
                action="ANALYSIS_FAILED",
                object_id=analysis_id,
                metadata={"error": str(e)},
            )
            db.commit()
            raise e

        return analysis


analysis_service = AnalysisService()
