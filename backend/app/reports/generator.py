"""
Forensic report compilation and calibration engine for StegoSentinel.
Synthesizes findings, candidates, and recursive evidence into defensible
JSON and Markdown forensic reports.
"""
from typing import Any, Dict, List
from sqlalchemy.orm import Session
from app.ai.llm import get_llm_provider
from app.models.base import Analysis, Candidate, EvidenceObject, Finding, LLMReport


def calculate_overall_stego_likelihood(
    findings: List[Finding], candidates: List[Candidate], entropy: float = 0.0
) -> float:
    """
    Calculate calibrated stego likelihood (0.0 to 1.0) using deterministic evidence hierarchy.
    """
    # 1. If any candidate was confirmed as VALID with structured payload (e.g. text/zip)
    valid_candidates = [c for c in candidates if c.status == "VALID"]
    if valid_candidates:
        top_cand = max(valid_candidates, key=lambda c: c.final_score)
        return min(0.98, max(0.85, round(top_cand.final_score, 2)))

    # 2. Score based on findings severity and confidence
    score = 0.05  # Base baseline
    has_critical = any(f.severity == "CRITICAL" for f in findings)
    has_high = any(f.severity == "HIGH" for f in findings)
    high_count = sum(1 for f in findings if f.severity in ["HIGH", "CRITICAL"])

    if has_critical:
        score += 0.50
    if has_high:
        score += 0.25 + (min(high_count, 4) * 0.05)

    # Chi-square or entropy anomalies
    for f in findings:
        if f.type in ["CHI_SQUARE_LSB_ANOMALY", "ZERO_WIDTH_UNICODE_STEGANOGRAPHY", "TRAILING_DATA_OVERLAY"]:
            score += 0.20
            break

    # High entropy bonus
    if entropy >= 7.9:
        score += 0.10

    return min(0.92, round(score, 2))


def generate_forensic_report(db: Session, analysis: Analysis) -> LLMReport:
    """Generate structured and Markdown forensic reports for an analysis."""
    findings = db.query(Finding).filter(Finding.analysis_id == analysis.id).all()
    candidates = (
        db.query(Candidate)
        .filter(Candidate.analysis_id == analysis.id)
        .order_by(Candidate.final_score.desc())
        .all()
    )
    evidence_objs = (
        db.query(EvidenceObject)
        .filter(EvidenceObject.analysis_id == analysis.id)
        .all()
    )

    # Calculate overall stego likelihood
    stego_likelihood = calculate_overall_stego_likelihood(
        findings, candidates, entropy=analysis.entropy or 0.0
    )
    analysis.stego_likelihood = stego_likelihood
    db.flush()

    top_cand_dict = None
    if candidates:
        top_cand = candidates[0]
        top_cand_dict = {
            "technique": top_cand.technique,
            "final_score": top_cand.final_score,
            "extracted_type": top_cand.extracted_type,
            "status": top_cand.status,
        }

    evidence_summary: Dict[str, Any] = {
        "original_filename": analysis.original_filename,
        "sha256": analysis.sha256,
        "detected_type": analysis.detected_type,
        "size": analysis.size,
        "entropy": analysis.entropy,
        "stego_likelihood": stego_likelihood,
        "findings": [
            {
                "type": f.type,
                "severity": f.severity,
                "confidence": f.confidence,
                "description": f.description,
                "analyzer": f.analyzer,
            }
            for f in findings
        ],
        "candidates": [
            {
                "technique": c.technique,
                "parameters": c.parameters,
                "ml_score": c.ml_score,
                "validation_score": c.validation_score,
                "final_score": c.final_score,
                "status": c.status,
                "extracted_type": c.extracted_type,
            }
            for c in candidates
        ],
        "top_candidate": top_cand_dict,
        "extracted_objects_count": len(evidence_objs),
        "evidence_objects": [
            {
                "name": eo.name,
                "detected_type": eo.detected_type,
                "size": eo.size,
                "extraction_method": eo.extraction_method,
                "sha256": eo.sha256,
                "recursion_depth": eo.recursion_depth,
            }
            for eo in evidence_objs
        ],
    }

    provider = get_llm_provider()
    summary_result = provider.generate_summary(evidence_summary)
    markdown_report = provider.generate_markdown_report(evidence_summary)

    report = LLMReport(
        analysis_id=analysis.id,
        model=getattr(provider, "model", "mock-forensic-v1"),
        prompt_version=1,
        result=summary_result,
        markdown_content=markdown_report,
    )
    db.add(report)
    db.flush()
    return report
