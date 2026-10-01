"""
SQLAlchemy models for StegoSentinel forensics platform.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), default="ANALYST", nullable=False)  # ADMIN, ANALYST, VIEWER
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    analyses = relationship("Analysis", back_populates="user", cascade="all, delete-orphan")


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    status = Column(
        String(32), default="PENDING", index=True, nullable=False
    )  # PENDING, RUNNING, COMPLETED, FAILED, RESOURCE_LIMIT
    original_filename = Column(String(255), nullable=False)
    sha256 = Column(String(64), index=True, nullable=False)
    sha512 = Column(String(128), nullable=True)
    size = Column(Integer, nullable=False)
    detected_type = Column(String(128), default="application/octet-stream", nullable=False)
    storage_reference = Column(String(128), nullable=False)
    entropy = Column(Float, nullable=True)
    stego_likelihood = Column(Float, nullable=True)  # Calibrated probability (0.0 to 1.0)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    user = relationship("User", back_populates="analyses")
    findings = relationship("Finding", back_populates="analysis", cascade="all, delete-orphan")
    candidates = relationship("Candidate", back_populates="analysis", cascade="all, delete-orphan")
    evidence_objects = relationship(
        "EvidenceObject", back_populates="analysis", cascade="all, delete-orphan"
    )
    reports = relationship("LLMReport", back_populates="analysis", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analyses.id"), index=True, nullable=False)
    type = Column(
        String(64), index=True, nullable=False
    )  # e.g. LSB_ENTROPY_ANOMALY, ZERO_WIDTH_CHARS
    severity = Column(
        String(32), default="MEDIUM", nullable=False
    )  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=0.5, nullable=False)  # 0.0 to 1.0
    description = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=True)  # Structured evidence dictionary
    analyzer = Column(String(64), nullable=False)
    analyzer_version = Column(String(32), default="1.0.0", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    analysis = relationship("Analysis", back_populates="findings")


class Candidate(Base):
    __tablename__ = "candidates"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analyses.id"), index=True, nullable=False)
    technique = Column(String(64), nullable=False)  # e.g. LSB_SEQUENTIAL, LSB_INTERLEAVED
    parameters = Column(
        JSON, nullable=False
    )  # {channel: "RGB", bit_plane: 0, order: "seq", stride: 1}
    feature_vector = Column(JSON, nullable=True)  # {entropy: 5.7, printable_ratio: 0.96, ...}
    raw_score = Column(Float, default=0.0, nullable=False)
    ml_score = Column(Float, default=0.0, nullable=False)
    validation_score = Column(Float, default=0.0, nullable=False)
    final_score = Column(Float, default=0.0, index=True, nullable=False)
    status = Column(
        String(32), default="UNKNOWN", nullable=False
    )  # VALID, PARTIAL, INVALID, UNKNOWN
    extracted_type = Column(String(64), nullable=True)
    printable_ratio = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    analysis = relationship("Analysis", back_populates="candidates")


class EvidenceObject(Base):
    __tablename__ = "evidence_objects"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analyses.id"), index=True, nullable=False)
    parent_id = Column(String(36), ForeignKey("evidence_objects.id"), nullable=True)
    name = Column(String(255), nullable=False)
    sha256 = Column(String(64), index=True, nullable=False)
    size = Column(Integer, nullable=False)
    detected_type = Column(String(128), default="application/octet-stream", nullable=False)
    storage_reference = Column(String(128), nullable=False)
    extraction_method = Column(String(128), nullable=False)
    source_offset = Column(Integer, default=0, nullable=False)
    recursion_depth = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    analysis = relationship("Analysis", back_populates="evidence_objects")
    children = relationship(
        "EvidenceObject",
        backref="parent",
        remote_side=[id],
        cascade="all, delete-orphan",
        single_parent=True,
    )


class LLMReport(Base):
    __tablename__ = "llm_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analyses.id"), index=True, nullable=False)
    model = Column(String(64), default="mock-forensic-v1", nullable=False)
    prompt_version = Column(Integer, default=1, nullable=False)
    result = Column(JSON, nullable=False)  # Structured forensic summary
    markdown_content = Column(Text, nullable=False)  # Rendered full Markdown report
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    analysis = relationship("Analysis", back_populates="reports")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    actor = Column(String(64), nullable=False)  # User ID or "SYSTEM"
    action = Column(String(64), index=True, nullable=False)  # UPLOAD, ANALYZE, EXTRACT, EXPORT
    object_id = Column(String(36), index=True, nullable=False)  # Analysis ID or Evidence ID
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    metadata_json = Column("metadata", JSON, nullable=True)
