"""
Audit logging service for StegoSentinel chain of custody.
"""
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from app.models.base import AuditEvent


class AuditService:
    @staticmethod
    def log_event(
        db: Session,
        actor: str,
        action: str,
        object_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            actor=actor,
            action=action,
            object_id=object_id,
            metadata_json=metadata or {},
        )
        db.add(event)
        db.flush()
        return event


audit_service = AuditService()
