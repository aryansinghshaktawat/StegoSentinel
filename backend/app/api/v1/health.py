"""
Health and readiness diagnostics endpoints for StegoSentinel.
"""
import shutil
from typing import Any, Dict
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.worker import get_redis_client

router = APIRouter(prefix="/health", tags=["Health Diagnostics"])


@router.get("")
def liveness():
    """Liveness probe returning basic service operational status."""
    return {
        "status": "healthy",
        "service": "StegoSentinel API",
        "version": "0.1.0",
        "environment": settings.ENVIRONMENT,
    }


@router.get("/ready")
def readiness(db: Session = Depends(get_db)):
    """Readiness probe evaluating database, storage, redis, and tool capabilities."""
    checks: Dict[str, Any] = {}

    # Database check
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = {"status": "UP"}
    except Exception as e:
        checks["database"] = {"status": "DOWN", "error": str(e)}

    # Storage check
    try:
        test_file = settings.storage_path / ".healthcheck"
        test_file.write_text("ok")
        test_file.unlink()
        checks["quarantine_storage"] = {"status": "UP", "path": str(settings.storage_path)}
    except Exception as e:
        checks["quarantine_storage"] = {"status": "DOWN", "error": str(e)}

    # Redis check
    r = get_redis_client()
    if r:
        checks["redis"] = {"status": "UP"}
    else:
        checks["redis"] = {
            "status": "FALLBACK_IN_PROCESS",
            "mode": settings.ASYNC_MODE,
        }

    # Tool capabilities matrix
    tools = {
        "exiftool": bool(shutil.which("exiftool")),
        "zsteg": bool(shutil.which("zsteg")),
        "steghide": bool(shutil.which("steghide")),
        "binwalk": bool(shutil.which("binwalk")),
    }
    checks["external_tools"] = tools

    return {
        "status": "ready" if checks["database"]["status"] == "UP" else "degraded",
        "checks": checks,
    }
