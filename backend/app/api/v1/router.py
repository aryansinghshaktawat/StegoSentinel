"""
API v1 Router aggregation for StegoSentinel.
"""

from fastapi import APIRouter

from app.api.v1.analyses import router as analyses_router
from app.api.v1.auth import router as auth_router
from app.api.v1.candidates import router as candidates_router
from app.api.v1.events import router as events_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.findings import router as findings_router
from app.api.v1.health import router as health_router
from app.api.v1.reports import router as reports_router

api_v1_router = APIRouter()

api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(analyses_router)
api_v1_router.include_router(findings_router)
api_v1_router.include_router(candidates_router)
api_v1_router.include_router(evidence_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(events_router)
