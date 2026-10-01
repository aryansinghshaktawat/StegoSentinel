"""
Main entry point for StegoSentinel FastAPI service.
"""
from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.core.database import init_db

logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger("stegosentinel")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure tables exist
    logger.info("Initializing StegoSentinel database tables...")
    init_db()
    yield
    # Shutdown logic if needed
    logger.info("StegoSentinel service stopping.")


app = FastAPI(
    title="StegoSentinel API",
    description="AI-Assisted Multi-Format Steganalysis & Hidden-Payload Forensics Platform",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal forensic processing fault occurred. Error recorded in audit log."},
    )


# Mount versioned API
app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)


@app.get("/")
def root():
    return {
        "platform": "StegoSentinel",
        "description": "AI-Assisted Multi-Format Steganalysis & Hidden-Payload Forensics Platform",
        "version": "0.1.0",
        "documentation": "/docs",
        "health": f"{settings.API_V1_PREFIX}/health",
    }
