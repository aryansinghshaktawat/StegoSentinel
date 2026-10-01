"""
Configuration management for StegoSentinel using pydantic-settings.
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # General
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    # API Gateway
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_V1_PREFIX: str = "/api/v1"
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Security & Auth
    JWT_SECRET_KEY: str = "dev-insecure-secret-key-change-in-prod-32bytes!"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database
    DATABASE_URL: str = "sqlite:///./stegosentinel.db"

    # Job Queue & Execution
    ASYNC_MODE: str = "thread"  # "thread" (in-process) or "redis"
    REDIS_URL: str = "redis://localhost:6379/0"

    # Quarantine Storage
    STORAGE_BACKEND: str = "local"
    STORAGE_LOCAL_PATH: str = "./storage/quarantine"
    S3_ENDPOINT_URL: str | None = None
    S3_ACCESS_KEY: str | None = None
    S3_SECRET_KEY: str | None = None
    S3_BUCKET_NAME: str = "stegosentinel-quarantine"

    # Machine Learning & AI
    ML_MODEL_PATH: str = "./ml/models/stego_ranker.pkl"
    LLM_PROVIDER: str = "mock"  # "mock" or "openai"
    LLM_API_KEY: str | None = None
    LLM_MODEL: str = "gpt-4o-mini"

    # Hard Forensic Budgets (default to ForensicLimits)
    MAX_UPLOAD_SIZE: int = 100 * 1024 * 1024
    MAX_FILE_SIZE_PER_OBJECT: int = 50 * 1024 * 1024
    MAX_TOTAL_EXTRACTED_SIZE: int = 250 * 1024 * 1024
    MAX_RECURSION_DEPTH: int = 3
    MAX_EXTRACTED_OBJECTS: int = 20
    MAX_ANALYSIS_SECONDS: int = 60
    MAX_CANDIDATES: int = 1000

    @property
    def storage_path(self) -> Path:
        p = Path(self.STORAGE_LOCAL_PATH)
        p.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()
