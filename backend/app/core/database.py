"""
Database session and connection management for StegoSentinel.
Supports PostgreSQL for production and SQLite for local development and testing.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.core.config import settings

# Determine database engine args based on dialect
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL, connect_args=connect_args, echo=False, pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency for obtaining database sessions per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def migrate_db(target_engine=None) -> None:
    """
    Safely migrate existing databases to the latest schema.
    Supports SQLite and PostgreSQL without deleting existing data.
    """
    if target_engine is None:
        target_engine = engine

    from sqlalchemy import inspect, text

    inspector = inspect(target_engine)
    table_names = inspector.get_table_names()
    if "candidates" not in table_names:
        return

    existing_columns = {col["name"] for col in inspector.get_columns("candidates")}

    columns_to_add = [
        ("validation_description", "TEXT"),
        ("payload_size", "INTEGER"),
        ("encoding", "VARCHAR(32)"),
        ("decode_status", "VARCHAR(32) DEFAULT 'NOT_ATTEMPTED'"),
        ("decoded_text", "TEXT"),
        ("evidence_object_id", "VARCHAR(36)"),
    ]

    with target_engine.connect() as conn:
        for col_name, col_type in columns_to_add:
            if col_name not in existing_columns:
                conn.execute(text(f"ALTER TABLE candidates ADD COLUMN {col_name} {col_type}"))
                conn.commit()

        # Ensure index exists
        try:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_candidates_evidence_object_id ON candidates (evidence_object_id)"
                )
            )
            conn.commit()
        except Exception:
            pass


def init_db() -> None:
    """Initialize database tables and apply pending migrations."""
    import app.models  # noqa: F401 - ensure models are registered

    Base.metadata.create_all(bind=engine)
    migrate_db()
