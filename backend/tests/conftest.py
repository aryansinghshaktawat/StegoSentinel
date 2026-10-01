"""
Pytest configuration and shared test fixtures for StegoSentinel.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.database import Base, get_db
from app.core.security import Role, create_access_token
from app.main import app
from app.models.base import User
from app.services.auth_service import hash_password

settings.ASYNC_MODE = "manual"

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"

# In-memory SQLite database for isolated test execution
TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    TEST_SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """Create a fresh database session for each test function."""
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()

    # Seed test users
    admin_user = User(
        id="usr_admin_01",
        username="admin_user",
        email="admin@stegosentinel.local",
        hashed_password=hash_password("AdminPass123!"),
        role=Role.ADMIN.value,
    )
    analyst_user = User(
        id="usr_analyst_01",
        username="analyst_alice",
        email="alice@stegosentinel.local",
        hashed_password=hash_password("AnalystPass123!"),
        role=Role.ANALYST.value,
    )
    viewer_user = User(
        id="usr_viewer_01",
        username="viewer_bob",
        email="bob@stegosentinel.local",
        hashed_password=hash_password("ViewerPass123!"),
        role=Role.VIEWER.value,
    )
    session.add_all([admin_user, analyst_user, viewer_user])
    session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    """TestClient that uses the test database."""

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def analyst_headers():
    token = create_access_token(
        data={"sub": "usr_analyst_01", "username": "analyst_alice", "role": Role.ANALYST.value}
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers():
    token = create_access_token(
        data={"sub": "usr_admin_01", "username": "admin_user", "role": Role.ADMIN.value}
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers():
    token = create_access_token(
        data={"sub": "usr_viewer_01", "username": "viewer_bob", "role": Role.VIEWER.value}
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def fixtures_path():
    return FIXTURES_DIR
