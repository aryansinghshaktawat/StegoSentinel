"""
Authentication API endpoints for StegoSentinel.
"""
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token, get_current_user_payload
from app.schemas.auth import Token, UserCreate, UserRead, UserLogin
from app.services.auth_service import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    """Register a new investigator or analyst."""
    if auth_service.get_by_username(db, user_in.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    if auth_service.get_by_email(db, user_in.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    return auth_service.create_user(db, user_in)


@router.post("/token", response_model=Token)
def login(login_in: UserLogin, db: Session = Depends(get_db)):
    """Authenticate and obtain JWT bearer token."""
    user = auth_service.authenticate(db, login_in.username, login_in.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    token = create_access_token(
        data={"sub": user.id, "username": user.username, "role": user.role},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return Token(access_token=token, token_type="bearer", user=UserRead.model_validate(user))


@router.get("/me")
def get_current_user(payload: dict = Depends(get_current_user_payload)):
    """Return currently active user context."""
    return payload
