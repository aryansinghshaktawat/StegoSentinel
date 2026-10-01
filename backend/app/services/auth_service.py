"""
Authentication service for user onboarding and session management.
"""


from sqlalchemy.orm import Session

from app.core.security import Role, hash_password, verify_password
from app.models.base import User
from app.schemas.auth import UserCreate


class AuthService:
    @staticmethod
    def get_by_username(db: Session, username: str) -> User | None:
        return db.query(User).filter(User.username == username).first()

    @staticmethod
    def get_by_email(db: Session, email: str) -> User | None:
        return db.query(User).filter(User.email == email).first()

    @staticmethod
    def create_user(db: Session, user_in: UserCreate) -> User:
        user = User(
            username=user_in.username,
            email=user_in.email,
            hashed_password=hash_password(user_in.password),
            role=user_in.role or Role.ANALYST.value,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def authenticate(db: Session, username: str, password: str) -> User | None:
        user = AuthService.get_by_username(db, username)
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user


auth_service = AuthService()
