from datetime import datetime

from pydantic import BaseModel, ConfigDict


class UserBase(BaseModel):
    username: str
    email: str
    role: str = "ANALYST"


class UserCreate(UserBase):
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserRead(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead


class TokenData(BaseModel):
    sub: str | None = None
    username: str | None = None
    role: str | None = None
