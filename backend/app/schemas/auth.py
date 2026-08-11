from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)


class UserCreate(UserBase):
    """Registro público. No acepta `role`: antes bastaba con enviar
    `{"role": "admin"}` para crearse una cuenta con permisos totales."""

    password: str = Field(min_length=8, max_length=128)


class UserAdminCreate(UserCreate):
    """Alta de usuarios desde el panel de administración."""

    role: Optional[str] = "viewer"


class UserAdminUpdate(UserBase):
    role: Optional[str] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(UserBase):
    id: int
    role: str
    is_active: bool
    mfa_enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefresh(BaseModel):
    refresh_token: str
