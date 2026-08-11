from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import settings as app_settings
from app.core.database import get_db
from app.core.deps import client_ip, get_current_user
from app.core.security import get_password_hash, verify_password
from app.models.user import User

router = APIRouter()


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    email: Optional[EmailStr] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


@router.get("/profile")
def get_profile(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.value,
        "mfa_enabled": user.mfa_enabled,
        "created_at": user.created_at,
    }


@router.put("/profile")
def update_profile(
    data: ProfileUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if data.full_name:
        user.full_name = data.full_name
    if data.email and data.email != user.email:
        if db.query(User).filter(User.email == data.email, User.id != user.id).first():
            raise HTTPException(status_code=400, detail="El correo ya está en uso")
        user.email = data.email

    db.commit()
    audit.record(db, audit.PROFILE_UPDATED, user_id=user.id, resource=user.email,
                 ip_address=client_ip(request))
    return {"message": "Perfil actualizado"}


@router.put("/password")
def change_password(
    data: PasswordChange,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(data.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="La contraseña actual es incorrecta")
    if data.new_password == data.current_password:
        raise HTTPException(status_code=400, detail="La nueva contraseña debe ser distinta de la actual")

    user.hashed_password = get_password_hash(data.new_password)
    db.commit()

    audit.record(db, audit.PASSWORD_CHANGED, user_id=user.id, resource=user.email,
                 ip_address=client_ip(request))
    return {"message": "Contraseña actualizada"}


@router.get("/system")
def get_system_config():
    """Configuración efectiva del servidor.

    Son los valores que la aplicación está usando de verdad, leídos de la
    configuración; antes este endpoint devolvía un diccionario fijo que no
    correspondía a ningún ajuste real.
    """
    return {
        "app_version": app_settings.APP_VERSION,
        "access_token_expire_minutes": app_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        "refresh_token_expire_days": app_settings.REFRESH_TOKEN_EXPIRE_DAYS,
        "cors_origins": app_settings.get_cors_origins(),
        "scan_max_assets": app_settings.SCAN_MAX_ASSETS,
        "scan_port_timeout_seconds": app_settings.SCAN_PORT_TIMEOUT,
        "scan_host_budget_seconds": app_settings.SCAN_HOST_BUDGET_SECONDS,
        "scan_allow_private_targets": app_settings.SCAN_ALLOW_PRIVATE_TARGETS,
        "seed_endpoint_enabled": bool(app_settings.SEED_TOKEN),
        "editable": False,
        "note": "Estos valores se configuran por variables de entorno y son de solo lectura desde la API.",
    }
