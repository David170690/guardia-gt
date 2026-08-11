"""Gestión de usuarios. Todo el router exige rol de administrador, aplicado en `main.py`."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.deps import client_ip, require_admin
from app.core.security import get_password_hash
from app.models.user import User, UserRole
from app.schemas.auth import UserAdminCreate, UserAdminUpdate, UserResponse

router = APIRouter()


def _parse_role(value: str | None, fallback: UserRole = UserRole.VIEWER) -> UserRole:
    if not value:
        return fallback
    try:
        return UserRole(value)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Rol inválido: {value}. Válidos: {', '.join(r.value for r in UserRole)}",
        )


@router.get("/", response_model=List[UserResponse])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).order_by(User.id).all()


@router.post("/", response_model=UserResponse, status_code=201)
def create_user(
    payload: UserAdminCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="El correo ya está registrado")

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        role=_parse_role(payload.role),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    audit.record(db, audit.USER_CREATED, user_id=admin.id, resource=user.email,
                 details=f"rol {user.role.value}", ip_address=client_ip(request))
    return user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    payload: UserAdminUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if payload.email != user.email:
        if db.query(User).filter(User.email == payload.email, User.id != user_id).first():
            raise HTTPException(status_code=400, detail="El correo ya está en uso")
        user.email = payload.email

    user.full_name = payload.full_name

    new_role = _parse_role(payload.role, user.role)
    # Un administrador no puede degradarse a sí mismo si es el último que queda.
    if user.id == admin.id and new_role != UserRole.ADMIN:
        remaining = db.query(User).filter(User.role == UserRole.ADMIN, User.id != user.id).count()
        if remaining == 0:
            raise HTTPException(status_code=400, detail="No puedes quitarte el último rol de administrador")
    user.role = new_role

    if payload.password:
        user.hashed_password = get_password_hash(payload.password)

    db.commit()
    db.refresh(user)

    audit.record(db, audit.USER_UPDATED, user_id=admin.id, resource=user.email,
                 details=f"rol {user.role.value}", ip_address=client_ip(request))
    return user


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propia cuenta")

    email = user.email
    db.delete(user)
    db.commit()

    audit.record(db, audit.USER_DELETED, user_id=admin.id, resource=email,
                 ip_address=client_ip(request))
    return {"message": "Usuario eliminado"}


@router.patch("/{user_id}/toggle-active")
def toggle_user_active(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="No puedes desactivar tu propia cuenta")

    user.is_active = not user.is_active
    db.commit()

    audit.record(db, audit.USER_TOGGLED, user_id=admin.id, resource=user.email,
                 details="activado" if user.is_active else "desactivado",
                 ip_address=client_ip(request))
    return {
        "message": f"Usuario {'activado' if user.is_active else 'desactivado'}",
        "is_active": user.is_active,
    }
