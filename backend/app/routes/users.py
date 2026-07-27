from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.core.security import get_password_hash, verify_password
from app.models.user import User, UserRole
from app.schemas.auth import UserCreate, UserResponse

router = APIRouter()


def require_admin(token: str = None, db: Session = None):
    from app.routes.auth import oauth2_scheme
    from app.core.security import decode_token
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user or user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@router.get("/", response_model=List[UserResponse])
def list_users(
    token: str = Depends(__import__('app.routes.auth', fromlist=['oauth2_scheme']).oauth2_scheme),
    db: Session = Depends(get_db),
):
    require_admin(token, db)
    return db.query(User).order_by(User.id).all()


@router.post("/", response_model=UserResponse)
def create_user(
    user: UserCreate,
    token: str = Depends(__import__('app.routes.auth', fromlist=['oauth2_scheme']).oauth2_scheme),
    db: Session = Depends(get_db),
):
    require_admin(token, db)
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email ya registrado")
    db_user = User(
        email=user.email,
        full_name=user.full_name,
        hashed_password=get_password_hash(user.password),
        role=UserRole(user.role) if user.role else UserRole.VIEWER,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user: UserCreate,
    token: str = Depends(__import__('app.routes.auth', fromlist=['oauth2_scheme']).oauth2_scheme),
    db: Session = Depends(get_db),
):
    require_admin(token, db)
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    db_user.email = user.email
    db_user.full_name = user.full_name
    db_user.role = UserRole(user.role) if user.role else db_user.role
    if user.password:
        db_user.hashed_password = get_password_hash(user.password)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    token: str = Depends(__import__('app.routes.auth', fromlist=['oauth2_scheme']).oauth2_scheme),
    db: Session = Depends(get_db),
):
    admin = require_admin(token, db)
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if db_user.id == admin.id:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propia cuenta")
    db.delete(db_user)
    db.commit()
    return {"message": "Usuario eliminado"}


@router.patch("/{user_id}/toggle-active")
def toggle_user_active(
    user_id: int,
    token: str = Depends(__import__('app.routes.auth', fromlist=['oauth2_scheme']).oauth2_scheme),
    db: Session = Depends(get_db),
):
    require_admin(token, db)
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    db_user.is_active = not db_user.is_active
    db.commit()
    return {"message": f"Usuario {'activado' if db_user.is_active else 'desactivado'}", "is_active": db_user.is_active}
