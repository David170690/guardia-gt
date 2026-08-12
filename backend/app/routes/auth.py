from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.deps import client_ip, get_current_user
from app.core.ratelimit import limiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)
from app.models.user import User, UserRole
from app.schemas.auth import Token, TokenRefresh, UserCreate, UserLogin, UserResponse

router = APIRouter()


def _issue_tokens(user: User) -> Token:
    return Token(
        access_token=create_access_token(data={"sub": str(user.id), "role": user.role.value}),
        refresh_token=create_refresh_token(data={"sub": str(user.id)}),
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Registro público. El rol siempre es `viewer`.

    Asignar roles es competencia de un administrador desde `/api/users`.
    """
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="El correo ya está registrado")

    db_user = User(
        email=user.email,
        full_name=user.full_name,
        hashed_password=get_password_hash(user.password),
        role=UserRole.VIEWER,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.post("/login", response_model=Token)
@limiter.limit("10/minute")
def login(credentials: UserLogin, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == credentials.email).first()
    ip = client_ip(request)

    if not user or not verify_password(credentials.password, user.hashed_password):
        audit.record(db, audit.LOGIN_FAILED, resource=credentials.email, ip_address=ip)
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    if not user.is_active:
        audit.record(db, audit.LOGIN_FAILED, user_id=user.id, resource=credentials.email,
                     details="cuenta desactivada", ip_address=ip)
        raise HTTPException(status_code=403, detail="Cuenta desactivada")

    # Segundo factor: si la cuenta tiene MFA activo, exige un código TOTP válido.
    # El código de estado 428 ("Precondition Required") le dice al frontend que
    # debe pedir el código sin tratar el primer paso como credencial inválida.
    if user.mfa_enabled:
        if not credentials.code:
            raise HTTPException(status_code=428, detail="Se requiere el código de verificación (MFA)")
        from app.services import mfa
        if not mfa.verify(user.mfa_secret, credentials.code):
            audit.record(db, audit.LOGIN_FAILED, user_id=user.id, resource=user.email,
                         details="código MFA inválido", ip_address=ip)
            raise HTTPException(status_code=401, detail="Código de verificación incorrecto")

    audit.record(db, audit.LOGIN_SUCCESS, user_id=user.id, resource=user.email, ip_address=ip)
    return _issue_tokens(user)


@router.post("/refresh", response_model=Token)
def refresh_token(body: TokenRefresh, db: Session = Depends(get_db)):
    payload = decode_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Token de refresco inválido")

    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Token de refresco inválido")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Cuenta desactivada")

    return _issue_tokens(user)


@router.get("/me", response_model=UserResponse)
def read_current_user(user: User = Depends(get_current_user)):
    return user
