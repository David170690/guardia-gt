"""Configuración de las pruebas.

Las variables de entorno se fijan antes de importar `app`, porque el motor de base
de datos y la configuración se construyen en tiempo de importación.
"""

import os
import tempfile

os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tempfile.gettempdir(), 'guardia_test.db')}"
os.environ["SECRET_KEY"] = "clave-solo-para-pruebas"
os.environ["SEED_TOKEN"] = "token-de-prueba"
os.environ["CORS_ORIGINS"] = '["http://localhost:5173"]'

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.database import Base, SessionLocal, engine, get_db  # noqa: E402
from app.core.security import get_password_hash  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User, UserRole  # noqa: E402


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _make_user(db, email: str, role: UserRole, password: str = "Password123!") -> User:
    user = User(
        email=email,
        full_name=f"Usuario {role.value}",
        hashed_password=get_password_hash(password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def admin(db):
    return _make_user(db, "admin@guardia.gt", UserRole.ADMIN)


@pytest.fixture()
def analyst(db):
    return _make_user(db, "analista@guardia.gt", UserRole.ANALYST)


@pytest.fixture()
def viewer(db):
    return _make_user(db, "viewer@guardia.gt", UserRole.VIEWER)


def auth_headers(client, email: str, password: str = "Password123!") -> dict:
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
