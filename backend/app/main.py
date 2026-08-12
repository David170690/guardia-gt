import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import Base, apply_schema_fixes, engine, get_db
from app.core.deps import get_current_user, require_admin
from app.core.ratelimit import limiter
from app.routes import (
    ai,
    assets,
    auth,
    compliance,
    dashboard,
    diagnostic,
    incidents,
    reports,
    users,
    vulnerabilities,
)
from app.routes import settings as settings_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # `create_all` cubre una base nueva; `apply_schema_fixes` alinea una base creada
    # por una versión anterior, que es lo que hay desplegado en Render.
    import app.models  # noqa: F401 — registra todos los modelos en Base.metadata

    Base.metadata.create_all(bind=engine)
    apply_schema_fixes()
    logger.info("GuardIA GT %s lista", settings.APP_VERSION)
    yield


app = FastAPI(
    title="GuardIA GT API",
    description="Plataforma Inteligente de Gestión Preventiva de Riesgos Cibernéticos",
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Limitador de tasa: protege el login de fuerza bruta y el diagnóstico de abuso.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Los orígenes salen de la configuración. Antes estaban fijados a ["*"], así que la
# variable CORS_ORIGINS del despliegue no tenía ningún efecto.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Solo /api/auth queda abierto: es donde se obtiene el token.
# Todo lo demás exige sesión, y /api/users además rol de administrador.
authenticated = [Depends(get_current_user)]

app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"], dependencies=authenticated)
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["Vulnerabilidades"], dependencies=authenticated)
app.include_router(compliance.router, prefix="/api/compliance", tags=["Cumplimiento"], dependencies=authenticated)
app.include_router(assets.router, prefix="/api/assets", tags=["Activos"], dependencies=authenticated)
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incidentes"], dependencies=authenticated)
app.include_router(reports.router, prefix="/api/reports", tags=["Reportes"], dependencies=authenticated)
app.include_router(diagnostic.router, prefix="/api/diagnostic", tags=["Diagnóstico"], dependencies=authenticated)
app.include_router(ai.router, prefix="/api/ai", tags=["IA"], dependencies=authenticated)
app.include_router(settings_router.router, prefix="/api/settings", tags=["Configuración"], dependencies=authenticated)
app.include_router(users.router, prefix="/api/users", tags=["Usuarios"], dependencies=[Depends(require_admin)])


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "service": "GuardIA GT API", "version": settings.APP_VERSION}


@app.post("/seed", tags=["Setup"])
def seed(
    x_seed_token: str = Header(default="", alias="X-Seed-Token"),
    db: Session = Depends(get_db),
):
    """Carga los datos de demostración en una base vacía.

    Exige la cabecera `X-Seed-Token` con el valor de la variable de entorno
    `SEED_TOKEN`. Sin esa variable el endpoint está deshabilitado: antes era público
    y permitía a cualquiera sembrar credenciales conocidas en una base recién creada.
    """
    from app.seed import seed_database

    if not settings.SEED_TOKEN:
        raise HTTPException(
            status_code=403,
            detail="Endpoint deshabilitado. Define la variable de entorno SEED_TOKEN para habilitarlo.",
        )
    if x_seed_token != settings.SEED_TOKEN:
        raise HTTPException(status_code=403, detail="Token de siembra inválido")

    try:
        return seed_database(db)
    except Exception as exc:
        db.rollback()
        logger.exception("Fallo la siembra de datos")
        raise HTTPException(status_code=500, detail=f"Error al sembrar: {exc}") from exc
