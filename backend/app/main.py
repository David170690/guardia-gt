from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.routes import auth, vulnerabilities, compliance, assets, incidents, dashboard, reports

app = FastAPI(
    title="GuardIA GT API",
    description="Plataforma Inteligente de Gestión Preventiva de Riesgos Cibernéticos con IA",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["Vulnerabilidades"])
app.include_router(compliance.router, prefix="/api/compliance", tags=["Cumplimiento"])
app.include_router(assets.router, prefix="/api/assets", tags=["Activos"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incidentes"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reportes"])


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "service": "GuardIA GT API", "version": "1.0.0"}
