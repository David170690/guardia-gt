import json
from pydantic_settings import BaseSettings
from typing import List, Union


class Settings(BaseSettings):
    APP_NAME: str = "GuardIA GT"
    APP_VERSION: str = "1.1.0"
    DEBUG: bool = False

    DATABASE_URL: str = "postgresql://guardia:guardia123@localhost:5432/guardia_gt"
    SECRET_KEY: str = "guardia-gt-secret-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    CORS_ORIGINS: Union[str, List[str]] = '["http://localhost:5173","http://localhost:3000","https://guardia-gt-frontend.onrender.com"]'

    # Bootstrap de datos de demostración. Si queda vacío, POST /seed responde 403.
    SEED_TOKEN: str = ""

    # Límites del motor de diagnóstico.
    # Escanear direcciones privadas o de loopback desde el servidor permite sondear
    # la red interna del proveedor, así que está deshabilitado salvo activación explícita.
    SCAN_ALLOW_PRIVATE_TARGETS: bool = False
    SCAN_MAX_ASSETS: int = 25
    SCAN_PORT_TIMEOUT: float = 0.6
    SCAN_MAX_WORKERS: int = 16
    SCAN_HOST_CONCURRENCY: int = 4
    SCAN_HOST_BUDGET_SECONDS: float = 8.0

    class Config:
        env_file = ".env"
        case_sensitive = True
        # Una variable de entorno sobrante no debe impedir que la aplicación arranque.
        extra = "ignore"

    def get_cors_origins(self) -> List[str]:
        if isinstance(self.CORS_ORIGINS, str):
            try:
                parsed = json.loads(self.CORS_ORIGINS)
                if isinstance(parsed, list):
                    return [str(o).strip() for o in parsed if str(o).strip()]
                return [str(parsed).strip()]
            except json.JSONDecodeError:
                return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]
        return list(self.CORS_ORIGINS)


settings = Settings()
