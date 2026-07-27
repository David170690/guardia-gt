import json
from pydantic_settings import BaseSettings
from typing import List, Union


class Settings(BaseSettings):
    APP_NAME: str = "GuardIA GT"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    DATABASE_URL: str = "postgresql://guardia:guardia123@localhost:5432/guardia_gt"
    SECRET_KEY: str = "guardia-gt-secret-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    CORS_ORIGINS: Union[str, List[str]] = '["http://localhost:5173","http://localhost:3000"]'

    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4"

    class Config:
        env_file = ".env"
        case_sensitive = True

    def get_cors_origins(self) -> List[str]:
        if isinstance(self.CORS_ORIGINS, str):
            try:
                return json.loads(self.CORS_ORIGINS)
            except json.JSONDecodeError:
                return [o.strip() for o in self.CORS_ORIGINS.split(",")]
        return self.CORS_ORIGINS


settings = Settings()
