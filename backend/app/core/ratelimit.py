"""Limitador de tasa compartido.

Se define aquí, aparte de main.py, para que los routers puedan importar la misma
instancia sin ciclos de importación. La clave es la IP real del cliente (respetando
el proxy de Render), de modo que el límite aplique por origen y no por el proxy.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings


def _client_key(request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(key_func=_client_key, enabled=settings.RATE_LIMIT_ENABLED)
