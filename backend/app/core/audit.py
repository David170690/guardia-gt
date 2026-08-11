"""Escritura de la bitácora de auditoría.

La tabla `audit_logs` existía desde el inicio pero nunca se escribía.
`record` no debe interrumpir nunca la operación que audita: si falla, se registra
en el log de la aplicación y la petición continúa.
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)

# Acciones auditadas
LOGIN_SUCCESS = "login.success"
LOGIN_FAILED = "login.failed"
USER_CREATED = "user.created"
USER_UPDATED = "user.updated"
USER_DELETED = "user.deleted"
USER_TOGGLED = "user.toggled"
PASSWORD_CHANGED = "password.changed"
PROFILE_UPDATED = "profile.updated"
DIAGNOSTIC_RUN = "diagnostic.run"
DIAGNOSTIC_REJECTED = "diagnostic.rejected"
SEED_RUN = "seed.run"


def record(
    db: Session,
    action: str,
    *,
    user_id: Optional[int] = None,
    resource: Optional[str] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> None:
    """Registra una acción. Hace commit por su cuenta para no arrastrar la transacción llamante."""
    try:
        db.add(
            AuditLog(
                user_id=user_id,
                action=action,
                resource=resource[:255] if resource else None,
                details=details,
                ip_address=ip_address[:45] if ip_address else None,
            )
        )
        db.commit()
    except Exception as exc:  # pragma: no cover - la auditoría nunca debe romper la petición
        logger.warning("No se pudo escribir la auditoría (%s): %s", action, exc)
        db.rollback()
