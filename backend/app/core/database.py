import logging

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker, declarative_base

from app.core.config import settings

logger = logging.getLogger(__name__)

# Hosts donde exigir TLS rompe la conexión: Postgres local y el contenedor de compose
# vienen con SSL desactivado y libpq aborta con "server does not support SSL".
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "postgres", "db", ""}


def _requires_ssl(url_str: str) -> bool:
    try:
        host = (make_url(url_str).host or "").lower()
    except Exception:
        return False
    return host not in LOCAL_HOSTS


def get_engine():
    url = settings.DATABASE_URL
    connect_args = {}

    if url.startswith("sqlite"):
        # Solo se usa en las pruebas.
        return create_engine(url, connect_args={"check_same_thread": False})

    if _requires_ssl(url) and "sslmode" not in url:
        connect_args["sslmode"] = "require"

    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        connect_args=connect_args,
    )


engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# DDL correctivo aplicado al arrancar.
#
# El esquema nace de `Base.metadata.create_all`, que crea tablas nuevas pero nunca
# altera las existentes. El plan gratuito de Render no da acceso a shell, así que no
# hay forma de ejecutar `alembic upgrade` a mano sobre la base ya desplegada.
# Cada sentencia es idempotente y se ejecuta de forma independiente: si una falla,
# se registra y las demás continúan.
_SCHEMA_FIXES = [
    (
        "vulnerabilities.cve_id deja de ser único",
        "DROP INDEX IF EXISTS ix_vulnerabilities_cve_id",
    ),
    (
        "constraint único heredado sobre cve_id",
        """
        DO $$
        DECLARE target text;
        BEGIN
            SELECT con.conname INTO target
            FROM pg_constraint con
            JOIN pg_class rel ON rel.oid = con.conrelid
            JOIN pg_attribute att ON att.attrelid = rel.oid AND att.attnum = ANY(con.conkey)
            WHERE rel.relname = 'vulnerabilities'
              AND con.contype = 'u'
              AND att.attname = 'cve_id'
              AND array_length(con.conkey, 1) = 1
            LIMIT 1;
            IF target IS NOT NULL THEN
                EXECUTE format('ALTER TABLE vulnerabilities DROP CONSTRAINT %I', target);
            END IF;
        END $$;
        """,
    ),
    (
        "cve_id ampliado a 64 caracteres",
        "ALTER TABLE vulnerabilities ALTER COLUMN cve_id TYPE VARCHAR(64)",
    ),
    (
        "índice no único sobre cve_id",
        "CREATE INDEX IF NOT EXISTS ix_vulnerabilities_cve_id ON vulnerabilities (cve_id)",
    ),
    (
        "assets.organization",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS organization VARCHAR(255)",
    ),
    (
        "índice sobre assets.organization",
        "CREATE INDEX IF NOT EXISTS ix_assets_organization ON assets (organization)",
    ),
    (
        "incidents.organization",
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS organization VARCHAR(255)",
    ),
    (
        "índice sobre incidents.organization",
        "CREATE INDEX IF NOT EXISTS ix_incidents_organization ON incidents (organization)",
    ),
    (
        "vulnerabilities.finding_type",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS finding_type VARCHAR(32)",
    ),
]


def apply_schema_fixes() -> None:
    """Alinea una base creada por una versión anterior con el modelo actual."""
    if engine.dialect.name != "postgresql":
        return

    for description, statement in _SCHEMA_FIXES:
        try:
            with engine.begin() as conn:
                conn.execute(text(statement))
        except Exception as exc:
            logger.warning("Ajuste de esquema omitido (%s): %s", description, exc)
