"""CLI para cargar los datos de demostración.

    python seed_data.py

Los datos viven en `app/seed.py`, compartidos con el endpoint `POST /seed`.
"""

from app.core.database import Base, SessionLocal, engine
from app.seed import seed_database


def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        result = seed_database(db)
        print(result["message"])
    finally:
        db.close()


if __name__ == "__main__":
    main()
