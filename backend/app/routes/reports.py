from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter()


@router.get("/")
def get_reports(db: Session = Depends(get_db)):
    return {
        "reports": [
            {
                "id": 1,
                "name": "Cumplimiento ISO 27001",
                "generated_at": "2026-07-26T10:30:00Z",
                "pages": 48,
                "format": "PDF",
                "status": "ready",
            },
            {
                "id": 2,
                "name": "Vulnerabilidades Mensual",
                "generated_at": "2026-07-26T09:15:00Z",
                "pages": 24,
                "format": "PDF",
                "status": "ready",
            },
            {
                "id": 3,
                "name": "Resumen Ejecutivo IA",
                "generated_at": "2026-07-25T18:00:00Z",
                "pages": 12,
                "format": "PDF",
                "status": "ready",
            },
            {
                "id": 4,
                "name": "NIST CSF 2.0 Assessment",
                "generated_at": None,
                "pages": None,
                "format": None,
                "status": "generating",
            },
        ]
    }


@router.get("/trends")
def get_trends(db: Session = Depends(get_db)):
    return {
        "months": ["Ene", "Feb", "Mar", "Abr", "May", "Jun"],
        "risk_scores": [85, 78, 72, 68, 60, 55],
        "vulnerabilities": [65, 58, 52, 48, 47, 42],
    }
