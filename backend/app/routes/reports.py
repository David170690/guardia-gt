"""Reportes y tendencias.

Antes este módulo devolvía cuatro reportes inventados con fechas y número de páginas
fijos, y una serie de tendencia escrita a mano. Ahora describe los reportes que la
plataforma puede componer con los datos que tiene, y calcula la tendencia real a
partir de las fechas de descubrimiento y remediación.
"""

from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.asset import Asset
from app.models.compliance import ComplianceControl
from app.models.incident import Incident
from app.models.vulnerability import Severity, Vulnerability, VulnStatus

router = APIRouter()

MONTHS_ES = ["Ene", "Feb", "Mar", "Abr", "May", "Jun",
             "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"]


@router.get("/")
def get_reports(db: Session = Depends(get_db)):
    """Reportes disponibles y el volumen de datos que respalda a cada uno."""
    vulns = db.query(Vulnerability).count()
    open_vulns = db.query(Vulnerability).filter(Vulnerability.status == VulnStatus.OPEN).count()
    assets = db.query(Asset).count()
    incidents = db.query(Incident).count()
    controls = db.query(ComplianceControl).count()

    reports = [
        {
            "id": "vulnerabilities",
            "name": "Inventario de vulnerabilidades",
            "description": "Hallazgos abiertos ordenados por CVSS, con activo afectado y remediación.",
            "records": vulns,
            "available": vulns > 0,
            "format": "CSV",
        },
        {
            "id": "assets",
            "name": "Inventario de activos",
            "description": "Activos registrados con tipo, criticidad y última fecha de escaneo.",
            "records": assets,
            "available": assets > 0,
            "format": "CSV",
        },
        {
            "id": "incidents",
            "name": "Bitácora de incidentes",
            "description": "Incidentes con severidad, estado y tiempos de contención y resolución.",
            "records": incidents,
            "available": incidents > 0,
            "format": "CSV",
        },
        {
            "id": "compliance",
            "name": "Estado de cumplimiento",
            "description": "Controles por estándar con su puntuación y hallazgos asociados.",
            "records": controls,
            "available": controls > 0,
            "format": "CSV",
        },
    ]

    return {
        "reports": reports,
        "summary": {
            "open_vulnerabilities": open_vulns,
            "total_assets": assets,
            "total_incidents": incidents,
        },
        "note": (
            "La exportación a PDF con redacción asistida todavía no está implementada. "
            "Estos reportes se componen con los datos actuales de la plataforma."
        ),
    }


@router.get("/trends")
def get_trends(months: int = 6, db: Session = Depends(get_db)):
    """Hallazgos descubiertos y remediados por mes, calculados sobre datos reales."""
    months = max(1, min(months, 24))
    now = datetime.now(timezone.utc)

    buckets: "OrderedDict[tuple, dict]" = OrderedDict()
    cursor = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
    keys: List[tuple] = []
    for _ in range(months):
        keys.append((cursor.year, cursor.month))
        cursor = (cursor.replace(day=1) - timedelta(days=1)).replace(day=1)
    for key in reversed(keys):
        buckets[key] = {"discovered": 0, "remediated": 0, "risk": 0}
    # Incluye el mes en curso.
    buckets[(now.year, now.month)] = {"discovered": 0, "remediated": 0, "risk": 0}

    weights = {Severity.CRITICAL: 10, Severity.HIGH: 6, Severity.MEDIUM: 3,
               Severity.LOW: 1, Severity.INFO: 0}

    for vuln in db.query(Vulnerability).all():
        if vuln.discovered_at:
            key = (vuln.discovered_at.year, vuln.discovered_at.month)
            if key in buckets:
                buckets[key]["discovered"] += 1
                buckets[key]["risk"] += weights.get(vuln.severity, 0)
        if vuln.remediated_at:
            key = (vuln.remediated_at.year, vuln.remediated_at.month)
            if key in buckets:
                buckets[key]["remediated"] += 1

    ordered = list(buckets.items())[-months:]
    return {
        "months": [MONTHS_ES[month - 1] for (_, month) in ordered],
        "vulnerabilities": [data["discovered"] for _, data in ordered],
        "remediated": [data["remediated"] for _, data in ordered],
        "risk_scores": [min(100, data["risk"]) for _, data in ordered],
        "note": (
            "Calculado sobre las fechas de descubrimiento y remediación registradas. "
            "Los meses sin diagnósticos aparecen en cero."
        ),
    }
