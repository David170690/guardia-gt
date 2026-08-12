"""Informe ejecutivo asistido por IA.

Genera un resumen para dirección a partir de los hallazgos reales almacenados de una
organización. Con un modelo configurado (MiMo vía OpenRouter) la redacción la hace el
modelo; sin él, una plantilla determinista compone el informe con los mismos datos.
En ningún caso se inventan hallazgos.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.asset import Asset
from app.models.vulnerability import Severity, Vulnerability
from app.services import ai_report

router = APIRouter()

_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                  Severity.LOW: 3, Severity.INFO: 4}
_ACTIONABLE = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}


class ReportRequest(BaseModel):
    organization: str = Field(min_length=1, max_length=255)


class ReportResponse(BaseModel):
    organization: str
    risk_level: str
    generated_by: str
    model: Optional[str]
    executive_summary: str
    key_risks: List[str]
    remediation_plan: List[str]


@router.get("/status")
def ai_status():
    """Indica si hay un modelo configurado y cuál."""
    return {
        "enabled": ai_report.ai_enabled(),
        "model": ai_report.configured_model() if ai_report.ai_enabled() else None,
        "mode": "modelo" if ai_report.ai_enabled() else "plantilla",
        "note": (
            "Hay un modelo de lenguaje configurado; el informe se redacta con IA."
            if ai_report.ai_enabled()
            else "Sin modelo configurado: el informe se compone con una plantilla "
                 "determinista sobre los hallazgos reales. Define AI_API_KEY para activar la IA."
        ),
    }


@router.get("/organizations")
def list_organizations(db: Session = Depends(get_db)):
    """Organizaciones con datos disponibles para generar un informe."""
    rows = (
        db.query(Asset.organization)
        .filter(Asset.organization.isnot(None))
        .distinct()
        .order_by(Asset.organization)
        .all()
    )
    return {"organizations": [r[0] for r in rows if r[0]]}


@router.post("/report", response_model=ReportResponse)
def generate(request: ReportRequest, db: Session = Depends(get_db)):
    organization = request.organization.strip()

    assets = db.query(Asset).filter(Asset.organization == organization).all()
    if not assets:
        raise HTTPException(
            status_code=404,
            detail=f"No hay datos para «{organization}». Ejecuta primero un diagnóstico.",
        )

    asset_ids = [a.id for a in assets]
    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.asset_id.in_(asset_ids))
        .order_by(Vulnerability.cvss_score.desc())
        .all()
    )

    findings = [
        {
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity.value,
            "cvss_score": v.cvss_score,
            "finding_type": v.finding_type,
            "affected_component": v.affected_component,
            "solution": v.solution,
        }
        for v in vulns
    ]

    actionable = [v for v in vulns if v.severity in _ACTIONABLE]
    risk_level = _risk_level(actionable)
    scanned = sum(1 for a in assets if a.ip_address)

    report = ai_report.generate_report(
        organization=organization,
        risk_level=risk_level,
        findings=findings,
        assets_scanned=scanned,
        assets_total=len(assets),
    )
    return ReportResponse(**report.to_dict())


def _risk_level(actionable: List[Vulnerability]) -> str:
    critical = sum(1 for v in actionable if v.severity == Severity.CRITICAL)
    high = sum(1 for v in actionable if v.severity == Severity.HIGH)
    medium = sum(1 for v in actionable if v.severity == Severity.MEDIUM)
    if critical >= 3:
        return "crítico"
    if critical >= 1 or high >= 3:
        return "alto"
    if high >= 1 or medium >= 3:
        return "medio"
    return "bajo"
