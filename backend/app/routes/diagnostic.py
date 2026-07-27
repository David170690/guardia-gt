from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from app.core.database import get_db
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.vulnerability import Vulnerability, Severity, VulnStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.compliance import ComplianceControl, ComplianceStandard, ComplianceStatus

router = APIRouter()


class AssetInput(BaseModel):
    name: str
    asset_type: str
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    criticality: str = "medium"


class DiagnosticRequest(BaseModel):
    organization_name: str
    ip_range: Optional[str] = None
    assets: List[AssetInput]
    scan_type: str = "full"


class DiagnosticResult(BaseModel):
    assets_created: int
    vulnerabilities_found: int
    incidents_created: int
    compliance_score: float
    risk_level: str
    summary: str


@router.post("/run", response_model=DiagnosticResult)
def run_diagnostic(request: DiagnosticRequest, db: Session = Depends(get_db)):
    # Limpiar datos anteriores de la misma organización si existe
    existing_assets = db.query(Asset).filter(
        Asset.name.like(f"%{request.organization_name}%")
    ).all()
    for a in existing_assets:
        db.query(Vulnerability).filter(Vulnerability.asset_id == a.id).delete()
        db.delete(a)
    db.commit()

    assets_created = 0
    vulns_found = 0
    incidents_created = 0

    # Crear activos escaneados
    new_assets = []
    for asset_input in request.assets:
        asset = Asset(
            name=asset_input.name,
            asset_type=AssetType(asset_input.asset_type),
            ip_address=asset_input.ip_address,
            operating_system=asset_input.operating_system,
            criticality=AssetCriticality(asset_input.criticality),
            status=AssetStatus.ONLINE,
            cpu_usage=0.0,
            ram_usage=0.0,
        )
        db.add(asset)
        db.flush()
        new_assets.append(asset)
        assets_created += 1

    db.commit()

    # Simular hallazgos de vulnerabilidades por activo
    vuln_templates = [
        {"cve": "CVE-2026-NEW-001", "title": "Servicio expuesto sin TLS", "cvss": 6.5, "severity": "medium", "solution": "Habilitar TLS en todos los servicios"},
        {"cve": "CVE-2026-NEW-002", "title": "Versión desactualizada detectada", "cvss": 7.8, "severity": "high", "solution": "Actualizar a la última versión estable"},
        {"cve": "CVE-2026-NEW-003", "title": "Puerto administrativo abierto", "cvss": 5.3, "severity": "medium", "solution": "Restringir acceso por IP"},
        {"cve": "CVE-2026-NEW-004", "title": "Certificado SSL próximo a vencer", "cvss": 4.0, "severity": "low", "solution": "Renovar certificado"},
        {"cve": "CVE-2026-NEW-005", "title": "Configuración por defecto detectada", "cvss": 8.1, "severity": "high", "solution": "Cambiar credenciales por defecto"},
    ]

    import random
    random.seed(int(datetime.now().timestamp()))

    for asset in new_assets:
        num_vulns = random.randint(1, 3)
        selected = random.sample(vuln_templates, min(num_vulns, len(vuln_templates)))
        for v in selected:
            vuln = Vulnerability(
                cve_id=f"{v['cve']}-{asset.id}",
                title=v["title"],
                description=f"Vulnerabilidad detectada en {asset.name} ({asset.ip_address})",
                cvss_score=v["cvss"],
                severity=Severity(v["severity"]),
                status=VulnStatus.OPEN,
                asset_id=asset.id,
                affected_component=asset.name,
                solution=v["solution"],
            )
            db.add(vuln)
            vulns_found += 1

    db.commit()

    # Crear incidentes leves por activos con vulnerabilidades altas/críticas
    high_vulns = db.query(Vulnerability).filter(
        Vulnerability.severity.in_([Severity.CRITICAL, Severity.HIGH]),
        Vulnerability.asset_id.in_([a.id for a in new_assets])
    ).all()

    for v in high_vulns:
        incident = Incident(
            title=f"Vulnerabilidad detectada — {v.affected_component}",
            description=f"{v.title} (CVSS {v.cvss_score})",
            severity=IncidentSeverity.HIGH if v.severity == Severity.HIGH else IncidentSeverity.CRITICAL,
            status=IncidentStatus.OPEN,
            affected_asset=v.affected_component,
            response_action="Requiere remediación",
        )
        db.add(incident)
        incidents_created += 1

    db.commit()

    # Calcular score de cumplimiento simulado
    total_controls = db.query(ComplianceControl).count()
    compliant_controls = db.query(ComplianceControl).filter(
        ComplianceControl.status.in_([ComplianceStatus.COMPLIANT, ComplianceStatus.PARTIAL])
    ).count()
    compliance_score = (compliant_controls / total_controls * 100) if total_controls > 0 else 0

    # Determinar nivel de riesgo
    critical_count = db.query(Vulnerability).filter(Vulnerability.severity == Severity.CRITICAL).count()
    high_count = db.query(Vulnerability).filter(Vulnerability.severity == Severity.HIGH).count()

    if critical_count >= 3:
        risk_level = "crítico"
    elif critical_count >= 1 or high_count >= 3:
        risk_level = "alto"
    elif high_count >= 1:
        risk_level = "medio"
    else:
        risk_level = "bajo"

    summary = (
        f"Diagnóstico completado para {request.organization_name}. "
        f"Se escanearon {assets_created} activos, se encontraron {vulns_found} vulnerabilidades "
        f"y se generaron {incidents_created} incidentes. "
        f"Nivel de riesgo: {risk_level.upper()}."
    )

    return DiagnosticResult(
        assets_created=assets_created,
        vulnerabilities_found=vulns_found,
        incidents_created=incidents_created,
        compliance_score=round(compliance_score, 1),
        risk_level=risk_level,
        summary=summary,
    )
