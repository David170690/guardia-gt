"""Motor de diagnóstico.

Escanea los activos de una organización y persiste los hallazgos acotados a ella.
Todo lo que devuelve este endpoint procede de esta ejecución: nunca mezcla los datos
de otros clientes ni rellena el informe con hallazgos inventados cuando el escaneo
no encuentra nada.
"""

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import settings
from app.core.database import get_db
from app.core.deps import client_ip, get_current_user
from app.core.ratelimit import limiter
from app.models.asset import Asset, AssetCriticality, AssetStatus, AssetType
from app.models.compliance import ComplianceControl, ComplianceStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.user import User
from app.models.vulnerability import FindingType, Severity, Vulnerability, VulnStatus
from app.services import compliance_map
from app.services.nmap_scanner import NetworkScanner

logger = logging.getLogger(__name__)
router = APIRouter()

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ACTIONABLE = {"critical", "high", "medium", "low"}


class AssetInput(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    asset_type: str
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    criticality: str = "medium"


class DiagnosticRequest(BaseModel):
    organization_name: str = Field(min_length=1, max_length=255)
    ip_range: Optional[str] = None
    assets: List[AssetInput] = Field(min_length=1)
    scan_type: str = "full"


class AssetDetail(BaseModel):
    id: int
    name: str
    asset_type: str
    ip_address: Optional[str]
    operating_system: Optional[str]
    criticality: str
    status: str


class VulnDetail(BaseModel):
    id: int
    cve_id: str
    title: str
    cvss_score: float
    severity: str
    status: str
    finding_type: Optional[str] = None
    affected_component: Optional[str]
    solution: Optional[str]
    ssl_info: Optional[dict] = None


class IncidentDetail(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    affected_asset: Optional[str]
    response_action: Optional[str]


class ComplianceDetail(BaseModel):
    standard: str
    control_id: str
    control_name: str
    status: str
    score: float
    findings: Optional[str]


class DiagnosticResult(BaseModel):
    organization: str
    assets_created: int
    assets_scanned: int
    assets_unreachable: int
    vulnerabilities_found: int
    incidents_created: int
    compliance_score: float
    compliance_assessed: bool
    risk_level: str
    summary: str
    notes: List[str]
    assets_detail: List[AssetDetail]
    vulns_detail: List[VulnDetail]
    incidents_detail: List[IncidentDetail]
    compliance_detail: List[ComplianceDetail]


@router.post("/run", response_model=DiagnosticResult)
@limiter.limit("6/minute")
def run_diagnostic(
    body: DiagnosticRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if len(body.assets) > settings.SCAN_MAX_ASSETS:
        audit.record(
            db, audit.DIAGNOSTIC_REJECTED, user_id=user.id,
            resource=body.organization_name,
            details=f"{len(body.assets)} activos solicitados",
            ip_address=client_ip(request),
        )
        raise HTTPException(
            status_code=400,
            detail=f"Máximo {settings.SCAN_MAX_ASSETS} activos por diagnóstico; se recibieron {len(body.assets)}.",
        )

    try:
        result = _execute(body, db, user)
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("Fallo el diagnóstico de %s", body.organization_name)
        raise HTTPException(status_code=500, detail=f"Error en el diagnóstico: {exc}") from exc

    audit.record(
        db, audit.DIAGNOSTIC_RUN, user_id=user.id,
        resource=body.organization_name,
        details=(
            f"{result.assets_created} activos, {result.vulnerabilities_found} hallazgos, "
            f"riesgo {result.risk_level}"
        ),
        ip_address=client_ip(request),
    )
    return result


def _execute(request: DiagnosticRequest, db: Session, user: User) -> DiagnosticResult:
    organization = request.organization_name.strip()
    notes: List[str] = []

    _purge_previous(db, organization)
    assets = _create_assets(db, request, organization)

    findings_by_asset = _scan(assets, request.scan_type)
    vulnerabilities = _persist_findings(db, assets, findings_by_asset)
    incidents = _create_incidents(db, organization, vulnerabilities, assets)

    actionable = [v for v in vulnerabilities if v.severity.value in ACTIONABLE]
    unreachable = sum(
        1 for f in _flatten(findings_by_asset)
        if f.get("finding_type") == FindingType.REACHABILITY.value
    )
    scanned = sum(1 for a in assets if a.ip_address)

    if scanned == 0:
        notes.append(
            "Ningún activo tenía dirección IP o nombre de dominio, así que no se ejecutó ningún escaneo."
        )
    elif not actionable:
        notes.append(
            "El escaneo se completó sin encontrar hallazgos accionables. "
            "Un informe vacío es un resultado válido, no un fallo."
        )
    if unreachable:
        notes.append(
            f"{unreachable} activo(s) no se pudieron alcanzar desde el servidor. "
            "Para inventarios en red privada, instala GuardIA dentro de la red del cliente."
        )

    risk_level = _risk_level(actionable)
    all_findings = _flatten(findings_by_asset)
    compliance_assessed, compliance_score, compliance_detail = _compliance(db, all_findings)
    if compliance_assessed:
        notes.append(
            "El cumplimiento se evaluó a partir de los hallazgos reales de este diagnóstico. "
            "Es una comprobación externa de controles verificables, no una auditoría completa."
        )
    elif compliance_detail:
        notes.append(
            "No se observaron servicios suficientes para evaluar cumplimiento; se muestra el "
            "marco de referencia cargado en la plataforma."
        )

    summary = (
        f"Diagnóstico de {organization}: se registraron {len(assets)} activos, "
        f"se escanearon {scanned} y se identificaron {len(actionable)} hallazgos accionables "
        f"de {len(vulnerabilities)} observaciones totales. Nivel de riesgo: {risk_level.upper()}."
    )

    return DiagnosticResult(
        organization=organization,
        assets_created=len(assets),
        assets_scanned=scanned,
        assets_unreachable=unreachable,
        vulnerabilities_found=len(actionable),
        incidents_created=len(incidents),
        compliance_score=compliance_score,
        compliance_assessed=compliance_assessed,
        risk_level=risk_level,
        summary=summary,
        notes=notes,
        assets_detail=[
            AssetDetail(
                id=a.id, name=a.name, asset_type=a.asset_type.value,
                ip_address=a.ip_address, operating_system=a.operating_system,
                criticality=a.criticality.value, status=a.status.value,
            )
            for a in assets
        ],
        vulns_detail=_vuln_details(vulnerabilities, findings_by_asset),
        incidents_detail=[
            IncidentDetail(
                id=i.id, title=i.title, severity=i.severity.value, status=i.status.value,
                affected_asset=i.affected_asset, response_action=i.response_action,
            )
            for i in incidents
        ],
        compliance_detail=compliance_detail,
    )


# --------------------------------------------------------------------- pasos


def _purge_previous(db: Session, organization: str) -> None:
    """Elimina el diagnóstico anterior de esta organización, y solo de esta.

    La versión previa comparaba el nombre de la organización con el *nombre del activo*,
    que casi nunca coincidía, así que los datos se acumulaban indefinidamente.
    """
    previous = db.query(Asset).filter(Asset.organization == organization).all()
    if previous:
        asset_ids = [a.id for a in previous]
        db.query(Vulnerability).filter(Vulnerability.asset_id.in_(asset_ids)).delete(
            synchronize_session=False
        )
        for asset in previous:
            db.delete(asset)
    db.query(Incident).filter(Incident.organization == organization).delete(
        synchronize_session=False
    )
    db.commit()


def _create_assets(db: Session, request: DiagnosticRequest, organization: str) -> List[Asset]:
    assets: List[Asset] = []
    for item in request.assets:
        try:
            asset_type = AssetType(item.asset_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Tipo de activo inválido: {item.asset_type}")
        try:
            criticality = AssetCriticality(item.criticality)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Criticidad inválida: {item.criticality}")

        asset = Asset(
            name=item.name.strip(),
            organization=organization,
            asset_type=asset_type,
            ip_address=(item.ip_address or "").strip() or None,
            operating_system=(item.operating_system or "").strip() or None,
            criticality=criticality,
            status=AssetStatus.ONLINE,
            last_scan=datetime.now(timezone.utc),
        )
        db.add(asset)
        assets.append(asset)

    db.commit()
    for asset in assets:
        db.refresh(asset)
    return assets


def _scan(assets: List[Asset], scan_type: str) -> Dict[int, List[Dict[str, Any]]]:
    """Escanea los activos con IP. Devuelve los hallazgos indexados por `asset.id`."""
    scanner = NetworkScanner()
    targets = [a for a in assets if a.ip_address]
    results: Dict[int, List[Dict[str, Any]]] = {a.id: [] for a in assets}
    if not targets:
        return results

    def run(asset: Asset):
        report = scanner.scan(asset.ip_address, scan_type)
        return asset.id, scanner.build_findings(report.hosts[0]) if report.hosts else []

    workers = min(settings.SCAN_HOST_CONCURRENCY, len(targets))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for asset_id, findings in pool.map(run, targets):
            results[asset_id] = findings
    return results


def _flatten(findings_by_asset: Dict[int, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    return [f for group in findings_by_asset.values() for f in group]


def _persist_findings(
    db: Session, assets: List[Asset], findings_by_asset: Dict[int, List[Dict[str, Any]]]
) -> List[Vulnerability]:
    """Guarda los hallazgos con el activo correcto, deduplicando por componente.

    Antes todo se colgaba de `new_assets[0].id`, así que el informe atribuía al primer
    activo los hallazgos de todos los demás.
    """
    by_name = {a.id: a for a in assets}
    stored: List[Vulnerability] = []
    seen: set[tuple] = set()

    for asset_id, findings in findings_by_asset.items():
        asset = by_name.get(asset_id)
        if not asset:
            continue
        for finding in findings:
            component = finding.get("affected_component") or asset.name
            key = (asset_id, finding.get("cve_id"), component)
            if key in seen:
                continue
            seen.add(key)

            severity_value = str(finding.get("severity", "info")).lower()
            if severity_value not in SEVERITY_ORDER:
                severity_value = "info"

            vulnerability = Vulnerability(
                cve_id=str(finding.get("cve_id", "UNKNOWN"))[:64],
                title=str(finding.get("title", "Hallazgo sin título"))[:500],
                description=finding.get("description", ""),
                cvss_score=float(finding.get("cvss_score", 0.0)),
                severity=Severity(severity_value),
                status=VulnStatus.OPEN,
                finding_type=finding.get("finding_type", FindingType.EXPOSURE.value),
                asset_id=asset_id,
                affected_component=component[:255],
                solution=finding.get("solution", ""),
            )
            db.add(vulnerability)
            stored.append(vulnerability)

    db.commit()
    for vulnerability in stored:
        db.refresh(vulnerability)
    return stored


def _create_incidents(
    db: Session, organization: str, vulnerabilities: List[Vulnerability], assets: List[Asset]
) -> List[Incident]:
    """Abre un incidente por cada hallazgo alto o crítico.

    `affected_asset` guarda el nombre del activo (no "ip:puerto") para que el listado
    del informe encuentre efectivamente los incidentes que acaba de crear.
    """
    asset_names = {a.id: a.name for a in assets}
    incidents: List[Incident] = []

    for vulnerability in vulnerabilities:
        if vulnerability.severity not in (Severity.CRITICAL, Severity.HIGH):
            continue
        asset_name = asset_names.get(vulnerability.asset_id, vulnerability.affected_component)
        incident = Incident(
            title=f"Hallazgo {vulnerability.severity.value} — {asset_name}",
            organization=organization,
            description=f"{vulnerability.title} (CVSS {vulnerability.cvss_score}) en {vulnerability.affected_component}",
            severity=(
                IncidentSeverity.CRITICAL
                if vulnerability.severity == Severity.CRITICAL
                else IncidentSeverity.HIGH
            ),
            status=IncidentStatus.OPEN,
            affected_asset=asset_name,
            response_action=vulnerability.solution or "Requiere remediación",
        )
        db.add(incident)
        incidents.append(incident)

    db.commit()
    for incident in incidents:
        db.refresh(incident)
    return incidents


def _risk_level(actionable: List[Vulnerability]) -> str:
    """Calcula el riesgo con los hallazgos de *esta* ejecución.

    Antes se contaba toda la tabla, así que los datos de demostración y los de otros
    clientes inflaban el riesgo de cualquier diagnóstico.
    """
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


def _compliance(db: Session, findings: List[Dict[str, Any]]) -> tuple[bool, float, List[ComplianceDetail]]:
    """Evalúa cumplimiento con los hallazgos reales cuando se observaron servicios;
    si no, devuelve el marco de referencia cargado en la plataforma."""
    observed = any(f.get("finding_type") in ("exposure", "ssl", "cve") for f in findings)
    if observed:
        assessment = compliance_map.assess(findings)
        detail = [ComplianceDetail(**c) for c in assessment]
        return True, compliance_map.score(assessment), detail
    baseline_score, baseline_detail = _compliance_baseline(db)
    return False, baseline_score, baseline_detail


def _compliance_baseline(db: Session) -> tuple[float, List[ComplianceDetail]]:
    controls = db.query(ComplianceControl).all()
    if not controls:
        return 0.0, []
    compliant = sum(
        1 for c in controls
        if c.status in (ComplianceStatus.COMPLIANT, ComplianceStatus.PARTIAL)
    )
    score = round(compliant / len(controls) * 100, 1)
    detail = [
        ComplianceDetail(
            standard=c.standard.value, control_id=c.control_id, control_name=c.control_name,
            status=c.status.value, score=c.score, findings=c.findings,
        )
        for c in controls
    ]
    return score, detail


def _vuln_details(
    vulnerabilities: List[Vulnerability], findings_by_asset: Dict[int, List[Dict[str, Any]]]
) -> List[VulnDetail]:
    ssl_by_key = {
        (f.get("cve_id"), f.get("affected_component")): f.get("ssl_info")
        for f in _flatten(findings_by_asset)
        if f.get("ssl_info")
    }
    details = [
        VulnDetail(
            id=v.id, cve_id=v.cve_id, title=v.title, cvss_score=v.cvss_score,
            severity=v.severity.value, status=v.status.value, finding_type=v.finding_type,
            affected_component=v.affected_component, solution=v.solution,
            ssl_info=ssl_by_key.get((v.cve_id, v.affected_component)),
        )
        for v in vulnerabilities
    ]
    details.sort(key=lambda d: (SEVERITY_ORDER.get(d.severity, 9), -d.cvss_score))
    return details
