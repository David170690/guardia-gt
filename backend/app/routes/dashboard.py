"""Dashboard ejecutivo.

Todas las cifras salen de la base de datos. La versión anterior mezclaba métricas
calculadas con listas fijas ("Ransomware: 1", "Phishing: 3") que no correspondían a
ningún dato real y con un `recent_incidents` que siempre volvía vacío.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.asset import Asset, AssetStatus, AssetType
from app.models.compliance import ComplianceControl, ComplianceStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.vulnerability import Severity, Vulnerability, VulnStatus

router = APIRouter()

ACTIVE_INCIDENT_STATUSES = (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)

# Agrupación de tipos de activo en las categorías que muestra el gráfico.
ASSET_CATEGORIES = [
    ("Red", {AssetType.NETWORK}, "#ef4444"),
    ("Servidores", {AssetType.SERVER, AssetType.DATABASE}, "#f59e0b"),
    ("Aplicaciones", {AssetType.WEB_APP}, "#f59e0b"),
    ("Endpoints", {AssetType.ENDPOINT}, "#10b981"),
    ("Nube", {AssetType.CLOUD, AssetType.OTHER}, "#10b981"),
]

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

SEVERITY_LABEL = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "low",
}


@router.get("/")
def get_dashboard(organization: Optional[str] = None, db: Session = Depends(get_db)):
    asset_query = db.query(Asset)
    if organization:
        asset_query = asset_query.filter(Asset.organization == organization)
    assets = asset_query.all()
    asset_ids = [a.id for a in assets]
    asset_type_by_id = {a.id: a.asset_type for a in assets}

    vuln_query = db.query(Vulnerability)
    incident_query = db.query(Incident)
    if organization:
        vuln_query = vuln_query.filter(Vulnerability.asset_id.in_(asset_ids or [-1]))
        incident_query = incident_query.filter(Incident.organization == organization)

    vulns = vuln_query.all()
    incidents = incident_query.all()
    controls = db.query(ComplianceControl).all()

    open_vulns = [v for v in vulns if v.status == VulnStatus.OPEN]
    by_severity = {
        severity: sum(1 for v in open_vulns if v.severity == severity) for severity in Severity
    }

    active_incidents = [i for i in incidents if i.status in ACTIVE_INCIDENT_STATUSES]
    critical_incidents = sum(1 for i in active_incidents if i.severity == IncidentSeverity.CRITICAL)

    compliant = sum(1 for c in controls if c.status == ComplianceStatus.COMPLIANT)
    compliance_score = round(compliant / len(controls) * 100) if controls else 0

    risk_score = min(
        100,
        by_severity[Severity.CRITICAL] * 20
        + by_severity[Severity.HIGH] * 10
        + critical_incidents * 15,
    )
    if risk_score < 30:
        risk_level = "BAJO"
    elif risk_score < 60:
        risk_level = "MEDIO"
    else:
        risk_level = "ALTO"

    return {
        "organization": organization,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "vulnerabilities": {
            "label": "Vulnerabilidades abiertas",
            "value": str(len(open_vulns)),
            "change": f"{by_severity[Severity.CRITICAL]} críticas",
            "trend": "up" if by_severity[Severity.CRITICAL] else "stable",
        },
        "compliance": {
            "label": "Cumplimiento",
            "value": f"{compliance_score}%",
            "change": f"{compliant}/{len(controls)} controles" if controls else "sin controles cargados",
            "trend": "stable",
        },
        "assets": {
            "label": "Activos",
            "value": str(len(assets)),
            "change": f"{sum(1 for a in assets if a.status == AssetStatus.ONLINE)} en línea",
            "trend": "stable",
        },
        "incidents": {
            "label": "Incidentes activos",
            "value": str(len(active_incidents)),
            "change": f"{critical_incidents} críticos",
            "trend": "up" if critical_incidents else "stable",
        },
        "risk_categories": _risk_by_category(open_vulns, asset_type_by_id),
        "active_threats": _top_findings(open_vulns),
        "recent_incidents": [
            {
                "id": i.id,
                "title": i.title,
                "severity": i.severity.value,
                "status": i.status.value,
                "affected_asset": i.affected_asset,
                "detected_at": i.detected_at.isoformat() if i.detected_at else None,
            }
            for i in sorted(
                incidents,
                key=lambda x: x.detected_at or x.created_at,
                reverse=True,
            )[:5]
        ],
    }


def _risk_by_category(open_vulns: List[Vulnerability], asset_types: dict) -> List[dict]:
    """Puntúa cada categoría de activo por la severidad de sus hallazgos abiertos."""
    categories = []
    for name, types, color in ASSET_CATEGORIES:
        score = sum(
            SEVERITY_WEIGHT.get(v.severity, 0)
            for v in open_vulns
            if asset_types.get(v.asset_id) in types
        )
        categories.append({"category": name, "score": score, "color": color})
    return categories


def _top_findings(open_vulns: List[Vulnerability]) -> List[dict]:
    """Agrupa los hallazgos abiertos por título para mostrar los más recurrentes."""
    grouped: dict = {}
    for vuln in open_vulns:
        entry = grouped.setdefault(
            vuln.title,
            {"name": vuln.title, "severity": SEVERITY_LABEL.get(vuln.severity, "low"),
             "count": 0, "description": "", "weight": SEVERITY_WEIGHT.get(vuln.severity, 0)},
        )
        entry["count"] += 1

    for entry in grouped.values():
        entry["description"] = (
            f"{entry['count']} activo{'s' if entry['count'] != 1 else ''} afectado"
            f"{'s' if entry['count'] != 1 else ''}"
        )

    ranked = sorted(grouped.values(), key=lambda e: (-e["weight"], -e["count"]))[:5]
    for entry in ranked:
        entry.pop("weight", None)
    return ranked
