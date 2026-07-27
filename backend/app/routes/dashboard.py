from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.vulnerability import Vulnerability, Severity, VulnStatus
from app.models.asset import Asset, AssetStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.compliance import ComplianceControl, ComplianceStandard, ComplianceStatus

router = APIRouter()


@router.get("/")
def get_dashboard(db: Session = Depends(get_db)):
    vulns = db.query(Vulnerability).all()
    assets = db.query(Asset).all()
    incidents = db.query(Incident).all()
    controls = db.query(ComplianceControl).all()

    vuln_critical = sum(1 for v in vulns if v.severity == Severity.CRITICAL and v.status == VulnStatus.OPEN)
    vuln_high = sum(1 for v in vulns if v.severity == Severity.HIGH and v.status == VulnStatus.OPEN)
    vuln_medium = sum(1 for v in vulns if v.severity == Severity.MEDIUM and v.status == VulnStatus.OPEN)
    vuln_low = sum(1 for v in vulns if v.severity == Severity.LOW and v.status == VulnStatus.OPEN)

    active_incidents = sum(1 for i in incidents if i.status in [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING])
    critical_incidents = sum(1 for i in incidents if i.severity == IncidentSeverity.CRITICAL and i.status != IncidentStatus.CLOSED)

    total_controls = len(controls) if controls else 1
    compliant = sum(1 for c in controls if c.status == ComplianceStatus.COMPLIANT)
    compliance_score = int((compliant / total_controls) * 100) if controls else 0

    risk_score = min(100, vuln_critical * 20 + vuln_high * 10 + critical_incidents * 15)
    if risk_score < 30:
        risk_level = "BAJO"
    elif risk_score < 60:
        risk_level = "MEDIO"
    else:
        risk_level = "ALTO"

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "vulnerabilities": {
            "label": "Vulnerabilidades",
            "value": str(len([v for v in vulns if v.status == VulnStatus.OPEN])),
            "change": f"{vuln_critical} críticas",
            "trend": "up" if vuln_critical > 0 else "down",
        },
        "compliance": {
            "label": "Cumplimiento",
            "value": f"{compliance_score}%",
            "change": f"{compliant}/{total_controls} controles",
            "trend": "up",
        },
        "assets": {
            "label": "Activos",
            "value": str(len(assets)),
            "change": f"{sum(1 for a in assets if a.status == AssetStatus.ONLINE)} en línea",
            "trend": "stable",
        },
        "incidents": {
            "label": "Incidentes",
            "value": str(active_incidents),
            "change": f"{critical_incidents} críticos",
            "trend": "up" if critical_incidents > 0 else "down",
        },
        "risk_categories": [
            {"category": "Red", "score": vuln_high + 5, "color": "#ef4444"},
            {"category": "Apps", "score": vuln_medium + 3, "color": "#f59e0b"},
            {"category": "Endpoint", "score": vuln_low + 8, "color": "#f59e0b"},
            {"category": "Cloud", "score": 2, "color": "#10b981"},
            {"category": "Correo", "score": 4, "color": "#10b981"},
        ],
        "active_threats": [
            {"name": "Ransomware", "severity": "critical", "count": 1, "description": "Detección en red"},
            {"name": "Phishing", "severity": "high", "count": 3, "description": "3 campañas activas"},
            {"name": "DDoS", "severity": "high", "count": 2, "description": "Intentos bloqueados"},
            {"name": "Fuga datos", "severity": "low", "count": 1, "description": "Monitoreo activo"},
        ],
        "recent_incidents": [],
    }
