"""Datos de demostración.

Fuente única para el CLI (`python seed_data.py`) y el endpoint `POST /seed`, que
antes mantenían dos copias divergentes del mismo conjunto de datos.

Todo lo que se carga aquí queda marcado con `organization = DEMO_ORG` para poder
distinguirlo de los datos reales de un cliente.
"""

from sqlalchemy.orm import Session

from app.core.security import get_password_hash
from app.models.asset import Asset, AssetCriticality, AssetStatus, AssetType
from app.models.compliance import ComplianceControl, ComplianceStandard, ComplianceStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.user import User, UserRole
from app.models.vulnerability import FindingType, Severity, Vulnerability, VulnStatus

DEMO_ORG = "Demostración GuardIA"


def seed_database(db: Session) -> dict:
    """Carga los datos de demostración. No hace nada si ya hay usuarios."""
    if db.query(User).first():
        return {"seeded": False, "message": "La base ya contiene datos"}

    db.add_all([
        User(
            email="admin@guardia.gt", full_name="Administrador GuardIA",
            hashed_password=get_password_hash("Admin123!"),
            role=UserRole.ADMIN, is_active=True,
        ),
        User(
            email="analista@guardia.gt", full_name="Analista de Seguridad",
            hashed_password=get_password_hash("Analyst123!"),
            role=UserRole.ANALYST, is_active=True,
        ),
    ])
    db.commit()

    assets = [
        Asset(name="SRV-WEB-01", organization=DEMO_ORG, asset_type=AssetType.SERVER,
              ip_address="192.168.1.10", operating_system="Ubuntu 22.04",
              criticality=AssetCriticality.HIGH, status=AssetStatus.ONLINE,
              cpu_usage=34.0, ram_usage=67.0),
        Asset(name="SRV-DB-01", organization=DEMO_ORG, asset_type=AssetType.DATABASE,
              ip_address="192.168.1.20", operating_system="Rocky Linux 9",
              criticality=AssetCriticality.CRITICAL, status=AssetStatus.ONLINE,
              cpu_usage=22.0, ram_usage=58.0),
        Asset(name="FW-CORE-01", organization=DEMO_ORG, asset_type=AssetType.NETWORK,
              ip_address="192.168.1.1", operating_system="FortiGate 100F",
              criticality=AssetCriticality.CRITICAL, status=AssetStatus.ONLINE,
              cpu_usage=78.0, ram_usage=45.0),
        Asset(name="AWS-EKS-CLUSTER", organization=DEMO_ORG, asset_type=AssetType.CLOUD,
              operating_system="Kubernetes 1.29",
              criticality=AssetCriticality.HIGH, status=AssetStatus.ONLINE,
              cpu_usage=60.0, ram_usage=55.0),
        Asset(name="PC-CONTAB-03", organization=DEMO_ORG, asset_type=AssetType.ENDPOINT,
              ip_address="192.168.2.45", operating_system="Windows 11",
              criticality=AssetCriticality.MEDIUM, status=AssetStatus.ONLINE,
              cpu_usage=45.0, ram_usage=72.0),
        Asset(name="PORTAL-WEB", organization=DEMO_ORG, asset_type=AssetType.WEB_APP,
              ip_address="203.0.113.50", operating_system="Apache 2.4 / Ubuntu",
              criticality=AssetCriticality.HIGH, status=AssetStatus.ONLINE,
              cpu_usage=28.0, ram_usage=41.0),
    ]
    db.add_all(assets)
    db.commit()

    by_name = {a.name: a.id for a in assets}

    db.add_all([
        Vulnerability(cve_id="CVE-2021-41773", title="Path traversal y RCE en Apache HTTP Server",
                      description="Apache 2.4.49 permite recorrer rutas fuera del document root y, con mod_cgi activo, ejecutar código.",
                      cvss_score=9.8, severity=Severity.CRITICAL, status=VulnStatus.OPEN,
                      finding_type=FindingType.CVE.value, asset_id=by_name["SRV-WEB-01"],
                      affected_component="SRV-WEB-01:443", solution="Actualizar Apache a 2.4.51 o superior."),
        Vulnerability(cve_id="CVE-2023-27997", title="RCE preautenticación en FortiGate SSL-VPN",
                      description="Desbordamiento de heap en la interfaz SSL-VPN de FortiOS explotable sin credenciales.",
                      cvss_score=9.2, severity=Severity.HIGH, status=VulnStatus.IN_PROGRESS,
                      finding_type=FindingType.CVE.value, asset_id=by_name["FW-CORE-01"],
                      affected_component="FW-CORE-01:443", solution="Aplicar el parche de Fortinet para la rama en uso."),
        Vulnerability(cve_id="EXPOSED-POSTGRESQL-5432", title="PostgreSQL accesible en la red interna",
                      description="El puerto 5432 responde desde segmentos que no requieren acceso a la base de datos.",
                      cvss_score=7.5, severity=Severity.HIGH, status=VulnStatus.OPEN,
                      finding_type=FindingType.EXPOSURE.value, asset_id=by_name["SRV-DB-01"],
                      affected_component="SRV-DB-01:5432", solution="Restringir por cortafuegos a los servidores de aplicación."),
        Vulnerability(cve_id="HTTP-NO-TLS-80", title="Portal web sin TLS",
                      description="El portal atiende HTTP sin redirigir a HTTPS.",
                      cvss_score=6.5, severity=Severity.MEDIUM, status=VulnStatus.REMEDIATED,
                      finding_type=FindingType.EXPOSURE.value, asset_id=by_name["PORTAL-WEB"],
                      affected_component="PORTAL-WEB:80", solution="Redirección 301 a HTTPS aplicada."),
        Vulnerability(cve_id="BANNER-22", title="El servicio SSH revela su versión",
                      description="El saludo del servicio expone la versión exacta de OpenSSH.",
                      cvss_score=2.0, severity=Severity.LOW, status=VulnStatus.REMEDIATED,
                      finding_type=FindingType.EXPOSURE.value, asset_id=by_name["PC-CONTAB-03"],
                      affected_component="PC-CONTAB-03:22", solution="Banner suprimido en sshd_config."),
    ])

    db.add_all([
        Incident(title="Intentos de acceso no autorizado — SRV-DB-01", organization=DEMO_ORG,
                 description="Múltiples fallos de autenticación SSH desde una IP externa.",
                 severity=IncidentSeverity.CRITICAL, status=IncidentStatus.INVESTIGATING,
                 source_ip="185.203.116.44", affected_asset="SRV-DB-01"),
        Incident(title="Malware detectado — PC-CONTAB-03", organization=DEMO_ORG,
                 description="Troyano detectado en la estación de contabilidad.",
                 severity=IncidentSeverity.HIGH, status=IncidentStatus.INVESTIGATING,
                 affected_asset="PC-CONTAB-03"),
        Incident(title="DDoS mitigado — Portal Web", organization=DEMO_ORG,
                 description="Ataque volumétrico de 2.3 Gbps bloqueado por el WAF.",
                 severity=IncidentSeverity.HIGH, status=IncidentStatus.RESOLVED,
                 affected_asset="PORTAL-WEB", response_action="Mitigado automáticamente por el WAF"),
        Incident(title="Correos de phishing bloqueados", organization=DEMO_ORG,
                 description="Tres correos de phishing detenidos por la pasarela de correo.",
                 severity=IncidentSeverity.MEDIUM, status=IncidentStatus.RESOLVED,
                 response_action="Correos puestos en cuarentena"),
    ])

    db.add_all([
        ComplianceControl(standard=ComplianceStandard.ISO_27001, control_id="A.5.15",
                          control_name="Política de control de acceso",
                          description="Definir e implantar una política de control de acceso.",
                          status=ComplianceStatus.NON_COMPLIANT, score=40.0,
                          findings="La política no se actualiza desde 2024."),
        ComplianceControl(standard=ComplianceStandard.ISO_27001, control_id="A.8.9",
                          control_name="Gestión de la configuración",
                          description="Establecer y mantener configuraciones seguras.",
                          status=ComplianceStatus.PARTIAL, score=65.0),
        ComplianceControl(standard=ComplianceStandard.ISO_27001, control_id="A.8.8",
                          control_name="Gestión de vulnerabilidades técnicas",
                          description="Obtener información sobre vulnerabilidades y actuar sobre ellas.",
                          status=ComplianceStatus.COMPLIANT, score=85.0),
        ComplianceControl(standard=ComplianceStandard.NIST_CSF, control_id="ID.AM",
                          control_name="Gestión de activos",
                          description="Inventario y gestión de activos.",
                          status=ComplianceStatus.PARTIAL, score=60.0,
                          findings="El inventario está incompleto."),
        ComplianceControl(standard=ComplianceStandard.NIST_CSF, control_id="PR.AA",
                          control_name="Identidad, autenticación y control de acceso",
                          description="Gestión de identidades y permisos.",
                          status=ComplianceStatus.COMPLIANT, score=80.0),
        ComplianceControl(standard=ComplianceStandard.NIST_CSF, control_id="DE.CM",
                          control_name="Monitoreo continuo",
                          description="Vigilancia de la red y del entorno.",
                          status=ComplianceStatus.COMPLIANT, score=90.0),
        ComplianceControl(standard=ComplianceStandard.CIS_V8, control_id="CIS 1",
                          control_name="Inventario de activos empresariales",
                          description="Mantener un inventario de todos los activos.",
                          status=ComplianceStatus.NON_COMPLIANT, score=45.0,
                          findings="Falta el 30 % de los endpoints."),
        ComplianceControl(standard=ComplianceStandard.CIS_V8, control_id="CIS 4",
                          control_name="Configuración segura de activos y software",
                          description="Establecer y mantener configuraciones seguras.",
                          status=ComplianceStatus.PARTIAL, score=55.0),
        ComplianceControl(standard=ComplianceStandard.OWASP_TOP10, control_id="A01",
                          control_name="Pérdida de control de acceso",
                          description="Restringir el acceso a los usuarios autorizados.",
                          status=ComplianceStatus.COMPLIANT, score=88.0),
        ComplianceControl(standard=ComplianceStandard.OWASP_TOP10, control_id="A03",
                          control_name="Inyección",
                          description="Proteger frente a ataques de inyección.",
                          status=ComplianceStatus.COMPLIANT, score=82.0),
        ComplianceControl(standard=ComplianceStandard.MITRE_ATTACK, control_id="TA0001",
                          control_name="Acceso inicial",
                          description="Técnicas para obtener el acceso inicial.",
                          status=ComplianceStatus.PARTIAL, score=65.0),
        ComplianceControl(standard=ComplianceStandard.MITRE_ATTACK, control_id="TA0005",
                          control_name="Evasión de defensas",
                          description="Técnicas para evadir los controles de seguridad.",
                          status=ComplianceStatus.COMPLIANT, score=78.0),
    ])
    db.commit()

    return {"seeded": True, "message": "Datos de demostración cargados"}
