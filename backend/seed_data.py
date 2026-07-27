from sqlalchemy.orm import Session
from app.core.database import engine, SessionLocal
from app.core.security import get_password_hash
from app.models.user import User, UserRole
from app.models.vulnerability import Vulnerability, Severity, VulnStatus
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.compliance import ComplianceControl, ComplianceStandard, ComplianceStatus


def seed_database():
    db = SessionLocal()
    try:
        if db.query(User).first():
            print("Database already seeded.")
            return

        admin = User(
            email="admin@guardia.gt",
            full_name="Administrador GuardIA",
            hashed_password=get_password_hash("Admin123!"),
            role=UserRole.ADMIN,
            is_active=True,
        )
        analyst = User(
            email="analista@guardia.gt",
            full_name="Analista de Seguridad",
            hashed_password=get_password_hash("Analyst123!"),
            role=UserRole.ANALYST,
            is_active=True,
        )
        db.add_all([admin, analyst])
        db.commit()

        assets_data = [
            Asset(name="SRV-WEB-01", asset_type=AssetType.SERVER, ip_address="192.168.1.10", operating_system="Ubuntu 22.04", criticality=AssetCriticality.HIGH, status=AssetStatus.ONLINE, cpu_usage=34.0, ram_usage=67.0),
            Asset(name="SRV-DB-01", asset_type=AssetType.DATABASE, ip_address="192.168.1.20", operating_system="Rocky Linux 9", criticality=AssetCriticality.CRITICAL, status=AssetStatus.ONLINE, cpu_usage=22.0, ram_usage=58.0),
            Asset(name="FW-CORE-01", asset_type=AssetType.NETWORK, ip_address="192.168.1.1", operating_system="FortiGate 100F", criticality=AssetCriticality.CRITICAL, status=AssetStatus.ONLINE, cpu_usage=78.0, ram_usage=45.0),
            Asset(name="AWS-EKS-CLUSTER", asset_type=AssetType.CLOUD, ip_address="10.0.0.0/16", operating_system="Kubernetes 1.29", criticality=AssetCriticality.HIGH, status=AssetStatus.ONLINE, cpu_usage=60.0, ram_usage=55.0),
            Asset(name="PC-CONTAB-03", asset_type=AssetType.ENDPOINT, ip_address="192.168.2.45", operating_system="Windows 11", criticality=AssetCriticality.MEDIUM, status=AssetStatus.ONLINE, cpu_usage=45.0, ram_usage=72.0),
            Asset(name="PORTAL-WEB", asset_type=AssetType.WEB_APP, ip_address="203.0.113.50", operating_system="Apache 2.4 / Ubuntu", criticality=AssetCriticality.HIGH, status=AssetStatus.ONLINE, cpu_usage=28.0, ram_usage=41.0),
        ]
        db.add_all(assets_data)
        db.commit()

        vulns_data = [
            Vulnerability(cve_id="CVE-2026-1234", title="Remote Code Execution in Apache", description="Critical RCE vulnerability in Apache HTTP Server", cvss_score=9.8, severity=Severity.CRITICAL, status=VulnStatus.OPEN, affected_component="SRV-WEB-01", solution="Update Apache to latest version"),
            Vulnerability(cve_id="CVE-2026-0567", title="FortiGate Buffer Overflow", description="Buffer overflow in FortiGate firewall firmware", cvss_score=8.5, severity=Severity.HIGH, status=VulnStatus.IN_PROGRESS, affected_component="FW-CORE-01", solution="Apply vendor patch"),
            Vulnerability(cve_id="CVE-2026-0891", title="PostgreSQL Privilege Escalation", description="Local privilege escalation in PostgreSQL", cvss_score=7.2, severity=Severity.HIGH, status=VulnStatus.OPEN, affected_component="SRV-DB-01", solution="Update PostgreSQL"),
            Vulnerability(cve_id="CVE-2026-0234", title="XSS in Portal Web", description="Reflected XSS vulnerability in web portal", cvss_score=5.4, severity=Severity.MEDIUM, status=VulnStatus.REMEDIATED, affected_component="PORTAL-WEB", solution="Input sanitization applied"),
            Vulnerability(cve_id="CVE-2026-1100", title="Outdated Exchange Server", description="Exchange Server with known vulnerabilities", cvss_score=4.1, severity=Severity.LOW, status=VulnStatus.REMEDIATED, affected_component="Exchange", solution="Server updated"),
        ]
        db.add_all(vulns_data)
        db.commit()

        incidents_data = [
            Incident(title="Unauthorized access attempt — SRV-DB-01", description="Multiple failed SSH login attempts from external IP", severity=IncidentSeverity.CRITICAL, status=IncidentStatus.INVESTIGATING, source_ip="185.x.x.x", affected_asset="SRV-DB-01"),
            Incident(title="Malware detected — PC-CONTAB-03", description="Trojan detected in accounting workstation", severity=IncidentSeverity.HIGH, status=IncidentStatus.INVESTIGATING, affected_asset="PC-CONTAB-03"),
            Incident(title="DDoS mitigated — Portal Web", description="DDoS attack blocked by WAF, 2.3Gbps volume", severity=IncidentSeverity.HIGH, status=IncidentStatus.RESOLVED, affected_asset="PORTAL-WEB", response_action="WAF auto-mitigated"),
            Incident(title="Phishing emails blocked", description="3 phishing emails blocked by email security gateway", severity=IncidentSeverity.MEDIUM, status=IncidentStatus.RESOLVED, response_action="Emails quarantined"),
        ]
        db.add_all(incidents_data)
        db.commit()

        controls_data = [
            ComplianceControl(standard=ComplianceStandard.ISO_27001, control_id="A.5.15", control_name="Access Control Policy", description="Define and implement access control policy", status=ComplianceStatus.NON_COMPLIANT, score=40.0, findings="Policy not updated since 2024"),
            ComplianceControl(standard=ComplianceStandard.ISO_27001, control_id="A.9.1", control_name="Access Control", description="Business requirements of access control", status=ComplianceStatus.PARTIAL, score=65.0),
            ComplianceControl(standard=ComplianceStandard.ISO_27001, control_id="A.12.6", control_name="Technical Vulnerability Management", description="Manage technical vulnerabilities promptly", status=ComplianceStatus.COMPLIANT, score=85.0),
            ComplianceControl(standard=ComplianceStandard.NIST_CSF, control_id="ID.AM", control_name="Asset Management", description="Asset inventory and management", status=ComplianceStatus.PARTIAL, score=60.0, findings="Inventory incomplete"),
            ComplianceControl(standard=ComplianceStandard.NIST_CSF, control_id="PR.AC", control_name="Access Control", description="Access rights and principles", status=ComplianceStatus.COMPLIANT, score=80.0),
            ComplianceControl(standard=ComplianceStandard.NIST_CSF, control_id="DE.CM", control_name="Continuous Monitoring", description="Network and environment monitoring", status=ComplianceStatus.COMPLIANT, score=90.0),
            ComplianceControl(standard=ComplianceStandard.CIS_V8, control_id="CIS 1", control_name="Inventory of Enterprise Assets", description="Maintain inventory of all enterprise assets", status=ComplianceStatus.NON_COMPLIANT, score=45.0, findings="Missing 30% of endpoints"),
            ComplianceControl(standard=ComplianceStandard.CIS_V8, control_id="CIS 2", control_name="Inventory of Software Assets", description="Maintain inventory of software", status=ComplianceStatus.PARTIAL, score=55.0),
            ComplianceControl(standard=ComplianceStandard.OWASP_TOP10, control_id="A01", control_name="Broken Access Control", description="Restrict access to authorized users", status=ComplianceStatus.COMPLIANT, score=88.0),
            ComplianceControl(standard=ComplianceStandard.OWASP_TOP10, control_id="A03", control_name="Injection", description="Protect against injection attacks", status=ComplianceStatus.COMPLIANT, score=82.0),
            ComplianceControl(standard=ComplianceStandard.MITRE_ATTACK, control_id="TA0001", control_name="Initial Access", description="Techniques for gaining initial access", status=ComplianceStatus.PARTIAL, score=65.0),
            ComplianceControl(standard=ComplianceStandard.MITRE_ATTACK, control_id="TA0005", control_name="Defense Evasion", description="Techniques for evading defenses", status=ComplianceStatus.COMPLIANT, score=78.0),
        ]
        db.add_all(controls_data)
        db.commit()

        print("Database seeded successfully!")

    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
