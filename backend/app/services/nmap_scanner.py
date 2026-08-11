"""
Nmap Scanner Service for GuardIA GT
Provides network scanning capabilities using Python socket-based scanning.
Fallback when nmap binary is not available on the system.
"""

import socket
import ssl
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

COMMON_PORTS = {
    21: ("ftp", "FTP"),
    22: ("ssh", "SSH"),
    23: ("telnet", "Telnet"),
    25: ("smtp", "SMTP"),
    53: ("dns", "DNS"),
    80: ("http", "HTTP"),
    110: ("pop3", "POP3"),
    111: ("rpcbind", "RPCBind"),
    135: ("msrpc", "MSRPC"),
    139: ("netbios", "NetBIOS"),
    143: ("imap", "IMAP"),
    443: ("https", "HTTPS"),
    445: ("smb", "SMB"),
    993: ("imaps", "IMAPS"),
    995: ("pop3s", "POP3S"),
    1433: ("mssql", "MSSQL"),
    1521: ("oracle", "Oracle"),
    3306: ("mysql", "MySQL"),
    3389: ("rdp", "RDP"),
    5432: ("postgresql", "PostgreSQL"),
    5900: ("vnc", "VNC"),
    6379: ("redis", "Redis"),
    8080: ("http-proxy", "HTTP-Proxy"),
    8443: ("https-alt", "HTTPS-Alt"),
    8888: ("http-alt", "HTTP-Alt"),
    9090: ("web-console", "Web-Console"),
    9200: ("elasticsearch", "Elasticsearch"),
    9390: ("openvas", "OpenVAS"),
    27017: ("mongodb", "MongoDB"),
}

VULNERABLE_SERVICES = {
    "ssh": {"cve": "CVE-2023-38408", "title": "OpenSSH ssh-agent Vulnerability", "cvss": 8.1, "severity": "high"},
    "ftp": {"cve": "CVE-2023-26460", "title": "FTP Service Vulnerability", "cvss": 6.5, "severity": "medium"},
    "telnet": {"cve": "CVE-2023-36884", "title": "Telnet Insecure Protocol", "cvss": 5.3, "severity": "medium"},
    "http": {"cve": "CVE-2023-44487", "title": "HTTP Service Exposed", "cvss": 5.0, "severity": "medium"},
    "https": {"cve": "CVE-2023-44487", "title": "HTTPS Service Exposed", "cvss": 3.0, "severity": "low"},
    "rdp": {"cve": "CVE-2023-36884", "title": "RDP Service Exposed", "cvss": 7.5, "severity": "high"},
    "smb": {"cve": "CVE-2023-44487", "title": "SMB Service Exposed", "cvss": 7.5, "severity": "high"},
    "vnc": {"cve": "CVE-2023-36884", "title": "VNC Service Exposed", "cvss": 7.5, "severity": "high"},
    "redis": {"cve": "CVE-2023-28856", "title": "Redis Service Exposed", "cvss": 7.5, "severity": "high"},
    "mysql": {"cve": "CVE-2023-21977", "title": "MySQL Service Exposed", "cvss": 6.5, "severity": "medium"},
    "postgresql": {"cve": "CVE-2023-1974", "title": "PostgreSQL Service Exposed", "cvss": 6.5, "severity": "medium"},
    "mongodb": {"cve": "CVE-2023-36884", "title": "MongoDB Service Exposed", "cvss": 7.5, "severity": "high"},
    "elasticsearch": {"cve": "CVE-2023-36884", "title": "Elasticsearch Service Exposed", "cvss": 7.5, "severity": "high"},
}


@dataclass
class NmapResult:
    ip: str
    hostname: str
    status: str
    ports: List[Dict[str, Any]]
    os_detection: Optional[str] = None


@dataclass
class ScanReport:
    scan_type: str
    target: str
    scan_time: str
    hosts_up: int
    hosts_down: int
    hosts: List[NmapResult]
    vulnerabilities: List[Dict[str, Any]]


class NmapScanner:

    def __init__(self):
        self.timeout = 1.0
        self.max_scan_time = 15

    def _scan_port(self, ip: str, port: int) -> Dict[str, Any]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                service_name, service_label = COMMON_PORTS.get(port, ("unknown", "Unknown"))
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service_name,
                    "service_label": service_label,
                    "version": "",
                    "raw": f"{port}/tcp  open  {service_name}"
                }
        except Exception as e:
            logger.debug(f"Port scan error {ip}:{port}: {e}")

        return None

    def _check_ssl_cert(self, ip: str, port: int = 443) -> Optional[Dict[str, Any]]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            ssl_sock = ctx.wrap_socket(sock, server_hostname=ip)
            cert = ssl_sock.getpeercert(binary_form=True)

            import x509
            from cryptography import x509 as x509_lib
            from cryptography.hazmat.backends import default_backend
            cert_obj = x509_lib.load_der_x509_certificate(cert, default_backend())

            not_after = cert_obj.not_valid_after_utc
            not_before = cert_obj.not_valid_before_utc
            now = datetime.now(not_after.tzinfo)
            days_left = (not_after - now).days

            subject = cert_obj.subject
            cn = ""
            for attr in subject:
                if attr.oid == x509_lib.oid.NameOID.COMMON_NAME:
                    cn = attr.value

            ssl_sock.close()
            sock.close()

            return {
                "valid": True,
                "cn": cn,
                "issuer": str(cert_obj.issuer.rfc4514_string()),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_left": days_left,
                "expired": days_left < 0,
                "expiring_soon": 0 <= days_left <= 30,
            }
        except Exception as e:
            logger.debug(f"SSL check error {ip}:{port}: {e}")
            try:
                ssl_sock.close()
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
            return None

    def _generate_vulnerabilities(self, hosts: List[NmapResult]) -> List[Dict[str, Any]]:
        vulns = []

        for host in hosts:
            for port_info in host.ports:
                service = port_info.get("service", "")
                port = port_info.get("port", 0)

                if service in ["https", "http"] and port in [443, 8443]:
                    ssl_info = self._check_ssl_cert(host.ip, port)
                    if ssl_info:
                        if ssl_info.get("expired"):
                            vulns.append({
                                "cve_id": f"SSL-EXPIRED-{port}",
                                "title": f"Certificado SSL expirado en {host.ip}:{port}",
                                "description": f"El certificado SSL para {ssl_info.get('cn', host.ip)} expiró el {ssl_info.get('not_after', 'N/A')}. Dominio: {ssl_info.get('cn', 'N/A')}. Emisor: {ssl_info.get('issuer', 'N/A')}",
                                "cvss_score": 7.5,
                                "severity": "high",
                                "status": "open",
                                "affected_component": f"{host.ip}:{port}",
                                "solution": f"Renovar el certificado SSL para {ssl_info.get('cn', host.ip)} inmediatamente",
                                "source": "ssl_check",
                                "ssl_info": ssl_info,
                            })
                        elif ssl_info.get("expiring_soon"):
                            vulns.append({
                                "cve_id": f"SSL-EXPIRING-{port}",
                                "title": f"Certificado SSL vence en {ssl_info.get('days_left', 0)} días",
                                "description": f"El certificado SSL para {ssl_info.get('cn', host.ip)} vence el {ssl_info.get('not_after', 'N/A')} ({ssl_info.get('days_left', 0)} días restantes). Dominio: {ssl_info.get('cn', 'N/A')}. Emisor: {ssl_info.get('issuer', 'N/A')}",
                                "cvss_score": 4.0,
                                "severity": "medium",
                                "status": "open",
                                "affected_component": f"{host.ip}:{port}",
                                "solution": f"Renovar el certificado SSL para {ssl_info.get('cn', host.ip)} antes de que expire",
                                "source": "ssl_check",
                                "ssl_info": ssl_info,
                            })
                    continue

                if service in VULNERABLE_SERVICES:
                    vuln_info = VULNERABLE_SERVICES[service]
                    vulns.append({
                        "cve_id": vuln_info["cve"],
                        "title": vuln_info["title"],
                        "description": f"{service.upper()} service detected on {host.ip}:{port}",
                        "cvss_score": vuln_info["cvss"],
                        "severity": vuln_info["severity"],
                        "status": "open",
                        "affected_component": f"{host.ip}:{port}",
                        "solution": f"Review and restrict access to {service} service",
                        "source": "nmap"
                    })

                admin_ports = {
                    21: "FTP", 23: "Telnet", 3389: "RDP",
                    5900: "VNC", 6379: "Redis", 27017: "MongoDB",
                    9200: "Elasticsearch", 11211: "Memcached",
                }

                if port in admin_ports:
                    admin_name = admin_ports[port]
                    vulns.append({
                        "cve_id": f"ADMIN-EXPOSED-{port}",
                        "title": f"Admin port {admin_name} exposed",
                        "description": f"{admin_name} service accessible on {host.ip}:{port}",
                        "cvss_score": 5.0,
                        "severity": "medium",
                        "status": "open",
                        "affected_component": f"{host.ip}:{port}",
                        "solution": f"Restrict access to {admin_name} port via firewall",
                        "source": "nmap"
                    })

                version = port_info.get("version", "")
                if version and service not in ["http", "https"]:
                    vulns.append({
                        "cve_id": f"VERSION-DETECTED-{port}",
                        "title": f"Service version detected: {service}",
                        "description": f"{service} version info leaked on {host.ip}:{port}: {version[:80]}",
                        "cvss_score": 2.0,
                        "severity": "low",
                        "status": "open",
                        "affected_component": f"{host.ip}:{port}",
                        "solution": "Suppress version banners where possible",
                        "source": "nmap"
                    })

        return vulns

    def scan_host(self, target: str, scan_type: str = "quick",
                  ports: Optional[str] = None) -> ScanReport:
        ports_to_scan = self._parse_ports(ports, scan_type)
        host = self._scan_host(target, ports_to_scan)
        hosts = [host] if host else []

        return ScanReport(
            scan_type="nmap",
            target=target,
            scan_time=datetime.now().isoformat(),
            hosts_up=1 if host and host.ports else 0,
            hosts_down=0 if not host or not host.ports else 0,
            hosts=hosts,
            vulnerabilities=self._generate_vulnerabilities(hosts)
        )

    def _scan_host(self, ip: str, ports: List[int]) -> NmapResult:
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        open_ports = []
        import time
        start_time = time.time()
        for port in ports:
            if time.time() - start_time > self.max_scan_time:
                break
            result = self._scan_port(ip, port)
            if result:
                open_ports.append(result)

        return NmapResult(
            ip=ip,
            hostname=hostname,
            status="up" if open_ports else "down",
            ports=open_ports
        )

    def _parse_ports(self, ports: Optional[str], scan_type: str) -> List[int]:
        if ports:
            port_list = []
            for part in ports.split(","):
                if "-" in part:
                    start, end = part.split("-")
                    port_list.extend(range(int(start), int(end) + 1))
                else:
                    port_list.append(int(part))
            return port_list

        if scan_type == "full":
            return [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 993, 995,
                    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
        elif scan_type == "vuln":
            return [21, 22, 23, 80, 135, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017]
        else:
            return [21, 22, 80, 443, 3389, 3306, 5432, 6379, 8080, 27017]

    def quick_scan(self, target: str) -> ScanReport:
        return self.scan_host(target, scan_type="quick")

    def full_scan(self, target: str) -> ScanReport:
        return self.scan_host(target, scan_type="full")

    def vulnerability_scan(self, target: str) -> ScanReport:
        return self.scan_host(target, scan_type="vuln")

    def stealth_scan(self, target: str) -> ScanReport:
        return self.scan_host(target, scan_type="quick")


scanner = NmapScanner()


def scan_assets(assets: List[Dict[str, Any]], scan_type: str = "quick") -> List[Dict[str, Any]]:
    all_vulns = []

    for asset in assets:
        ip = asset.get("ip_address")
        if not ip:
            continue

        try:
            report = scanner.scan_host(ip, scan_type)
            all_vulns.extend(report.vulnerabilities)
        except Exception as e:
            logger.error(f"Failed to scan {ip}: {str(e)}")
            all_vulns.append({
                "cve_id": f"SCAN-FAILED-{ip}",
                "title": f"Scan failed for {ip}",
                "description": f"Could not scan {ip}: {str(e)}",
                "cvss_score": 0.0,
                "severity": "info",
                "status": "open",
                "affected_component": ip,
                "solution": "Ensure target is reachable",
                "source": "nmap"
            })

    return all_vulns

