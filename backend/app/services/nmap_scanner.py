"""Escáner de red de GuardIA GT.

Descubre puertos TCP abiertos con sockets de Python (sin depender del binario de
nmap, que no existe en el entorno de Render) y traduce lo observado a hallazgos.

Dos reglas gobiernan este módulo:

1. **No se inventan CVEs.** Un puerto abierto prueba que hay un servicio escuchando,
   no que sea vulnerable a un CVE concreto. Esas observaciones se emiten como
   `exposure`. Un CVE solo se afirma cuando hay evidencia (hoy: la fecha de un
   certificado TLS leído del servidor).
2. **No se escanea hacia dentro.** Los destinos privados, de loopback y reservados se
   rechazan salvo que se habiliten de forma explícita, para que la API no sirva de
   sonda hacia la red interna del proveedor.
"""

import ipaddress
import logging
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app.core.config import settings
from app.services import cve_lookup

logger = logging.getLogger(__name__)

COMMON_PORTS: Dict[int, Tuple[str, str]] = {
    21: ("ftp", "FTP"),
    22: ("ssh", "SSH"),
    23: ("telnet", "Telnet"),
    25: ("smtp", "SMTP"),
    53: ("dns", "DNS"),
    80: ("http", "HTTP"),
    110: ("pop3", "POP3"),
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
    9200: ("elasticsearch", "Elasticsearch"),
    27017: ("mongodb", "MongoDB"),
}

PORT_PROFILES = {
    "quick": [21, 22, 23, 80, 443, 3306, 3389, 5432, 6379, 8080, 27017],
    "vuln": [21, 22, 23, 80, 135, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017],
    "full": sorted(COMMON_PORTS.keys()),
}

# Servicios que transmiten credenciales en claro. Es un defecto del protocolo,
# no de una versión, así que se puede afirmar sin detectar versión.
CLEARTEXT_SERVICES = {
    "telnet": ("Telnet transmite credenciales sin cifrar", 7.5, "high"),
    "ftp": ("FTP transmite credenciales sin cifrar", 6.5, "medium"),
    "pop3": ("POP3 sin cifrado en tránsito", 5.3, "medium"),
    "imap": ("IMAP sin cifrado en tránsito", 5.3, "medium"),
}

# Servicios que no deberían ser alcanzables desde fuera del perímetro.
RESTRICTED_SERVICES = {
    "redis": ("Redis", 8.6, "high"),
    "mongodb": ("MongoDB", 8.6, "high"),
    "elasticsearch": ("Elasticsearch", 8.1, "high"),
    "mssql": ("Microsoft SQL Server", 7.5, "high"),
    "mysql": ("MySQL", 7.5, "high"),
    "postgresql": ("PostgreSQL", 7.5, "high"),
    "oracle": ("Oracle Database", 7.5, "high"),
    "rdp": ("Escritorio remoto (RDP)", 7.8, "high"),
    "vnc": ("Escritorio remoto (VNC)", 7.8, "high"),
    "smb": ("Comparticiones SMB", 7.5, "high"),
    "netbios": ("NetBIOS", 5.3, "medium"),
    "msrpc": ("RPC de Windows", 5.3, "medium"),
    "ssh": ("Acceso SSH", 4.3, "medium"),
}


@dataclass
class PortResult:
    port: int
    service: str
    service_label: str
    protocol: str = "tcp"
    state: str = "open"
    banner: str = ""


@dataclass
class HostResult:
    target: str
    ip: str
    hostname: str = ""
    reachable: bool = False
    ports: List[PortResult] = field(default_factory=list)
    error: Optional[str] = None
    truncated: bool = False


@dataclass
class ScanReport:
    scan_type: str
    target: str
    scan_time: str
    hosts: List[HostResult]
    findings: List[Dict[str, Any]]

    @property
    def hosts_up(self) -> int:
        return sum(1 for h in self.hosts if h.reachable)

    @property
    def hosts_down(self) -> int:
        return sum(1 for h in self.hosts if not h.reachable)


class TargetNotAllowed(ValueError):
    """El destino solicitado no puede escanearse desde este servidor."""


def resolve_target(target: str) -> Tuple[str, str]:
    """Devuelve (ip, hostname) y valida que el destino sea escaneable.

    La validación se hace sobre la IP *resuelta*, no sobre el texto que llegó, para
    que un nombre de dominio no pueda apuntar a una dirección interna.
    """
    target = (target or "").strip()
    if not target:
        raise TargetNotAllowed("Destino vacío")

    if "/" in target:
        raise TargetNotAllowed(
            f"'{target}' es un rango de red. Indica direcciones o nombres individuales."
        )

    hostname = ""
    try:
        ip_obj = ipaddress.ip_address(target)
        ip = str(ip_obj)
    except ValueError:
        try:
            ip = socket.gethostbyname(target)
            hostname = target
            ip_obj = ipaddress.ip_address(ip)
        except (socket.gaierror, socket.herror) as exc:
            raise TargetNotAllowed(f"No se pudo resolver '{target}': {exc}") from exc

    if not settings.SCAN_ALLOW_PRIVATE_TARGETS:
        if ip_obj.is_loopback:
            raise TargetNotAllowed(f"'{target}' es una dirección de loopback")
        if ip_obj.is_link_local:
            raise TargetNotAllowed(
                f"'{target}' es link-local (incluye los endpoints de metadatos del proveedor)"
            )
        if ip_obj.is_private:
            raise TargetNotAllowed(
                f"'{target}' es una dirección privada, inalcanzable desde el servidor. "
                "Habilita SCAN_ALLOW_PRIVATE_TARGETS solo en una instalación dentro de la red del cliente."
            )
        if ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified:
            raise TargetNotAllowed(f"'{target}' no es una dirección unicast enrutable")

    return ip, hostname


class NetworkScanner:
    def __init__(
        self,
        timeout: Optional[float] = None,
        max_workers: Optional[int] = None,
        host_budget: Optional[float] = None,
    ):
        self.timeout = timeout if timeout is not None else settings.SCAN_PORT_TIMEOUT
        self.max_workers = max_workers if max_workers is not None else settings.SCAN_MAX_WORKERS
        self.host_budget = host_budget if host_budget is not None else settings.SCAN_HOST_BUDGET_SECONDS

    # ---------------------------------------------------------------- puertos

    def _probe_port(self, ip: str, port: int) -> Optional[PortResult]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            if sock.connect_ex((ip, port)) != 0:
                return None
            service, label = COMMON_PORTS.get(port, ("unknown", "Desconocido"))
            return PortResult(port=port, service=service, service_label=label,
                              banner=self._read_banner(sock, service))
        except OSError as exc:
            logger.debug("Sondeo fallido %s:%s — %s", ip, port, exc)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _read_banner(self, sock: socket.socket, service: str) -> str:
        """Lee el saludo del servicio, cuando lo hay. Es la única evidencia de versión
        que obtiene este escáner, y se reporta como divulgación de información."""
        if service in ("https", "https-alt", "unknown"):
            return ""
        try:
            sock.settimeout(min(self.timeout, 1.0))
            if service in ("http", "http-proxy", "http-alt"):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            raw = sock.recv(256)
            return raw.decode("utf-8", errors="replace").strip().replace("\r\n", " ")[:180]
        except OSError:
            return ""

    def scan_host(self, target: str, scan_type: str = "quick",
                  ports: Optional[List[int]] = None) -> HostResult:
        try:
            ip, hostname = resolve_target(target)
        except TargetNotAllowed as exc:
            return HostResult(target=target, ip="", error=str(exc))

        if not hostname:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except OSError:
                hostname = ""

        port_list = ports or PORT_PROFILES.get(scan_type, PORT_PROFILES["quick"])
        result = HostResult(target=target, ip=ip, hostname=hostname)
        deadline = time.monotonic() + self.host_budget

        # En paralelo: el coste de un host pasa de (nº puertos x timeout) a
        # aproximadamente un solo timeout.
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(port_list))) as pool:
            futures = {pool.submit(self._probe_port, ip, p): p for p in port_list}
            for future in as_completed(futures):
                if time.monotonic() > deadline:
                    result.truncated = True
                    for pending in futures:
                        pending.cancel()
                    break
                try:
                    port_result = future.result()
                except Exception as exc:  # pragma: no cover - defensivo
                    logger.debug("Error sondeando %s: %s", futures[future], exc)
                    continue
                if port_result:
                    result.ports.append(port_result)

        result.ports.sort(key=lambda p: p.port)
        result.reachable = bool(result.ports)
        return result

    # ------------------------------------------------------------------- TLS

    def inspect_certificate(self, ip: str, port: int = 443,
                            server_hostname: str = "") -> Optional[Dict[str, Any]]:
        """Lee el certificado TLS que presenta el servidor.

        Devuelve `None` si no se pudo establecer el handshake o leer el certificado.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(max(self.timeout, 2.0))
        tls_sock = None
        try:
            sock.connect((ip, port))
            tls_sock = ctx.wrap_socket(sock, server_hostname=server_hostname or ip)
            der = tls_sock.getpeercert(binary_form=True)
            if not der:
                return None

            cert = x509.load_der_x509_certificate(der, default_backend())

            # `not_valid_after_utc` existe desde cryptography 42; el atributo anterior
            # devuelve un datetime ingenuo en UTC.
            not_after = getattr(cert, "not_valid_after_utc", None)
            not_before = getattr(cert, "not_valid_before_utc", None)
            if not_after is None:
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            if not_before is None:
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

            days_left = (not_after - datetime.now(timezone.utc)).days

            common_name = ""
            for attribute in cert.subject:
                if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                    common_name = str(attribute.value)
                    break

            return {
                "valid": True,
                "cn": common_name,
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_left": days_left,
                "expired": days_left < 0,
                "expiring_soon": 0 <= days_left <= 30,
            }
        except (OSError, ssl.SSLError, ValueError) as exc:
            logger.debug("No se pudo leer el certificado de %s:%s — %s", ip, port, exc)
            return None
        finally:
            for closable in (tls_sock, sock):
                try:
                    if closable:
                        closable.close()
                except OSError:
                    pass

    # -------------------------------------------------------------- hallazgos

    def build_findings(self, host: HostResult) -> List[Dict[str, Any]]:
        if host.error:
            return [{
                "cve_id": f"UNREACHABLE-{host.target}"[:64],
                "title": f"No se pudo escanear {host.target}",
                "description": host.error,
                "cvss_score": 0.0,
                "severity": "info",
                "finding_type": "reachability",
                "affected_component": host.target,
                "solution": "Verifica la dirección o ejecuta el escaneo desde dentro de la red del cliente.",
                "source": "scanner",
            }]

        if not host.reachable:
            return [{
                "cve_id": f"NO-OPEN-PORTS-{host.ip}"[:64],
                "title": f"Sin puertos abiertos detectados en {host.ip}",
                "description": (
                    f"Se sondearon los puertos del perfil sin obtener respuesta en {host.ip}. "
                    "El host puede estar apagado, filtrado por un cortafuegos o sin servicios expuestos."
                ),
                "cvss_score": 0.0,
                "severity": "info",
                "finding_type": "reachability",
                "affected_component": host.ip,
                "solution": "Ninguna acción requerida si es el comportamiento esperado.",
                "source": "scanner",
            }]

        findings: List[Dict[str, Any]] = []
        label = host.hostname or host.ip
        has_https = any(p.service in ("https", "https-alt") for p in host.ports)

        for port_result in host.ports:
            component = f"{label}:{port_result.port}"
            service = port_result.service

            # --- TLS: el único punto donde hay evidencia dura de un defecto -------
            if service in ("https", "https-alt"):
                cert = self.inspect_certificate(host.ip, port_result.port, host.hostname)
                if cert and cert["expired"]:
                    findings.append({
                        "cve_id": f"SSL-EXPIRED-{port_result.port}",
                        "title": f"Certificado TLS expirado en {component}",
                        "description": (
                            f"El certificado de {cert['cn'] or label} expiró el {cert['not_after']}. "
                            f"Emisor: {cert['issuer']}."
                        ),
                        "cvss_score": 7.5,
                        "severity": "high",
                        "finding_type": "ssl",
                        "affected_component": component,
                        "solution": f"Renueva el certificado de {cert['cn'] or label} de inmediato.",
                        "source": "scanner",
                        "ssl_info": cert,
                    })
                elif cert and cert["expiring_soon"]:
                    findings.append({
                        "cve_id": f"SSL-EXPIRING-{port_result.port}",
                        "title": f"Certificado TLS vence en {cert['days_left']} días",
                        "description": (
                            f"El certificado de {cert['cn'] or label} vence el {cert['not_after']}. "
                            f"Emisor: {cert['issuer']}."
                        ),
                        "cvss_score": 4.0,
                        "severity": "medium",
                        "finding_type": "ssl",
                        "affected_component": component,
                        "solution": "Programa la renovación antes de la fecha de vencimiento.",
                        "source": "scanner",
                        "ssl_info": cert,
                    })
                elif cert:
                    findings.append({
                        "cve_id": f"SSL-OK-{port_result.port}",
                        "title": f"Certificado TLS válido en {component}",
                        "description": (
                            f"Certificado de {cert['cn'] or label} vigente hasta {cert['not_after']} "
                            f"({cert['days_left']} días). Emisor: {cert['issuer']}."
                        ),
                        "cvss_score": 0.0,
                        "severity": "info",
                        "finding_type": "ssl",
                        "affected_component": component,
                        "solution": "Ninguna acción requerida.",
                        "source": "scanner",
                        "ssl_info": cert,
                    })
                else:
                    findings.append({
                        "cve_id": f"TLS-HANDSHAKE-{port_result.port}",
                        "title": f"No se pudo negociar TLS en {component}",
                        "description": (
                            "El puerto acepta conexiones pero el handshake TLS no se completó. "
                            "Puede indicar una configuración incorrecta o un protocolo obsoleto."
                        ),
                        "cvss_score": 5.3,
                        "severity": "medium",
                        "finding_type": "exposure",
                        "affected_component": component,
                        "solution": "Revisa la configuración TLS del servicio y los protocolos habilitados.",
                        "source": "scanner",
                    })
                continue

            # --- Protocolos en claro ---------------------------------------------
            if service in CLEARTEXT_SERVICES:
                reason, score, severity = CLEARTEXT_SERVICES[service]
                findings.append({
                    "cve_id": f"CLEARTEXT-{service.upper()}-{port_result.port}"[:64],
                    "title": f"{reason} ({component})",
                    "description": (
                        f"El servicio {port_result.service_label} responde en {component} y no cifra "
                        "el tráfico, por lo que credenciales y datos viajan legibles en la red."
                    ),
                    "cvss_score": score,
                    "severity": severity,
                    "finding_type": "exposure",
                    "affected_component": component,
                    "solution": f"Sustituye {port_result.service_label} por su equivalente cifrado y cierra el puerto.",
                    "source": "scanner",
                })
                continue

            # --- HTTP sin equivalente cifrado ------------------------------------
            if service in ("http", "http-proxy", "http-alt"):
                if not has_https:
                    findings.append({
                        "cve_id": f"HTTP-NO-TLS-{port_result.port}",
                        "title": f"Servicio web sin TLS en {component}",
                        "description": (
                            f"{component} atiende HTTP sin que se detecte un equivalente HTTPS. "
                            "El tráfico, incluidas las credenciales de sesión, viaja sin cifrar."
                        ),
                        "cvss_score": 6.5,
                        "severity": "medium",
                        "finding_type": "exposure",
                        "affected_component": component,
                        "solution": "Publica el servicio sobre HTTPS y redirige el puerto 80.",
                        "source": "scanner",
                    })

            # --- Servicios que no deberían estar expuestos ------------------------
            elif service in RESTRICTED_SERVICES:
                label_service, score, severity = RESTRICTED_SERVICES[service]
                findings.append({
                    "cve_id": f"EXPOSED-{service.upper()}-{port_result.port}"[:64],
                    "title": f"{label_service} accesible en {component}",
                    "description": (
                        f"{label_service} responde en {component}. Este escaneo confirma que el "
                        "puerto es alcanzable; no comprueba la versión ni la configuración del servicio."
                    ),
                    "cvss_score": score,
                    "severity": severity,
                    "finding_type": "exposure",
                    "affected_component": component,
                    "solution": (
                        f"Restringe el acceso a {label_service} por cortafuegos o VPN y "
                        "limítalo a las direcciones que lo necesiten."
                    ),
                    "source": "scanner",
                })

            # --- Divulgación de versión ------------------------------------------
            if port_result.banner:
                findings.append({
                    "cve_id": f"BANNER-{port_result.port}",
                    "title": f"El servicio revela su versión en {component}",
                    "description": f"Respuesta del servicio: {port_result.banner}",
                    "cvss_score": 2.0,
                    "severity": "low",
                    "finding_type": "exposure",
                    "affected_component": component,
                    "solution": "Suprime los banners de versión en la configuración del servicio.",
                    "source": "scanner",
                })
                # Si el banner revela versión y la confirmación está activada,
                # consulta el NVD por CVEs reales. Best-effort: sin conexión o
                # desactivado, devuelve una lista vacía y no altera el escaneo.
                findings.extend(cve_lookup.confirm_cves(port_result.banner, component))

        if host.truncated:
            findings.append({
                "cve_id": f"SCAN-PARTIAL-{host.ip}"[:64],
                "title": f"Escaneo incompleto en {host.ip}",
                "description": (
                    "Se agotó el presupuesto de tiempo del host antes de sondear todos los puertos. "
                    "Los resultados son parciales."
                ),
                "cvss_score": 0.0,
                "severity": "info",
                "finding_type": "reachability",
                "affected_component": host.ip,
                "solution": "Vuelve a ejecutar el diagnóstico con menos activos o amplía SCAN_HOST_BUDGET_SECONDS.",
                "source": "scanner",
            })

        return findings

    # ---------------------------------------------------------------- fachada

    def scan(self, target: str, scan_type: str = "quick") -> ScanReport:
        host = self.scan_host(target, scan_type)
        return ScanReport(
            scan_type=scan_type,
            target=target,
            scan_time=datetime.now(timezone.utc).isoformat(),
            hosts=[host],
            findings=self.build_findings(host),
        )


scanner = NetworkScanner()

# Alias histórico: el módulo se llamaba NmapScanner cuando dependía del binario.
NmapScanner = NetworkScanner


def scan_assets(assets: List[Dict[str, Any]], scan_type: str = "quick") -> List[Dict[str, Any]]:
    """Escanea una lista de activos y devuelve todos los hallazgos."""
    findings: List[Dict[str, Any]] = []
    for asset in assets:
        target = asset.get("ip_address")
        if not target:
            continue
        report = scanner.scan(target, scan_type)
        for finding in report.findings:
            finding.setdefault("asset_name", asset.get("name"))
            findings.append(finding)
    return findings
