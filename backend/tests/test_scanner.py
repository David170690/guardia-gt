"""Pruebas del escáner (hallazgos F-03, F-04, F-08, F-09)."""

import socket
import threading
from contextlib import closing

import pytest

from app.services.nmap_scanner import (
    HostResult,
    NetworkScanner,
    PortResult,
    TargetNotAllowed,
    resolve_target,
)


# --------------------------------------------------------------- F-03: destinos


@pytest.mark.parametrize("target", [
    "127.0.0.1",
    "192.168.1.10",
    "10.0.0.5",
    "172.16.4.4",
    "169.254.169.254",   # metadatos del proveedor de nube
    "0.0.0.0",
])
def test_internal_targets_are_rejected(target):
    with pytest.raises(TargetNotAllowed):
        resolve_target(target)


def test_cidr_range_is_rejected():
    with pytest.raises(TargetNotAllowed):
        resolve_target("192.168.1.0/24")


def test_empty_target_is_rejected():
    with pytest.raises(TargetNotAllowed):
        resolve_target("   ")


def test_public_address_is_accepted():
    ip, hostname = resolve_target("8.8.8.8")
    assert ip == "8.8.8.8"
    assert hostname == ""


def test_private_targets_allowed_when_enabled(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config.settings, "SCAN_ALLOW_PRIVATE_TARGETS", True)
    ip, _ = resolve_target("127.0.0.1")
    assert ip == "127.0.0.1"


# ------------------------------------------------------- F-04: certificado TLS


def test_certificate_reader_imports_and_returns_none_on_failure():
    """La versión anterior tenía `import x509`, que lanzaba ModuleNotFoundError
    dentro de un try/except y hacía que el chequeo TLS siempre fallara en silencio."""
    scanner = NetworkScanner(timeout=0.2)
    # Puerto cerrado: debe devolver None por no conectar, no por un import roto.
    assert scanner.inspect_certificate("127.0.0.1", 1) is None


def test_cryptography_x509_is_importable():
    from app.services import nmap_scanner
    assert hasattr(nmap_scanner.x509, "load_der_x509_certificate")


def test_https_port_still_yields_a_finding_when_tls_fails(monkeypatch):
    """F-04 (efecto colateral): antes, un fallo de TLS en 443 hacía `continue` y el
    puerto no generaba ningún hallazgo."""
    scanner = NetworkScanner()
    monkeypatch.setattr(scanner, "inspect_certificate", lambda *a, **k: None)

    host = HostResult(target="ejemplo.gt", ip="203.0.113.10", hostname="ejemplo.gt", reachable=True,
                      ports=[PortResult(port=443, service="https", service_label="HTTPS")])
    findings = scanner.build_findings(host)

    assert findings, "un puerto 443 abierto siempre debe producir al menos un hallazgo"
    assert any(f["cve_id"].startswith("TLS-HANDSHAKE") for f in findings)


def test_expired_certificate_becomes_a_high_finding(monkeypatch):
    scanner = NetworkScanner()
    monkeypatch.setattr(scanner, "inspect_certificate", lambda *a, **k: {
        "valid": True, "cn": "ejemplo.gt", "issuer": "CN=Prueba",
        "not_before": "2024-01-01T00:00:00+00:00", "not_after": "2025-01-01T00:00:00+00:00",
        "days_left": -120, "expired": True, "expiring_soon": False,
    })

    host = HostResult(target="ejemplo.gt", ip="203.0.113.10", reachable=True,
                      ports=[PortResult(port=443, service="https", service_label="HTTPS")])
    findings = scanner.build_findings(host)

    expired = [f for f in findings if f["cve_id"] == "SSL-EXPIRED-443"]
    assert len(expired) == 1
    assert expired[0]["severity"] == "high"
    assert expired[0]["ssl_info"]["days_left"] == -120


# ------------------------------------------------------- F-08: sin CVEs falsos


def test_open_ssh_port_does_not_claim_a_cve():
    """Un puerto abierto no prueba una versión vulnerable: no debe emitirse un CVE."""
    scanner = NetworkScanner()
    host = HostResult(target="ejemplo.gt", ip="203.0.113.10", reachable=True,
                      ports=[PortResult(port=22, service="ssh", service_label="SSH")])
    findings = scanner.build_findings(host)

    assert findings
    for finding in findings:
        assert not finding["cve_id"].startswith("CVE-"), (
            f"el escáner afirmó {finding['cve_id']} solo por ver el puerto abierto"
        )
        assert finding["finding_type"] == "exposure"


def test_exposed_database_is_reported_as_exposure():
    scanner = NetworkScanner()
    host = HostResult(target="ejemplo.gt", ip="203.0.113.10", reachable=True,
                      ports=[PortResult(port=6379, service="redis", service_label="Redis")])
    findings = scanner.build_findings(host)

    redis = [f for f in findings if f["cve_id"] == "EXPOSED-REDIS-6379"]
    assert len(redis) == 1
    assert redis[0]["severity"] == "high"
    assert redis[0]["finding_type"] == "exposure"


def test_cleartext_protocol_is_reported():
    scanner = NetworkScanner()
    host = HostResult(target="ejemplo.gt", ip="203.0.113.10", reachable=True,
                      ports=[PortResult(port=23, service="telnet", service_label="Telnet")])
    findings = scanner.build_findings(host)
    assert any(f["cve_id"] == "CLEARTEXT-TELNET-23" for f in findings)


def test_http_without_https_is_flagged_as_missing_tls(monkeypatch):
    scanner = NetworkScanner()
    monkeypatch.setattr(scanner, "inspect_certificate", lambda *a, **k: None)

    host = HostResult(target="ejemplo.gt", ip="203.0.113.10", reachable=True,
                      ports=[PortResult(port=80, service="http", service_label="HTTP")])
    findings = scanner.build_findings(host)
    assert any(f["cve_id"] == "HTTP-NO-TLS-80" for f in findings)


def test_http_alongside_https_is_not_flagged_as_missing_tls(monkeypatch):
    scanner = NetworkScanner()
    monkeypatch.setattr(scanner, "inspect_certificate", lambda *a, **k: None)

    host = HostResult(target="ejemplo.gt", ip="203.0.113.10", reachable=True, ports=[
        PortResult(port=80, service="http", service_label="HTTP"),
        PortResult(port=443, service="https", service_label="HTTPS"),
    ])
    findings = scanner.build_findings(host)
    assert not any(f["cve_id"] == "HTTP-NO-TLS-80" for f in findings)


def test_finding_ids_fit_the_column():
    """La columna cve_id era VARCHAR(20) y `VERSION-DETECTED-8443` ya la desbordaba."""
    scanner = NetworkScanner()
    host = HostResult(target="ejemplo.gt", ip="203.0.113.10", reachable=True, ports=[
        PortResult(port=8443, service="https-alt", service_label="HTTPS-Alt"),
        PortResult(port=27017, service="mongodb", service_label="MongoDB"),
        PortResult(port=9200, service="elasticsearch", service_label="Elasticsearch"),
    ])
    for finding in scanner.build_findings(host):
        assert len(finding["cve_id"]) <= 64


# ------------------------------------------- comportamiento honesto sin hallazgos


def test_unreachable_host_reports_the_reason_instead_of_inventing_findings():
    scanner = NetworkScanner()
    host = HostResult(target="10.0.0.1", ip="", error="dirección privada")
    findings = scanner.build_findings(host)

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "reachability"
    assert findings[0]["severity"] == "info"
    assert not findings[0]["cve_id"].startswith("CVE-")


def test_host_without_open_ports_reports_zero_findings():
    scanner = NetworkScanner()
    host = HostResult(target="ejemplo.gt", ip="203.0.113.10", reachable=False, ports=[])
    findings = scanner.build_findings(host)

    assert len(findings) == 1
    assert findings[0]["cve_id"].startswith("NO-OPEN-PORTS")
    assert findings[0]["severity"] == "info"


# ---------------------------------------------------- F-09: escaneo en paralelo


def test_port_scan_detects_a_real_listening_socket(monkeypatch):
    """Levanta un socket local y comprueba que el escaneo paralelo lo encuentra."""
    from app.core import config
    monkeypatch.setattr(config.settings, "SCAN_ALLOW_PRIVATE_TARGETS", True)

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        stop = threading.Event()

        def accept_loop():
            server.settimeout(0.3)
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                    conn.close()
                except OSError:
                    continue

        thread = threading.Thread(target=accept_loop, daemon=True)
        thread.start()
        try:
            scanner = NetworkScanner(timeout=0.5)
            result = scanner.scan_host("127.0.0.1", ports=[port])
            assert result.reachable
            assert [p.port for p in result.ports] == [port]
        finally:
            stop.set()
            thread.join(timeout=2)


def test_scan_of_many_closed_ports_stays_within_budget(monkeypatch):
    """En serie, 20 puertos cerrados costaban 20 x timeout. En paralelo, ~1 timeout."""
    import time

    from app.core import config
    monkeypatch.setattr(config.settings, "SCAN_ALLOW_PRIVATE_TARGETS", True)

    scanner = NetworkScanner(timeout=0.4, max_workers=20, host_budget=10)
    ports = list(range(49200, 49220))

    started = time.monotonic()
    scanner.scan_host("127.0.0.1", ports=ports)
    elapsed = time.monotonic() - started

    assert elapsed < 3.0, f"el escaneo paralelo tardó {elapsed:.1f}s; parece secuencial"
