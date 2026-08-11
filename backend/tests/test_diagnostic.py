"""Pruebas del motor de diagnóstico (hallazgos F-05, F-06)."""

import pytest

from conftest import auth_headers

from app.models.asset import Asset
from app.models.incident import Incident
from app.models.vulnerability import Vulnerability


@pytest.fixture()
def stub_scan(monkeypatch):
    """Sustituye el escaneo de red por hallazgos deterministas."""
    from app.routes import diagnostic

    def fake_scan(assets, scan_type):
        results = {}
        for index, asset in enumerate(assets):
            if not asset.ip_address:
                results[asset.id] = []
                continue
            results[asset.id] = [
                {
                    # El mismo identificador en varios activos: antes esto violaba
                    # la restricción `unique` de cve_id y devolvía un 500.
                    "cve_id": "EXPOSED-REDIS-6379",
                    "title": "Redis accesible",
                    "description": "",
                    "cvss_score": 8.6,
                    "severity": "high",
                    "finding_type": "exposure",
                    "affected_component": f"{asset.ip_address}:6379",
                    "solution": "Restringir por cortafuegos",
                },
                {
                    "cve_id": "BANNER-22",
                    "title": "El servicio SSH revela su versión",
                    "description": "",
                    "cvss_score": 2.0,
                    "severity": "low",
                    "finding_type": "exposure",
                    "affected_component": f"{asset.ip_address}:22",
                    "solution": "Suprimir banner",
                },
                # Duplicado exacto: debe deduplicarse.
                {
                    "cve_id": "BANNER-22",
                    "title": "El servicio SSH revela su versión",
                    "description": "",
                    "cvss_score": 2.0,
                    "severity": "low",
                    "finding_type": "exposure",
                    "affected_component": f"{asset.ip_address}:22",
                    "solution": "Suprimir banner",
                },
            ]
        return results

    monkeypatch.setattr(diagnostic, "_scan", fake_scan)


def _run(client, headers, organization, assets):
    return client.post(
        "/api/diagnostic/run",
        headers=headers,
        json={"organization_name": organization, "assets": assets, "scan_type": "quick"},
    )


def test_same_finding_on_two_assets_does_not_break(client, analyst, stub_scan, db):
    """F-05: el mismo identificador en dos activos ya no provoca un error 500."""
    headers = auth_headers(client, "analista@guardia.gt")
    response = _run(client, headers, "Municipalidad A", [
        {"name": "SRV-01", "asset_type": "server", "ip_address": "203.0.113.10"},
        {"name": "SRV-02", "asset_type": "server", "ip_address": "203.0.113.11"},
    ])

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["assets_created"] == 2
    # 2 hallazgos únicos por activo (el tercero es un duplicado exacto).
    assert db.query(Vulnerability).count() == 4


def test_findings_attach_to_their_own_asset(client, analyst, stub_scan, db):
    """F-06: antes todo se guardaba con el id del primer activo."""
    headers = auth_headers(client, "analista@guardia.gt")
    _run(client, headers, "Municipalidad A", [
        {"name": "SRV-01", "asset_type": "server", "ip_address": "203.0.113.10"},
        {"name": "SRV-02", "asset_type": "server", "ip_address": "203.0.113.11"},
    ])

    asset_ids = {a.id for a in db.query(Asset).all()}
    used_ids = {v.asset_id for v in db.query(Vulnerability).all()}
    assert used_ids == asset_ids, "cada activo debe tener sus propios hallazgos"


def test_second_organization_does_not_see_the_first(client, analyst, stub_scan, db):
    """F-06: el riesgo se calculaba contando toda la tabla."""
    headers = auth_headers(client, "analista@guardia.gt")

    _run(client, headers, "Municipalidad A", [
        {"name": "SRV-A", "asset_type": "server", "ip_address": "203.0.113.10"},
    ])
    second = _run(client, headers, "Municipalidad B", [
        {"name": "SRV-B", "asset_type": "server", "ip_address": "203.0.113.20"},
    ])

    assert second.status_code == 200
    body = second.json()
    assert body["organization"] == "Municipalidad B"
    assert body["assets_created"] == 1
    # Un solo hallazgo accionable (el `low` de banner cuenta, el duplicado no).
    assert body["vulnerabilities_found"] == 2
    assert {a["name"] for a in body["assets_detail"]} == {"SRV-B"}
    # Los datos de la primera organización siguen existiendo, sin mezclarse.
    assert db.query(Asset).filter(Asset.organization == "Municipalidad A").count() == 1


def test_rerunning_replaces_only_its_own_organization(client, analyst, stub_scan, db):
    headers = auth_headers(client, "analista@guardia.gt")

    _run(client, headers, "Municipalidad A", [
        {"name": "SRV-A", "asset_type": "server", "ip_address": "203.0.113.10"},
    ])
    _run(client, headers, "Municipalidad B", [
        {"name": "SRV-B", "asset_type": "server", "ip_address": "203.0.113.20"},
    ])
    _run(client, headers, "Municipalidad A", [
        {"name": "SRV-A", "asset_type": "server", "ip_address": "203.0.113.10"},
        {"name": "SRV-A2", "asset_type": "server", "ip_address": "203.0.113.11"},
    ])

    assert db.query(Asset).filter(Asset.organization == "Municipalidad A").count() == 2
    assert db.query(Asset).filter(Asset.organization == "Municipalidad B").count() == 1


def test_incidents_are_listed_in_the_result(client, analyst, stub_scan, db):
    """F-06: los incidentes se creaban con `ip:puerto` y el listado filtraba por
    nombre de activo, así que el informe salía siempre vacío."""
    headers = auth_headers(client, "analista@guardia.gt")
    response = _run(client, headers, "Municipalidad A", [
        {"name": "SRV-01", "asset_type": "server", "ip_address": "203.0.113.10"},
    ])

    body = response.json()
    assert body["incidents_created"] == 1
    assert len(body["incidents_detail"]) == 1
    assert body["incidents_detail"][0]["affected_asset"] == "SRV-01"
    assert db.query(Incident).filter(Incident.organization == "Municipalidad A").count() == 1


def test_no_findings_produces_an_honest_empty_report(client, analyst, monkeypatch, db):
    """Sin hallazgos ya no se rellena el informe con CVEs inventados."""
    from app.routes import diagnostic
    monkeypatch.setattr(diagnostic, "_scan", lambda assets, scan_type: {a.id: [] for a in assets})

    headers = auth_headers(client, "analista@guardia.gt")
    response = _run(client, headers, "Municipalidad Limpia", [
        {"name": "SRV-01", "asset_type": "server", "ip_address": "203.0.113.10"},
    ])

    body = response.json()
    assert body["vulnerabilities_found"] == 0
    assert body["risk_level"] == "bajo"
    assert db.query(Vulnerability).count() == 0
    assert any("sin encontrar hallazgos" in note for note in body["notes"])


def test_private_target_is_reported_not_invented(client, analyst, db):
    """El escáner real rechaza direcciones privadas y lo dice, en lugar de
    fabricar vulnerabilidades como hacía la versión anterior."""
    headers = auth_headers(client, "analista@guardia.gt")
    response = _run(client, headers, "Red Interna", [
        {"name": "SRV-INTERNO", "asset_type": "server", "ip_address": "192.168.1.10"},
    ])

    assert response.status_code == 200
    body = response.json()
    assert body["assets_unreachable"] == 1
    assert body["vulnerabilities_found"] == 0
    for vuln in db.query(Vulnerability).all():
        assert not vuln.cve_id.startswith("CVE-2026-NEW")


def test_asset_limit_is_enforced(client, analyst):
    """F-03: sin límite, una sola petición podía lanzar un escaneo masivo."""
    headers = auth_headers(client, "analista@guardia.gt")
    response = _run(client, headers, "Grande", [
        {"name": f"SRV-{i}", "asset_type": "server", "ip_address": "203.0.113.10"}
        for i in range(30)
    ])
    assert response.status_code == 400
    assert "Máximo" in response.json()["detail"]


def test_invalid_asset_type_returns_400(client, analyst):
    headers = auth_headers(client, "analista@guardia.gt")
    response = _run(client, headers, "Org", [
        {"name": "X", "asset_type": "no-existe"},
    ])
    assert response.status_code == 400
