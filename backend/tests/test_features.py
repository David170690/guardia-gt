"""Pruebas de las funcionalidades nuevas: IA, cumplimiento derivado, CVE, MFA, export."""

import pyotp
import pytest

from conftest import auth_headers

from app.services import ai_report, compliance_map, cve_lookup


# --------------------------------------------------------- IA (informe ejecutivo)


def test_report_falls_back_to_template_without_api_key(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config.settings, "AI_API_KEY", "")

    findings = [
        {"cve_id": "EXPOSED-REDIS-6379", "title": "Redis accesible", "severity": "high",
         "cvss_score": 8.6, "finding_type": "exposure",
         "affected_component": "1.2.3.4:6379", "solution": "Restringir por firewall"},
    ]
    report = ai_report.generate_report("Muni A", "alto", findings, 1, 1)
    assert report.generated_by == "plantilla"
    assert "Muni A" in report.executive_summary
    assert report.remediation_plan  # sale de la solución real del hallazgo
    # La plantilla no inventa: el riesgo mencionado viene del hallazgo dado.
    assert any("Redis" in r for r in report.key_risks)


def test_report_clean_scan_is_honest(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config.settings, "AI_API_KEY", "")
    report = ai_report.generate_report("Muni Limpia", "bajo", [], 2, 2)
    assert report.generated_by == "plantilla"
    assert "no identificó hallazgos" in report.executive_summary
    assert report.key_risks == []


def test_report_uses_model_when_configured(monkeypatch):
    """Con API key, se llama al modelo; su JSON se refleja en el informe."""
    from app.core import config
    monkeypatch.setattr(config.settings, "AI_API_KEY", "clave-falsa")

    captured = {}

    def fake_call(org, risk, findings, scanned, total):
        captured["called"] = True
        return ai_report.ExecutiveReport(
            organization=org, risk_level=risk, generated_by="ia", model="modelo-test",
            executive_summary="Resumen del modelo.",
            key_risks=["riesgo del modelo"], remediation_plan=["paso del modelo"],
        )

    monkeypatch.setattr(ai_report, "_generate_with_model", fake_call)
    report = ai_report.generate_report("Muni B", "medio", [], 1, 1)
    assert captured.get("called")
    assert report.generated_by == "ia"
    assert report.executive_summary == "Resumen del modelo."


def test_model_chain_skips_deprecated_and_uses_next(monkeypatch):
    """Si el primer slug :free está descontinuado (404), se usa el siguiente."""
    import httpx
    from app.core import config
    monkeypatch.setattr(config.settings, "AI_API_KEY", "clave")
    monkeypatch.setattr(config.settings, "AI_MODEL", "modelo-muerto:free,modelo-vivo:free")

    calls = []

    def fake_call(model, messages):
        calls.append(model)
        if model == "modelo-muerto:free":
            req = httpx.Request("POST", "http://x")
            resp = httpx.Response(404, request=req, text="deprecated")
            raise httpx.HTTPStatusError("404", request=req, response=resp)
        return '{"executive_summary": "ok", "key_risks": [], "remediation_plan": []}'

    monkeypatch.setattr(ai_report, "_call_openrouter", fake_call)
    report = ai_report.generate_report("Org", "bajo", [], 1, 1)
    assert calls == ["modelo-muerto:free", "modelo-vivo:free"]
    assert report.generated_by == "ia"
    assert report.model == "modelo-vivo:free"


def test_all_models_dead_falls_back_with_reason(monkeypatch):
    import httpx
    from app.core import config
    monkeypatch.setattr(config.settings, "AI_API_KEY", "clave")
    monkeypatch.setattr(config.settings, "AI_MODEL", "a:free,b:free")

    def always_404(model, messages):
        req = httpx.Request("POST", "http://x")
        raise httpx.HTTPStatusError("404", request=req, response=httpx.Response(404, request=req))

    monkeypatch.setattr(ai_report, "_call_openrouter", always_404)
    report = ai_report.generate_report("Org", "bajo", [], 1, 1)
    assert report.generated_by == "plantilla"
    assert "a:free" in report.fallback_reason and "b:free" in report.fallback_reason


def test_report_endpoint_requires_data(client, analyst):
    headers = auth_headers(client, "analista@guardia.gt")
    r = client.post("/api/ai/report", headers=headers, json={"organization": "No Existe"})
    assert r.status_code == 404


def test_ai_status_reports_mode(client, analyst):
    headers = auth_headers(client, "analista@guardia.gt")
    r = client.get("/api/ai/status", headers=headers)
    assert r.status_code == 200
    assert r.json()["mode"] in ("modelo", "plantilla")


def test_ai_endpoint_requires_auth(client):
    assert client.post("/api/ai/report", json={"organization": "X"}).status_code == 401


# ---------------------------------------------- cumplimiento derivado de hallazgos


def test_compliance_maps_findings_to_failed_controls():
    findings = [
        {"cve_id": "HTTP-NO-TLS-80", "finding_type": "exposure", "affected_component": "web:80"},
        {"cve_id": "EXPOSED-REDIS-6379", "finding_type": "exposure", "affected_component": "db:6379"},
    ]
    assessment = compliance_map.assess(findings)
    failed = [c for c in assessment if c["status"] == "non_compliant"]
    # HTTP sin TLS incumple criptografía; Redis expuesto incumple configuración/acceso.
    assert any(c["control_id"] == "A02" for c in failed)          # OWASP fallos cripto
    assert any(c["control_id"] == "CIS 4" for c in failed)        # config segura
    assert all(0 <= c["score"] <= 100 for c in assessment)


def test_compliance_clean_findings_pass():
    findings = [{"cve_id": "SSL-OK-443", "finding_type": "ssl", "affected_component": "web:443"}]
    assessment = compliance_map.assess(findings)
    # Sin evidencia de incumplimiento, los controles evaluables pasan.
    assert all(c["status"] == "compliant" for c in assessment)
    assert compliance_map.score(assessment) == 100.0


def test_diagnostic_produces_real_compliance(client, analyst, monkeypatch, db):
    """Cuando se observan servicios, el cumplimiento pasa a ser una evaluación real."""
    from app.routes import diagnostic

    def fake_scan(assets, scan_type):
        return {a.id: [{
            "cve_id": "HTTP-NO-TLS-80", "title": "Web sin TLS", "description": "",
            "cvss_score": 6.5, "severity": "medium", "finding_type": "exposure",
            "affected_component": f"{a.ip_address}:80", "solution": "Usar HTTPS",
        }] for a in assets if a.ip_address}

    monkeypatch.setattr(diagnostic, "_scan", fake_scan)
    headers = auth_headers(client, "analista@guardia.gt")
    r = client.post("/api/diagnostic/run", headers=headers, json={
        "organization_name": "Muni C",
        "assets": [{"name": "WEB", "asset_type": "web_app", "ip_address": "203.0.113.9"}],
        "scan_type": "quick",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["compliance_assessed"] is True
    assert any(c["status"] == "non_compliant" for c in body["compliance_detail"])


# ------------------------------------------------------ confirmación de CVEs


@pytest.mark.parametrize("banner,expected", [
    ("SSH-2.0-OpenSSH_8.9p1 Ubuntu", ("OpenSSH", "8.9p1")),
    ("Server: Apache/2.4.49 (Unix)", ("Apache httpd", "2.4.49")),
    ("Server: nginx/1.18.0", ("nginx", "1.18.0")),
    ("algo sin version reconocible", None),
])
def test_banner_parsing(banner, expected):
    assert cve_lookup.parse_banner(banner) == expected


def test_cve_lookup_disabled_by_default(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config.settings, "CVE_LOOKUP_ENABLED", False)
    # Aunque el banner tenga versión, sin activar no consulta nada.
    assert cve_lookup.confirm_cves("SSH-2.0-OpenSSH_8.9p1", "1.2.3.4:22") == []


def test_cve_lookup_maps_nvd_response(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config.settings, "CVE_LOOKUP_ENABLED", True)
    monkeypatch.setattr(cve_lookup, "lookup", lambda p, v: [
        {"cve_id": "CVE-2023-99999", "cvss_score": 9.1, "severity": "critical",
         "description": "fallo grave"},
    ])
    findings = cve_lookup.confirm_cves("SSH-2.0-OpenSSH_8.9p1", "1.2.3.4:22")
    assert len(findings) == 1
    assert findings[0]["cve_id"] == "CVE-2023-99999"
    assert findings[0]["finding_type"] == "cve"


# --------------------------------------------------------------------- MFA


def test_mfa_full_flow(client, analyst, db):
    headers = auth_headers(client, "analista@guardia.gt")

    setup = client.post("/api/settings/mfa/setup", headers=headers)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert setup.json()["qr_data_uri"].startswith("data:image/png;base64,")

    # Código incorrecto no activa.
    bad = client.post("/api/settings/mfa/enable", headers=headers, json={"code": "000000"})
    assert bad.status_code == 400

    # Código correcto sí.
    code = pyotp.TOTP(secret).now()
    ok = client.post("/api/settings/mfa/enable", headers=headers, json={"code": code})
    assert ok.status_code == 200
    assert ok.json()["mfa_enabled"] is True


def test_login_requires_code_when_mfa_enabled(client, analyst, db):
    from app.services import mfa
    from app.models.user import User
    user = db.query(User).filter(User.email == "analista@guardia.gt").first()
    user.mfa_secret = mfa.new_secret()
    user.mfa_enabled = True
    db.commit()

    # Sin código: 428 (se requiere segundo factor), no 200 ni 401.
    r = client.post("/api/auth/login", json={"email": "analista@guardia.gt", "password": "Password123!"})
    assert r.status_code == 428

    # Con código válido: entra.
    code = pyotp.TOTP(user.mfa_secret).now()
    ok = client.post("/api/auth/login", json={
        "email": "analista@guardia.gt", "password": "Password123!", "code": code})
    assert ok.status_code == 200
    assert "access_token" in ok.json()


# ---------------------------------------------------------------- exportación


def test_csv_export(client, analyst, db):
    from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
    db.add(Asset(name="SRV-X", organization="Muni D", asset_type=AssetType.SERVER,
                 criticality=AssetCriticality.HIGH, status=AssetStatus.ONLINE))
    db.commit()

    headers = auth_headers(client, "analista@guardia.gt")
    r = client.get("/api/reports/export/assets", headers=headers)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "SRV-X" in r.text


def test_csv_export_unknown_type(client, analyst):
    headers = auth_headers(client, "analista@guardia.gt")
    assert client.get("/api/reports/export/desconocido", headers=headers).status_code == 400


def test_pdf_export(client, analyst, db):
    from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
    db.add(Asset(name="SRV-Y", organization="Muni E", asset_type=AssetType.SERVER,
                 ip_address="203.0.113.5", criticality=AssetCriticality.HIGH,
                 status=AssetStatus.ONLINE))
    db.commit()

    headers = auth_headers(client, "analista@guardia.gt")
    r = client.get("/api/reports/pdf", headers=headers, params={"organization": "Muni E"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF"


def test_export_requires_auth(client):
    assert client.get("/api/reports/export/assets").status_code == 401
    assert client.get("/api/reports/pdf?organization=X").status_code == 401
