"""Verifica que la API no vuelva a quedar abierta (hallazgos F-01, F-02, F-03)."""

import pytest

from conftest import auth_headers

PROTECTED_ENDPOINTS = [
    ("GET", "/api/dashboard/"),
    ("GET", "/api/vulnerabilities/"),
    ("GET", "/api/vulnerabilities/stats"),
    ("GET", "/api/assets/"),
    ("GET", "/api/assets/stats"),
    ("GET", "/api/incidents/"),
    ("GET", "/api/incidents/stats"),
    ("GET", "/api/compliance/"),
    ("GET", "/api/compliance/dashboard"),
    ("GET", "/api/reports/"),
    ("GET", "/api/reports/trends"),
    ("GET", "/api/users/"),
    ("GET", "/api/settings/profile"),
    ("GET", "/api/settings/system"),
    ("POST", "/api/diagnostic/run"),
]


@pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
def test_endpoint_requires_authentication(client, method, path):
    response = client.request(method, path, json={})
    assert response.status_code == 401, f"{method} {path} respondió {response.status_code}"


def test_health_is_public(client):
    assert client.get("/health").status_code == 200


def test_refresh_token_is_not_accepted_as_access_token(client, admin):
    tokens = client.post(
        "/api/auth/login",
        json={"email": "admin@guardia.gt", "password": "Password123!"},
    ).json()

    response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {tokens['refresh_token']}"},
    )
    assert response.status_code == 401


def test_public_registration_cannot_grant_admin(client):
    """F-02: enviar `role` en el registro público no debe escalar privilegios."""
    response = client.post(
        "/api/auth/register",
        json={
            "email": "atacante@example.com",
            "full_name": "Atacante",
            "password": "Password123!",
            "role": "admin",
        },
    )
    assert response.status_code == 201
    assert response.json()["role"] == "viewer"


def test_viewer_cannot_write(client, viewer):
    headers = auth_headers(client, "viewer@guardia.gt")
    response = client.post(
        "/api/assets/",
        headers=headers,
        json={"name": "PRUEBA", "asset_type": "server"},
    )
    assert response.status_code == 403


def test_analyst_can_write(client, analyst):
    headers = auth_headers(client, "analista@guardia.gt")
    response = client.post(
        "/api/assets/",
        headers=headers,
        json={"name": "SRV-PRUEBA", "asset_type": "server", "criticality": "high"},
    )
    assert response.status_code == 201


def test_only_admin_lists_users(client, analyst):
    headers = auth_headers(client, "analista@guardia.gt")
    assert client.get("/api/users/", headers=headers).status_code == 403


def test_seed_requires_token(client):
    assert client.post("/seed").status_code == 403
    assert client.post("/seed", headers={"X-Seed-Token": "incorrecto"}).status_code == 403
    ok = client.post("/seed", headers={"X-Seed-Token": "token-de-prueba"})
    assert ok.status_code == 200
    assert ok.json()["seeded"] is True


def test_disabled_account_cannot_log_in(client, db, viewer):
    viewer.is_active = False
    db.commit()
    response = client.post(
        "/api/auth/login",
        json={"email": "viewer@guardia.gt", "password": "Password123!"},
    )
    assert response.status_code == 403
