from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from uuid import uuid4

from app.api.dependencies import current_user, require_roles
from app.models.user import User


def register(client, email="analyst@example.com"):
    return client.post("/api/auth/register", json={"email": email, "password": "correct horse battery"})


def test_registration_login_and_me(client):
    response = register(client)
    assert response.status_code == 201
    tokens = response.json()
    assert tokens["user"]["role"] == "viewer"
    assert "password_hash" not in tokens["user"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200
    assert me.json()["email"] == "analyst@example.com"
    login = client.post("/api/auth/login", json={"email": "analyst@example.com", "password": "correct horse battery"})
    assert login.status_code == 200
    assert login.json()["access_token"] != tokens["access_token"]


def test_duplicate_registration_and_invalid_login(client):
    assert register(client).status_code == 201
    assert register(client).status_code == 409
    response = client.post("/api/auth/login", json={"email": "analyst@example.com", "password": "wrong password"})
    assert response.status_code == 401


def test_refresh_rotates_and_logout_revokes(client):
    tokens = register(client).json()
    rotated = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert rotated.status_code == 200
    next_tokens = rotated.json()
    assert next_tokens["refresh_token"] != tokens["refresh_token"]
    assert client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert client.post("/api/auth/logout", json={"refresh_token": next_tokens["refresh_token"]}).status_code == 204
    assert client.post("/api/auth/refresh", json={"refresh_token": next_tokens["refresh_token"]}).status_code == 401


def test_role_dependency_enforces_access(client):
    test_app = FastAPI()
    test_app.dependency_overrides.update(client.app.dependency_overrides)
    test_app.dependency_overrides[current_user] = lambda: User(
        id=uuid4(), email="viewer@example.com", password_hash="unused", role="viewer"
    )

    @test_app.get("/admin", dependencies=[Depends(require_roles("admin"))])
    def admin_route():
        return {"ok": True}

    assert TestClient(test_app).get("/admin").status_code == 403
