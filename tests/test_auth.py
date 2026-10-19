"""
test_auth.py — Verify login endpoint and token behaviour.
"""
from tests.conftest import auth_headers


def test_admin_login_succeeds(client):
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["role"] == "admin"
    assert body["username"] == "admin"


def test_user_login_succeeds(client):
    resp = client.post("/auth/login", json={"username": "alice", "password": "user123"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "user"


def test_wrong_password_fails(client):
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrongpass"})
    assert resp.status_code == 401


def test_unknown_user_fails(client):
    resp = client.post("/auth/login", json={"username": "ghost", "password": "ghost"})
    assert resp.status_code == 401


def test_protected_endpoint_without_token_returns_401(client):
    """Verify that protected routes reject unauthenticated requests."""
    resp = client.get("/users/1")
    assert resp.status_code == 401


def test_protected_endpoint_with_valid_token_succeeds(client, user_token):
    resp = client.get("/users/2", headers=auth_headers(user_token))
    assert resp.status_code == 200
