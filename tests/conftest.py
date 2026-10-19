"""
conftest.py — Shared pytest fixtures for VulnFastAPI tests.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Ensure the database is initialised before any test runs."""
    init_db()


@pytest.fixture(scope="session")
def client():
    """Return a TestClient for the FastAPI application."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_token(client):
    """Return a valid admin bearer token."""
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture(scope="session")
def user_token(client):
    """Return a valid regular-user bearer token (alice)."""
    resp = client.post("/auth/login", json={"username": "alice", "password": "user123"})
    assert resp.status_code == 200
    return resp.json()["access_token"]


def auth_headers(token: str) -> dict:
    """Helper: return Authorization header dict."""
    return {"Authorization": f"Bearer {token}"}
