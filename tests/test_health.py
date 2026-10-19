"""
test_health.py — Verify the /health endpoint is reachable without authentication.
"""


def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_health_no_auth_required(client):
    """Health endpoint must not require a token (used by ClairSec readiness check)."""
    resp = client.get("/health", headers={})
    assert resp.status_code == 200


def test_docs_available(client):
    """OpenAPI docs must be reachable."""
    assert client.get("/docs").status_code == 200


def test_openapi_json_available(client):
    """openapi.json must be a valid JSON document."""
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "paths" in data
    assert "info" in data
