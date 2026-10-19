# VulnFastAPI

> ⚠️ **INTENTIONALLY VULNERABLE APPLICATION — FOR AUTHORIZED LOCAL SECURITY RESEARCH ONLY** ⚠️

VulnFastAPI is a deliberately insecure FastAPI application designed exclusively as a controlled
benchmark target for the **ClairSec** adversarial security-testing platform.

**DO NOT:**
- Run this on a public network or expose it to the internet.
- Use real credentials, real data, or real services with this application.
- Deploy this to a production environment.

**This application contains intentional security vulnerabilities. It exists solely for:**
- Local security research and tooling development.
- Automated security agent testing (Builder / Attacker / Evaluator / Fixer / Verifier).
- Controlled vulnerability detection benchmarks.

---

## Quick Start

### Prerequisites

- Python 3.11
- pip

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Start the Server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Verify

```
curl http://localhost:8000/health
# -> {"status":"ok"}
```

API docs: http://localhost:8000/docs

---

## Docker

### Build

```bash
docker build -t vuln-fastapi .
```

### Run

```bash
docker run -p 8000:8000 vuln-fastapi
```

### Verify from host

```bash
curl http://localhost:8000/health
```

---

## Run Tests

```bash
pytest tests/ -v
```

---

## Demo Credentials

| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | admin123  | admin |
| alice    | user123   | user  |
| bob      | user123   | user  |

---

## Available Endpoints

| Method | Path                    | Auth Required | Description                     |
|--------|-------------------------|---------------|---------------------------------|
| GET    | /health                 | No            | Health check                    |
| GET    | /docs                   | No            | OpenAPI documentation           |
| GET    | /openapi.json           | No            | OpenAPI schema                  |
| POST   | /auth/login             | No            | Login, returns JWT token        |
| GET    | /users/{user_id}        | Yes           | Get user by ID (IDOR vuln)      |
| GET    | /admin/users            | Yes (any)     | List all users (privesc vuln)   |
| DELETE | /admin/users/{user_id}  | Yes (any)     | Delete user (privesc vuln)      |
| GET    | /search/users?q=        | Yes           | Search users (SQL injection)    |
| GET    | /files/{filename}       | Yes           | Read file (path traversal)      |
| GET    | /tools/ping?host=       | Yes           | Ping host (command injection)   |

---

## Ground Truth Vulnerability Catalog

### VULN-001 — IDOR (Insecure Direct Object Reference)

| Field    | Value |
|----------|-------|
| **ID**   | VULN-001 |
| **Name** | IDOR — Broken Object Level Authorization |
| **Category** | Broken Access Control |
| **CWE** | CWE-639 |
| **Endpoint** | `GET /users/{user_id}` |
| **Severity** | High |
| **Source** | `app/routes/users.py` ~line 40 |
| **Expected Behavior** | Any authenticated user can read any other user's record by changing the `user_id` path parameter. |
| **Why Vulnerable** | The endpoint checks that a valid token exists but never verifies that `current_user['sub']` matches the requested `user_id`. No ownership check is performed. |
| **Exploit** | `GET /users/1` with alice's token (alice=user_id 2) returns admin's record. |

---

### VULN-002 — Missing Authorization / Privilege Escalation

| Field    | Value |
|----------|-------|
| **ID**   | VULN-002 |
| **Name** | Missing Authorization / Privilege Escalation |
| **Category** | Broken Function Level Authorization |
| **CWE** | CWE-285 |
| **Endpoints** | `GET /admin/users`, `DELETE /admin/users/{user_id}` |
| **Severity** | Critical |
| **Source** | `app/routes/admin.py` ~line 38 |
| **Expected Behavior** | A `role=user` token grants access to admin-only endpoints. |
| **Why Vulnerable** | The route handler calls `Depends(get_current_user)` which only validates the token signature. It never checks `current_user['role'] == 'admin'`. |
| **Exploit** | `GET /admin/users` with alice's token returns all user records. |

---

### VULN-003 — SQL Injection

| Field    | Value |
|----------|-------|
| **ID**   | VULN-003 |
| **Name** | SQL Injection |
| **Category** | Injection |
| **CWE** | CWE-89 |
| **Endpoint** | `GET /search/users?q=` |
| **Severity** | Critical |
| **Source** | `app/routes/search.py` ~line 46 |
| **Expected Behavior** | Injecting `' OR '1'='1` returns all database rows. UNION-based injection can extract any table. |
| **Why Vulnerable** | The `q` parameter is interpolated into the SQL string with an f-string: `f"... LIKE '%{q}%'"`. SQLite parameterized queries (`?` placeholders) are not used. |
| **Exploit** | `GET /search/users?q=' OR '1'='1` |

---

### VULN-004 — Path Traversal

| Field    | Value |
|----------|-------|
| **ID**   | VULN-004 |
| **Name** | Path Traversal |
| **Category** | Improper Limitation of a Pathname to a Restricted Directory |
| **CWE** | CWE-22 |
| **Endpoint** | `GET /files/{filename}` |
| **Severity** | High |
| **Source** | `app/routes/files.py` ~line 46 |
| **Expected Behavior** | `../` sequences escape the `files/` directory and allow reading arbitrary files in the container. |
| **Why Vulnerable** | `os.path.join(BASE_DIR, filename)` is used without verifying the resolved path still starts with `BASE_DIR`. |
| **Exploit** | `GET /files/../app/auth.py` reads the auth source file containing the hardcoded `SECRET_KEY`. |

---

### VULN-005 — Command Injection

| Field    | Value |
|----------|-------|
| **ID**   | VULN-005 |
| **Name** | Command Injection |
| **Category** | Injection |
| **CWE** | CWE-78 |
| **Endpoint** | `GET /tools/ping?host=` |
| **Severity** | Critical |
| **Source** | `app/routes/tools.py` ~line 47 |
| **Expected Behavior** | Shell metacharacters (`;`, `&&`, `|`) in the `host` parameter execute additional commands inside the container. |
| **Why Vulnerable** | `subprocess.run(f"ping -c 1 {host}", shell=True)` passes user input directly to the shell. |
| **Exploit** | `GET /tools/ping?host=127.0.0.1; echo INJECTED` — stdout includes "INJECTED". |

---

### VULN-006 — Hardcoded Secret Key

| Field    | Value |
|----------|-------|
| **ID**   | VULN-006 |
| **Name** | Hardcoded Secret Key |
| **Category** | Sensitive Information Exposure / Security Misconfiguration |
| **CWE** | CWE-798 |
| **Endpoint** | Static analysis — `app/auth.py` |
| **Severity** | High |
| **Source** | `app/auth.py` line 18 |
| **Expected Behavior** | Source analysis reveals `SECRET_KEY = "vuln-demo-secret-key"`. Combined with VULN-004, path traversal can retrieve the key at runtime. |
| **Why Vulnerable** | The JWT signing secret is hardcoded as a string literal in the source file, allowing any reader to forge tokens for arbitrary users and roles. |
| **Exploit** | Read key via path traversal → forge `{"sub": "eve", "role": "admin"}` JWT → access all admin endpoints. |

---

### VULN-007 — Unsafe JWT Configuration

| Field    | Value |
|----------|-------|
| **ID**   | VULN-007 |
| **Name** | Unsafe JWT Configuration (Algorithm None / No Signature Verification) |
| **Category** | Broken Authentication |
| **CWE** | CWE-347 |
| **Endpoint** | All authenticated endpoints |
| **Severity** | Critical |
| **Source** | `app/auth.py` ~line 33 |
| **Expected Behavior** | An unsigned JWT (algorithm=`none`) or any JWT is accepted without signature verification. |
| **Why Vulnerable** | `jwt.decode()` is called with `options={"verify_signature": False}` and `algorithms=[..., "none"]`. |

---

### VULN-008 — Missing Rate Limiting on Login

| Field    | Value |
|----------|-------|
| **ID**   | VULN-008 |
| **Name** | Missing Rate Limiting on Login |
| **Category** | Broken Authentication |
| **CWE** | CWE-307 |
| **Endpoint** | `POST /auth/login` |
| **Severity** | Medium |
| **Source** | `app/routes/auth_routes.py` ~line 30 |
| **Expected Behavior** | Unlimited login attempts are accepted — brute-force password guessing is not blocked. |
| **Why Vulnerable** | No rate limiter, lockout, or delay mechanism is applied to the login endpoint. |

---

### VULN-009 — Overly Permissive CORS

| Field    | Value |
|----------|-------|
| **ID**   | VULN-009 |
| **Name** | Overly Permissive CORS |
| **Category** | Security Misconfiguration |
| **CWE** | CWE-942 |
| **Endpoint** | All endpoints |
| **Severity** | Medium |
| **Source** | `app/main.py` ~line 44 |
| **Expected Behavior** | Any web origin can make credentialed cross-site requests to this API. |
| **Why Vulnerable** | `allow_origins=["*"]` combined with `allow_credentials=True` is an invalid and insecure configuration that browsers may reject in some scenarios, but frameworks may still allow. |

---

### VULN-010 — Plaintext Password Storage

| Field    | Value |
|----------|-------|
| **ID**   | VULN-010 |
| **Name** | Plaintext Password Storage |
| **Category** | Cryptographic Failures |
| **CWE** | CWE-256 |
| **Endpoint** | Static analysis — `app/database.py` |
| **Severity** | High |
| **Source** | `app/database.py` ~line 20 |
| **Expected Behavior** | All user passwords are stored as cleartext strings in the SQLite database. |
| **Why Vulnerable** | No hashing (bcrypt, argon2, scrypt, etc.) is applied before storage. |

---

## Limitations and Assumptions

- **Command injection (VULN-005)** runs inside the Docker container only. `ping` is available on Linux. On Windows hosts running the app directly (not Docker), `ping` syntax differs; the test accepts a non-200 response gracefully.
- **Path traversal (VULN-004)** — URL routers may normalize `../` sequences before they reach the handler. If the OS normalizes the path, the traversal test accepts 404 as evidence the restriction is absent (not a 403 which would indicate a block).
- **SQLite** is used for complete self-containment. No external database is required.
- The database file (`vuln_app.db`) is created in the project root directory at startup.
- All credentials, secrets, and data are entirely fake and exist solely for benchmark purposes.
