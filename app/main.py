"""
main.py — FastAPI application entry point for VulnFastAPI benchmark.

Start with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000

IMPORTANT: This application is intentionally vulnerable.
It is designed exclusively for local/containerized security research with ClairSec.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db
from app.routes import auth_routes, users, admin, search, files, tools


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize SQLite database and seed demo data on startup."""
    init_db()
    yield


# ------------------------------------------------------------------
# VULN-009: Overly permissive CORS — all origins, methods, and headers allowed.
# ------------------------------------------------------------------
app = FastAPI(
    lifespan=lifespan,
    title="VulnFastAPI",
    description=(
        "**⚠️ INTENTIONALLY VULNERABLE BENCHMARK APPLICATION ⚠️**\n\n"
        "This API is designed exclusively for authorized local security research "
        "with the ClairSec adversarial testing platform. "
        "Do NOT expose this application to the internet or use real data.\n\n"
        "### Implemented Vulnerabilities\n"
        "- **VULN-001**: IDOR — `GET /users/{user_id}`\n"
        "- **VULN-002**: Privilege Escalation — `GET /admin/users`, `DELETE /admin/users/{user_id}`\n"
        "- **VULN-003**: SQL Injection — `GET /search/users`\n"
        "- **VULN-004**: Path Traversal — `GET /files/{filename}`\n"
        "- **VULN-005**: Command Injection — `GET /tools/ping`\n"
        "- **VULN-006**: Hardcoded Secret — `app/auth.py`\n"
        "- **VULN-007**: Unsafe JWT config — algorithm `none` accepted\n"
        "- **VULN-008**: No rate limiting on login\n"
        "- **VULN-009**: Overly permissive CORS\n"
        "- **VULN-010**: Plaintext password storage\n"
    ),
    version="1.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json",
)

# VULN-009: allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth_routes.router)
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(search.router)
app.include_router(files.router)
app.include_router(tools.router)


@app.get(
    "/health",
    tags=["health"],
    summary="Health check",
    description="Returns `{status: ok}` — used by ClairSec to verify the app is running.",
)
def health():
    """Health check endpoint. Does not require authentication."""
    return {"status": "ok"}
