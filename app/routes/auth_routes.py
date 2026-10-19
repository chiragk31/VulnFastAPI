"""
auth_routes.py — Authentication endpoints.

POST /auth/login
    Accepts username + password, returns a JWT token.

VULN-008: No rate limiting — brute-force login is possible.
VULN-006: Token is signed with the hardcoded SECRET_KEY from auth.py.
"""
from fastapi import APIRouter, HTTPException
from app.models import LoginRequest, TokenResponse
from app.database import get_db
from app.auth import create_token

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and receive a bearer token",
    description=(
        "Authenticate with username and password. "
        "Returns a JWT token. "
        "**[VULN-008]** No rate limiting on this endpoint."
    ),
)
def login(body: LoginRequest):
    """
    Login endpoint.
    VULN-008: No rate limiting — automated brute-force is trivially possible.
    VULN-006: Token signed with hardcoded SECRET_KEY.
    """
    conn = get_db()
    cursor = conn.cursor()
    # Lookup user by username and plaintext password
    row = cursor.execute(
        "SELECT id, username, role, email FROM users WHERE username = ? AND password = ?",
        (body.username, body.password),
    ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(username=row["username"], role=row["role"])
    return TokenResponse(
        access_token=token,
        username=row["username"],
        role=row["role"],
    )
