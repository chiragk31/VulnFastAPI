"""
auth.py - Authentication helpers.

VULN-006: SECRET_KEY is hardcoded in source code.
VULN-007: JWT algorithm set to 'none' is also accepted (unsafe JWT config).
VULN-008: No rate-limiting on login endpoint.
"""
from fastapi import Header, HTTPException
from jose import jwt, JWTError
from typing import Optional

# ------------------------------------------------------------------
# VULN-006: Hardcoded secret key — easily discoverable by static analysis.
# ------------------------------------------------------------------
SECRET_KEY = "vuln-demo-secret-key"
ALGORITHM = "HS256"


def create_token(username: str, role: str) -> str:
    """Create a signed JWT token. Uses a hardcoded weak secret."""
    payload = {"sub": username, "role": role}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decode a JWT token.
    VULN: accepts tokens signed with 'none' algorithm (no signature verification).
    """
    try:
        # ------------------------------------------------------------------
        # VULN-007: algorithms list includes 'none', allowing unsigned tokens.
        # ------------------------------------------------------------------
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM, "none"],
            options={"verify_signature": False},  # signature verification disabled
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def get_current_user(authorization: Optional[str] = Header(default=None)) -> dict:
    """
    FastAPI dependency: extracts and decodes the bearer token from the
    Authorization header.  Raises 401 if missing or invalid.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    return decode_token(token)
