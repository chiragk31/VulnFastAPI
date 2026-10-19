"""
users.py — User endpoints.

GET /users/{user_id}
    Returns the user record for the given ID.

VULN-001: IDOR — Broken Object Level Authorization.
    The endpoint verifies that the caller is authenticated but does NOT
    verify that the authenticated user is requesting their own record.
    Any authenticated user can retrieve any other user's data by changing
    the user_id path parameter.
"""
from fastapi import APIRouter, HTTPException, Depends
from app.models import UserResponse
from app.database import get_db
from app.auth import get_current_user

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user by ID",
    description=(
        "Returns the user record for the given user_id. "
        "**[VULN-001 IDOR]** No ownership check — any authenticated user can "
        "read any other user's record by changing the ID."
    ),
)
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    """
    VULN-001: IDOR — object ownership is never verified.
    current_user['sub'] is authenticated but is NOT compared to user_id.
    """
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, role, email FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    # --- VULNERABLE: no check that current_user['sub'] == row['username'] ---
    return UserResponse(
        id=row["id"],
        username=row["username"],
        role=row["role"],
        email=row["email"],
    )
