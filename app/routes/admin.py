"""
admin.py — Administrative endpoints.

GET  /admin/users
DELETE /admin/users/{user_id}

VULN-002: Missing Authorization / Privilege Escalation.
    Both endpoints authenticate the caller (valid token required) but do NOT
    verify that the caller has the 'admin' role.
    A regular 'user'-role token grants full access to admin operations.
"""
from fastapi import APIRouter, HTTPException, Depends
from app.models import UserResponse, UserListResponse
from app.database import get_db
from app.auth import get_current_user

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List all users (admin)",
    description=(
        "Returns a list of all users. "
        "**[VULN-002]** No role check — any authenticated user (including role='user') "
        "can access this admin endpoint."
    ),
)
def list_all_users(current_user: dict = Depends(get_current_user)):
    """
    VULN-002: Privilege Escalation — role is never checked.
    Any authenticated user can list all users.
    """
    # --- VULNERABLE: should check current_user['role'] == 'admin' but does not ---
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, role, email FROM users"
    ).fetchall()
    conn.close()

    users = [
        UserResponse(id=r["id"], username=r["username"], role=r["role"], email=r["email"])
        for r in rows
    ]
    return UserListResponse(users=users)


@router.delete(
    "/users/{user_id}",
    summary="Delete a user (admin)",
    description=(
        "Deletes the user with the given ID. "
        "**[VULN-002]** No role check — any authenticated user can delete any account."
    ),
)
def delete_user(user_id: int, current_user: dict = Depends(get_current_user)):
    """
    VULN-002: Privilege Escalation — role is never checked.
    Any authenticated user can delete any user record.
    """
    # --- VULNERABLE: should check current_user['role'] == 'admin' but does not ---
    conn = get_db()
    result = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")

    return {"detail": f"User {user_id} deleted"}
