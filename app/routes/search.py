"""
search.py — Search endpoints.

GET /search/users?q=<query>

VULN-003: SQL Injection.
    The query parameter is interpolated directly into the SQL string using
    an f-string, bypassing SQLite's parameterized query mechanism.
    An attacker can inject arbitrary SQL and extract or manipulate data.

Example injection: ?q=' OR '1'='1
"""
from fastapi import APIRouter, Depends
from app.database import get_db
from app.auth import get_current_user

router = APIRouter(prefix="/search", tags=["search"])


@router.get(
    "/users",
    summary="Search users by username",
    description=(
        "Search users by username fragment. "
        "**[VULN-003 SQL Injection]** The query parameter is interpolated "
        "directly into the SQL string — parameterized queries are NOT used."
    ),
)
def search_users(q: str = "", current_user: dict = Depends(get_current_user)):
    """
    VULN-003: SQL Injection via f-string interpolation.
    Safe equivalent would be: cursor.execute("... WHERE username LIKE ?", (f"%{q}%",))
    """
    conn = get_db()
    cursor = conn.cursor()

    # ------------------------------------------------------------------
    # VULN-003: Unsafe SQL construction — user input injected directly.
    # ------------------------------------------------------------------
    unsafe_query = f"SELECT id, username, role, email FROM users WHERE username LIKE '%{q}%'"
    try:
        rows = cursor.execute(unsafe_query).fetchall()
    except Exception as exc:
        conn.close()
        # Return raw DB error — also an information exposure vulnerability
        return {"error": str(exc), "query": unsafe_query}
    conn.close()

    return {
        "query": q,
        "results": [
            {"id": r["id"], "username": r["username"], "role": r["role"], "email": r["email"]}
            for r in rows
        ],
    }
