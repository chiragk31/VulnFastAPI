"""
files.py — File serving endpoints.

GET /files/{filename}

VULN-004: Path Traversal.
    The filename parameter is appended to the base directory path without
    sanitization, allowing traversal outside the intended 'files/' directory
    using sequences such as '../'.

Demonstration within the project:
    GET /files/public.txt         -> returns files/public.txt  (intended)
    GET /files/../app/auth.py     -> returns app/auth.py       (traversal)
    GET /files/secret.txt         -> returns files/secret.txt  (accessible)
"""
import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from app.auth import get_current_user
from fastapi import Depends

router = APIRouter(prefix="/files", tags=["files"])

# Base directory for served files — relative to project root
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "files")


@router.get(
    "/{filename:path}",
    response_class=PlainTextResponse,
    summary="Read a file from the files directory",
    description=(
        "Returns the contents of a file from the `files/` directory. "
        "**[VULN-004 Path Traversal]** The filename is not sanitized — "
        "traversal sequences like `../` can escape the files directory."
    ),
)
def read_file(filename: str, current_user: dict = Depends(get_current_user)):
    """
    VULN-004: Path Traversal — no path sanitization applied.
    Safe equivalent would resolve the path and verify it starts with BASE_DIR.
    """
    # ------------------------------------------------------------------
    # VULN-004: Unsafe path construction — traversal not prevented.
    # ------------------------------------------------------------------
    file_path = os.path.join(BASE_DIR, filename)

    # No check: if not file_path.startswith(os.path.realpath(BASE_DIR)): raise 403

    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()
