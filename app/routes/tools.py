"""
tools.py — Diagnostic/utility endpoints.

GET /tools/ping?host=<host>

VULN-005: Command Injection.
    The 'host' parameter is passed directly to subprocess.Popen via shell=True,
    allowing injection of arbitrary shell commands.

This endpoint is designed to run ONLY inside an isolated Docker container
during ClairSec security testing. It has no access to host OS resources
beyond the container boundary.

Safe demonstration payloads (for authorized testing inside the container):
    ?host=127.0.0.1                       -> runs: ping -c 1 127.0.0.1
    ?host=127.0.0.1; echo INJECTED        -> runs both ping and echo
    ?host=127.0.0.1; whoami               -> reveals container user
"""
import subprocess
from fastapi import APIRouter, Depends
from app.auth import get_current_user

router = APIRouter(prefix="/tools", tags=["tools"])


@router.get(
    "/ping",
    summary="Ping a host (diagnostic)",
    description=(
        "Runs a ping command against the provided host. "
        "**[VULN-005 Command Injection]** The host parameter is passed to "
        "the shell without sanitization, enabling command injection. "
        "Intended to be exercised only inside the isolated Docker container."
    ),
)
def ping_host(host: str = "127.0.0.1", current_user: dict = Depends(get_current_user)):
    """
    VULN-005: Command Injection via shell=True with unsanitized user input.
    Safe equivalent would use: subprocess.run(["ping", "-c", "1", host], shell=False)
    """
    # ------------------------------------------------------------------
    # VULN-005: shell=True with user-controlled input — command injection.
    # ------------------------------------------------------------------
    command = f"ping -c 1 {host}"
    try:
        result = subprocess.run(
            command,
            shell=True,          # VULNERABLE: shell interpretation enabled
            capture_output=True,
            text=True,
            timeout=10,
        )
        return {
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"command": command, "error": "Command timed out"}
    except Exception as exc:
        return {"command": command, "error": str(exc)}
