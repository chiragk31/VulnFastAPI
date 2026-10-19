"""
database.py - SQLite database initialization and connection helpers.
Auto-creates the database and seeds demo users on startup.
"""
import sqlite3
import os

# Database file path — resolved relative to this file so it works inside Docker
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "vuln_app.db")

# ------------------------------------------------------------------
# VULN: Passwords are stored as plaintext (no hashing).
# This is intentional for the benchmark.
# ------------------------------------------------------------------
SEED_USERS = [
    (1, "admin",  "admin123", "admin", "admin@example.test"),
    (2, "alice",  "user123",  "user",  "alice@example.test"),
    (3, "bob",    "user123",  "user",  "bob@example.test"),
]


def get_db() -> sqlite3.Connection:
    """Return a new SQLite connection. Caller is responsible for closing it."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables and seed data if they do not already exist."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT    NOT NULL UNIQUE,
            password TEXT    NOT NULL,
            role     TEXT    NOT NULL DEFAULT 'user',
            email    TEXT    NOT NULL
        )
    """)

    for user in SEED_USERS:
        cursor.execute(
            "INSERT OR IGNORE INTO users (id, username, password, role, email) "
            "VALUES (?, ?, ?, ?, ?)",
            user,
        )

    conn.commit()
    conn.close()
