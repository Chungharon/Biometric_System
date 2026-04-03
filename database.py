"""
database.py - SQLite Database Module for the Biometric Authentication System.

Provides CRUD operations for:
  - users          : registered individuals
  - face_encodings : serialised 128-d numpy arrays
  - access_logs    : every authentication attempt
"""

import sqlite3
import csv
import os
import pickle
import datetime
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

import config


# ─── Connection Helper ────────────────────────────────────────────────────────

@contextmanager
def get_connection():
    """Context manager that yields a SQLite connection and commits/rolls back."""
    conn = sqlite3.connect(config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row          # Rows behave like dicts
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─── Schema Initialization ────────────────────────────────────────────────────

def initialize_database() -> None:
    """
    Create all required tables if they do not already exist.

    Tables
    ------
    users           : core user identity and role.
    face_encodings  : serialised encoding blobs linked to a user.
    access_logs     : immutable audit trail of every auth attempt.
    lockouts        : tracks temporary account lockouts.
    """
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id     TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'visitor',
                pin_hash    TEXT,
                active      INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS face_encodings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                encoding    BLOB NOT NULL,
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS access_logs (
                log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         TEXT,
                name            TEXT,
                timestamp       TEXT NOT NULL,
                location        TEXT DEFAULT 'Main Entrance',
                status          TEXT NOT NULL,
                confidence      REAL,
                method          TEXT DEFAULT 'face'
            );

            CREATE TABLE IF NOT EXISTS lockouts (
                user_id         TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    TEXT
            );
        """)
    print("[DB] Database initialised at:", config.DB_PATH)


# ─── User CRUD ────────────────────────────────────────────────────────────────

def add_user(user_id: str, name: str, role: str = "visitor",
             pin_hash: Optional[str] = None) -> bool:
    """
    Insert a new user record.

    Parameters
    ----------
    user_id  : Unique identifier string (e.g. 'USR001').
    name     : Full display name.
    role     : One of 'admin', 'employee', 'visitor'.
    pin_hash : bcrypt-hashed PIN (optional).

    Returns True on success, False if user_id already exists.
    """
    now = datetime.datetime.utcnow().isoformat()
    try:
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO users (user_id, name, role, pin_hash, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, name, role, pin_hash, now, now)
            )
        print(f"[DB] User '{name}' ({user_id}) added with role '{role}'.")
        return True
    except sqlite3.IntegrityError:
        print(f"[DB] User ID '{user_id}' already exists.")
        return False


def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single user by user_id.  Returns None if not found."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
    return dict(row) if row else None


def get_all_users(active_only: bool = True) -> List[Dict[str, Any]]:
    """Return all users, optionally filtered to active accounts only."""
    query = "SELECT * FROM users"
    if active_only:
        query += " WHERE active = 1"
    query += " ORDER BY created_at DESC"
    with get_connection() as conn:
        rows = conn.execute(query).fetchall()
    return [dict(r) for r in rows]


def deactivate_user(user_id: str) -> bool:
    """
    Soft-delete a user by setting active = 0.

    Returns True if a row was updated, False otherwise.
    """
    now = datetime.datetime.utcnow().isoformat()
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE users SET active = 0, updated_at = ? WHERE user_id = ?",
            (now, user_id)
        )
    updated = cur.rowcount > 0
    if updated:
        print(f"[DB] User '{user_id}' deactivated.")
    return updated


def delete_user(user_id: str) -> bool:
    """
    Hard-delete a user and all linked encodings (cascade).

    Returns True if a row was deleted.
    """
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    deleted = cur.rowcount > 0
    if deleted:
        # Remove encoding file if present
        enc_file = os.path.join(config.ENCODINGS_DIR, f"{user_id}.pkl")
        if os.path.exists(enc_file):
            os.remove(enc_file)
        print(f"[DB] User '{user_id}' deleted.")
    return deleted


def update_user(user_id: str, **fields) -> bool:
    """
    Update arbitrary columns on a user record.

    Usage: update_user('USR001', name='New Name', role='employee')
    """
    if not fields:
        return False
    now = datetime.datetime.utcnow().isoformat()
    fields["updated_at"] = now
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [user_id]
    with get_connection() as conn:
        cur = conn.execute(
            f"UPDATE users SET {set_clause} WHERE user_id = ?", values
        )
    return cur.rowcount > 0


# ─── Face Encoding CRUD ───────────────────────────────────────────────────────

def save_encoding(user_id: str, encoding) -> None:
    """
    Persist a single face encoding (numpy array) to the DB as a BLOB
    and also write a .pkl file to ENCODINGS_DIR for fast bulk loading.

    Parameters
    ----------
    user_id  : The owner's user_id.
    encoding : A 128-dimensional numpy array from face_recognition.
    """
    now = datetime.datetime.utcnow().isoformat()
    blob = pickle.dumps(encoding)
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO face_encodings (user_id, encoding, created_at) VALUES (?, ?, ?)",
            (user_id, blob, now)
        )
    # Also update the pickle sidecar (list of all encodings for this user)
    _update_encoding_file(user_id)


def load_all_encodings() -> Dict[str, List]:
    """
    Load every active user's face encodings from the database.

    Returns
    -------
    Dict mapping user_id → list of numpy arrays.
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT fe.user_id, fe.encoding
            FROM face_encodings fe
            JOIN users u ON fe.user_id = u.user_id
            WHERE u.active = 1
        """).fetchall()
    result: Dict[str, List] = {}
    for row in rows:
        uid = row["user_id"]
        enc = pickle.loads(row["encoding"])
        result.setdefault(uid, []).append(enc)
    return result


def get_user_encodings(user_id: str) -> List:
    """Return list of numpy arrays for a specific user."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT encoding FROM face_encodings WHERE user_id = ?", (user_id,)
        ).fetchall()
    return [pickle.loads(r["encoding"]) for r in rows]


def _update_encoding_file(user_id: str) -> None:
    """Refresh the .pkl sidecar file for a user from the database."""
    encodings = get_user_encodings(user_id)
    path = os.path.join(config.ENCODINGS_DIR, f"{user_id}.pkl")
    with open(path, "wb") as f:
        pickle.dump(encodings, f)


# ─── Access Log CRUD ──────────────────────────────────────────────────────────

def log_access(user_id: Optional[str], name: Optional[str],
               status: str, confidence: Optional[float] = None,
               location: str = "Main Entrance", method: str = "face") -> None:
    """
    Append a record to the access_logs table.

    Parameters
    ----------
    user_id    : user_id if known, else None.
    name       : Display name or 'Unknown'.
    status     : 'GRANTED' or 'DENIED'.
    confidence : Match confidence (1 - distance); None for unknown faces.
    location   : Access point label.
    method     : Authentication method used ('face', 'pin', 'face+pin').
    """
    now = datetime.datetime.utcnow().isoformat()
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO access_logs
               (user_id, name, timestamp, location, status, confidence, method)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name or "Unknown", now, location, status, confidence, method)
        )


def get_access_logs(user_id: Optional[str] = None,
                    date: Optional[str] = None,
                    role: Optional[str] = None,
                    limit: int = 200) -> List[Dict[str, Any]]:
    """
    Query access logs with optional filters.

    Parameters
    ----------
    user_id : Filter to a specific user (exact match).
    date    : ISO date string 'YYYY-MM-DD' to filter by day.
    role    : Filter by user role (joins users table).
    limit   : Maximum rows to return.
    """
    conditions: List[str] = []
    params: List[Any] = []

    base_query = """
        SELECT al.*, u.role
        FROM access_logs al
        LEFT JOIN users u ON al.user_id = u.user_id
    """
    if user_id:
        conditions.append("al.user_id = ?")
        params.append(user_id)
    if date:
        conditions.append("DATE(al.timestamp) = ?")
        params.append(date)
    if role:
        conditions.append("u.role = ?")
        params.append(role)

    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)
    base_query += " ORDER BY al.timestamp DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(base_query, params).fetchall()
    return [dict(r) for r in rows]


def export_logs_to_csv(filepath: Optional[str] = None) -> str:
    """
    Dump the full access_logs table to a CSV file.

    Returns the path of the written file.
    """
    filepath = filepath or config.LOG_PATH
    logs = get_access_logs(limit=100_000)
    if not logs:
        print("[DB] No logs to export.")
        return filepath
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)
    print(f"[DB] {len(logs)} log entries exported to {filepath}")
    return filepath


# ─── Lockout Management ───────────────────────────────────────────────────────

def record_failed_attempt(user_id: str) -> int:
    """
    Increment the failed-attempt counter for a user.

    Automatically triggers a lockout when LOCKOUT_ATTEMPTS is reached.
    Returns the current failed-attempt count.
    """
    now = datetime.datetime.utcnow()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM lockouts WHERE user_id = ?", (user_id,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO lockouts (user_id, failed_attempts) VALUES (?, 1)",
                (user_id,)
            )
            attempts = 1
        else:
            attempts = row["failed_attempts"] + 1
            locked_until = None
            if attempts >= config.LOCKOUT_ATTEMPTS:
                locked_until = (
                    now + datetime.timedelta(seconds=config.LOCKOUT_DURATION)
                ).isoformat()
                print(f"[SECURITY] User '{user_id}' locked out until {locked_until}.")
            conn.execute(
                "UPDATE lockouts SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
                (attempts, locked_until, user_id)
            )
    return attempts


def clear_failed_attempts(user_id: str) -> None:
    """Reset a user's failed-attempt counter (called after successful auth)."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE lockouts SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?",
            (user_id,)
        )


def is_locked_out(user_id: str) -> bool:
    """
    Check if a user is currently in a lockout period.

    Automatically clears expired lockouts.
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT locked_until FROM lockouts WHERE user_id = ?", (user_id,)
        ).fetchone()
    if row is None or row["locked_until"] is None:
        return False
    locked_until = datetime.datetime.fromisoformat(row["locked_until"])
    if datetime.datetime.utcnow() < locked_until:
        remaining = (locked_until - datetime.datetime.utcnow()).seconds
        print(f"[SECURITY] Account locked. Try again in {remaining}s.")
        return True
    # Lockout expired – clear it
    clear_failed_attempts(user_id)
    return False


# ─── Statistics ───────────────────────────────────────────────────────────────

def get_statistics() -> Dict[str, Any]:
    """Return a summary dict of system-wide statistics."""
    today = datetime.date.today().isoformat()
    with get_connection() as conn:
        total_users  = conn.execute("SELECT COUNT(*) FROM users WHERE active = 1").fetchone()[0]
        total_logs   = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
        today_total  = conn.execute(
            "SELECT COUNT(*) FROM access_logs WHERE DATE(timestamp) = ?", (today,)
        ).fetchone()[0]
        today_grant  = conn.execute(
            "SELECT COUNT(*) FROM access_logs WHERE DATE(timestamp) = ? AND status = 'GRANTED'",
            (today,)
        ).fetchone()[0]
        today_deny   = conn.execute(
            "SELECT COUNT(*) FROM access_logs WHERE DATE(timestamp) = ? AND status = 'DENIED'",
            (today,)
        ).fetchone()[0]

    success_rate = (today_grant / today_total * 100) if today_total else 0.0
    return {
        "total_users":   total_users,
        "total_logs":    total_logs,
        "today_total":   today_total,
        "today_granted": today_grant,
        "today_denied":  today_deny,
        "success_rate":  round(success_rate, 1),
    }
