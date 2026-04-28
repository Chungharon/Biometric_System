"""
utils.py - Shared helper utilities for the Biometric Authentication System.

Contains:
  - Colour-coded terminal output
  - UUID / ID generation
  - PIN hashing & verification via bcrypt
  - Date/time helpers
  - Liveness-detection helpers (Eye Aspect Ratio)
"""

import os
import sys
import uuid
import datetime
from typing import Optional, Tuple

import bcrypt
import numpy as np

# ─── ANSI Colour Codes ────────────────────────────────────────────────────────

class Colors:
    """ANSI escape codes for terminal colour output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

    @staticmethod
    def supports_color() -> bool:
        """Return True if the terminal supports ANSI colour codes."""
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _col(text: str, *codes: str) -> str:
    """Wrap *text* in ANSI codes if supported, else return plain text."""
    if Colors.supports_color():
        return "".join(codes) + text + Colors.RESET
    return text


# ─── Status Printers ─────────────────────────────────────────────────────────

def print_status(tag: str, message: str) -> None:
    """Print a formatted status line: [TAG] message."""
    tag_map = {
        "ENROLLING":  Colors.CYAN,
        "SCANNING":   Colors.BLUE,
        "GRANTED":    Colors.GREEN,
        "DENIED":     Colors.RED,
        "LOCKOUT":    Colors.RED,
        "DB":         Colors.MAGENTA,
        "SECURITY":   Colors.YELLOW,
        "INFO":       Colors.WHITE,
        "ERROR":      Colors.RED,
        "OK":         Colors.GREEN,
    }
    colour = tag_map.get(tag.upper(), Colors.WHITE)
    bracket = _col(f"[{tag}]", Colors.BOLD, colour)
    print(f"{bracket} {message}")


def banner(title: str, width: int = 60) -> None:
    """Print a decorative banner."""
    line = "─" * width
    print(f"\n{_col(line, Colors.CYAN)}")
    print(_col(f"  {title}".center(width), Colors.BOLD, Colors.CYAN))
    print(f"{_col(line, Colors.CYAN)}\n")


# ─── ID Generation ────────────────────────────────────────────────────────────

def generate_user_id(prefix: str = "USR") -> str:
    """
    Generate a unique user ID with the given prefix.

    Example: 'USR-7f3a1c'
    """
    short = uuid.uuid4().hex[:6].upper()
    return f"{prefix}-{short}"


# ─── PIN / Password Helpers ───────────────────────────────────────────────────

def hash_pin(pin: str) -> str:
    """
    Hash a plain-text PIN using bcrypt.

    Parameters
    ----------
    pin : Plain-text string (typically 4-8 digits).

    Returns
    -------
    UTF-8 bcrypt hash string safe for DB storage.
    """
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pin.encode("utf-8"), salt).decode("utf-8")


def verify_pin(pin: str, hashed: str) -> bool:
    """
    Verify a plain-text PIN against a stored bcrypt hash.

    Returns True if the PIN matches.
    """
    try:
        return bcrypt.checkpw(pin.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ─── Date / Time ──────────────────────────────────────────────────────────────

def now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.datetime.utcnow().isoformat()


def today_iso() -> str:
    """Return today's date in YYYY-MM-DD format."""
    return datetime.date.today().isoformat()


def format_timestamp(iso_str: str) -> str:
    """Convert an ISO timestamp to a human-friendly string."""
    try:
        dt = datetime.datetime.fromisoformat(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso_str


# ─── Liveness Detection (Eye Aspect Ratio) ────────────────────────────────────

def eye_aspect_ratio(eye_landmarks) -> float:
    """
    Compute the Eye Aspect Ratio (EAR) from six (x, y) landmark points.

    EAR = (||p2-p6|| + ||p3-p5||) / (2 * ||p1-p4||)

    A low EAR (~0.25) indicates a blink.

    Parameters
    ----------
    eye_landmarks : sequence of 6 (x, y) tuples (dlib or mediapipe order).

    Returns
    -------
    float EAR value.
    """
    p = [np.array(pt) for pt in eye_landmarks]
    A = np.linalg.norm(p[1] - p[5])
    B = np.linalg.norm(p[2] - p[4])
    C = np.linalg.norm(p[0] - p[3])
    return (A + B) / (2.0 * C + 1e-6)


# ─── Confidence / Distance ────────────────────────────────────────────────────

def distance_to_confidence(distance: float) -> float:
    """
    Convert a face_recognition distance value to a 0–1 confidence score.

    distance 0.0 → confidence 1.0 (perfect match)
    distance 0.6 → confidence 0.4 (at threshold)
    distance ≥ 1.0 → confidence 0.0
    """
    return max(0.0, round(1.0 - distance, 4))


# ─── Miscellaneous ────────────────────────────────────────────────────────────

def validate_role(role: str) -> str:
    """
    Return role if valid, else raise ValueError.

    Valid roles: admin, employee, visitor.
    """
    import config
    role = role.strip().lower()
    if role not in config.VALID_ROLES:
        raise ValueError(
            f"Invalid role '{role}'. Choose from: {config.VALID_ROLES}"
        )
    return role


def clear_screen() -> None:
    """Clear the terminal screen in a cross-platform way."""
    os.system("cls" if os.name == "nt" else "clear")


def prompt(label: str, hidden: bool = False) -> str:
    """
    Prompt the user for input.

    Parameters
    ----------
    label  : The prompt text.
    hidden : If True, hide input (useful for PINs).
    """
    if hidden:
        import getpass
        return getpass.getpass(f"{label}: ").strip()
    return input(f"{label}: ").strip()