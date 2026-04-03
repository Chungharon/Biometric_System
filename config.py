"""
config.py - Global configuration settings for the Biometric Authentication System.

Edit values here to tune recognition accuracy, lockout behavior, and file paths.
"""

import os

# ─── Face Recognition ────────────────────────────────────────────────────────
FACE_TOLERANCE = 0.6          # Lower = stricter match (0.0 – 1.0)
MIN_FACE_SAMPLES = 5          # Minimum frames captured during enrollment
MAX_FACE_SAMPLES = 10         # Maximum frames captured during enrollment

# ─── Security / Lockout ──────────────────────────────────────────────────────
LOCKOUT_ATTEMPTS = 3          # Failed attempts before lockout
LOCKOUT_DURATION = 300        # Lockout duration in seconds (5 minutes)
CONFIDENCE_DISPLAY = True     # Show confidence score in output

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DATA_DIR       = os.path.join(BASE_DIR, "data")
DB_PATH        = os.path.join(DATA_DIR, "users.db")
LOG_PATH       = os.path.join(DATA_DIR, "access_logs.csv")
ENCODINGS_DIR  = os.path.join(DATA_DIR, "encodings")

# ─── Camera ──────────────────────────────────────────────────────────────────
CAMERA_INDEX          = 0     # Default webcam index
CAMERA_WARMUP_FRAMES  = 10    # Frames to skip at startup (camera warm-up)
FRAME_WIDTH           = 640
FRAME_HEIGHT          = 480

# ─── Roles ───────────────────────────────────────────────────────────────────
VALID_ROLES = ["admin", "employee", "visitor"]
DEFAULT_ROLE = "visitor"

# ─── Reporting ───────────────────────────────────────────────────────────────
REPORT_DIR = os.path.join(DATA_DIR, "reports")

# ─── Encryption ──────────────────────────────────────────────────────────────
ENCRYPTION_ITERATIONS = 12    # bcrypt cost factor

# ─── Liveness Detection ──────────────────────────────────────────────────────
LIVENESS_EYE_BLINK_THRESHOLD = 0.25   # EAR (Eye Aspect Ratio) blink threshold
LIVENESS_REQUIRED_BLINKS     = 1      # Blinks required to pass liveness check

# Ensure directories exist on import
for _dir in (DATA_DIR, ENCODINGS_DIR, REPORT_DIR):
    os.makedirs(_dir, exist_ok=True)
