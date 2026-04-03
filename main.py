"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          BIOMETRIC AUTHENTICATION SYSTEM  —  main.py (entry point)         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  HOW TO RUN                                                                  ║
║  ──────────                                                                  ║
║  1. Install dependencies (once):                                             ║
║       pip install -r requirements.txt                                        ║
║                                                                              ║
║  2. macOS / Linux – cmake + dlib pre-req:                                    ║
║       brew install cmake          # macOS                                    ║
║       sudo apt-get install cmake  # Ubuntu/Debian                            ║
║       pip install dlib face_recognition                                      ║
║                                                                              ║
║  3. Launch the main menu:                                                    ║
║       python main.py                                                         ║
║                                                                              ║
║  4. Individual modules:                                                      ║
║       python enrollment.py       # enroll a user from the command line       ║
║       python authentication.py   # run a face-scan session                   ║
║       python admin.py            # open the admin dashboard                  ║
║       python access_log.py       # view / export logs                        ║
║                                                                              ║
║  OPTIONAL ENVIRONMENT VARIABLES                                              ║
║  ──────────────────────────────                                              ║
║   ADMIN_PIN   — if set, the admin dashboard will require this PIN.           ║
║   CAMERA_IDX  — override the default camera index (default 0).              ║
║                                                                              ║
║  FILE STRUCTURE                                                              ║
║  ──────────────                                                              ║
║   biometric_system/                                                          ║
║   ├── main.py           ← you are here                                       ║
║   ├── enrollment.py     ← face capture & user registration                   ║
║   ├── authentication.py ← real-time face matching & access control           ║
║   ├── database.py       ← SQLite CRUD + lockout management                   ║
║   ├── access_log.py     ← logging, reports, suspicious-activity flags        ║
║   ├── admin.py          ← CLI admin dashboard                                ║
║   ├── utils.py          ← helpers: colours, bcrypt, EAR, EAR                ║
║   ├── config.py         ← all tuneable settings                              ║
║   ├── requirements.txt                                                       ║
║   └── data/                                                                  ║
║       ├── users.db      ← SQLite database (auto-created)                     ║
║       ├── access_logs.csv                                                    ║
║       ├── encodings/    ← .pkl sidecar files per user                        ║
║       └── reports/      ← generated CSV reports                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys

# ── ensure the package root is on sys.path regardless of invocation location ──
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
import database
import utils
from utils import banner, print_status, prompt

# Import sub-systems (lazy camera access – imports are safe even without hw)
import enrollment
import authentication
import admin
import access_log


# ─── Pre-flight Checks ────────────────────────────────────────────────────────

def _check_dependencies() -> bool:
    """
    Verify that critical optional packages are importable and warn if missing.

    Returns True if all critical deps are available, False otherwise.
    """
    ok = True
    deps = {
        "cv2":             "opencv-python",
        "face_recognition":"face_recognition",
        "numpy":           "numpy",
        "bcrypt":          "bcrypt",
    }
    for module, pkg in deps.items():
        try:
            __import__(module)
        except ImportError:
            print_status("ERROR", f"Missing package: '{pkg}'.  Run: pip install {pkg}")
            ok = False
    return ok


def _setup() -> None:
    """Initialise the database and data directories on first run."""
    database.initialize_database()
    print_status("OK", "Database ready.")


# ─── Main Menu ────────────────────────────────────────────────────────────────

MAIN_MENU = {
    "1": "Authenticate (face scan)",
    "2": "Enroll new user",
    "3": "Admin dashboard",
    "4": "View access logs",
    "5": "Generate daily report",
    "6": "System statistics",
    "7": "Run PIN fallback authentication",
    "q": "Quit",
}


def main() -> None:
    """
    Entry point – displays the top-level menu and dispatches to sub-systems.

    All sub-system imports are already done at module level; this function
    only handles routing and error recovery.
    """
    _check_dependencies()   # warn; don't abort – demo mode handles missing deps
    _setup()

    banner("BIOMETRIC AUTHENTICATION SYSTEM  v1.0")
    print_status("INFO", f"Database : {config.DB_PATH}")
    print_status("INFO", f"Camera   : index {config.CAMERA_INDEX}")
    print_status("INFO", f"Tolerance: {config.FACE_TOLERANCE}")
    print()

    while True:
        print(f"\n{'─'*50}")
        for key, label in MAIN_MENU.items():
            print(f"  [{key}]  {label}")
        print(f"{'─'*50}")
        choice = input("  Choice: ").strip().lower()

        # ── 1. Face authentication ────────────────────────────────────────
        if choice == "1":
            location = prompt("Access point / location (default: Main Entrance)") \
                       or "Main Entrance"
            result = authentication.run_authentication_session(location=location)
            if result:
                tag = "GRANTED" if result["status"] == "GRANTED" else "DENIED"
                print_status(tag,
                    f"{result['name']} — {result['status']} "
                    f"(conf {result['confidence']*100:.1f}%)")

        # ── 2. Enroll new user ────────────────────────────────────────────
        elif choice == "2":
            enrollment.interactive_enroll()

        # ── 3. Admin dashboard ────────────────────────────────────────────
        elif choice == "3":
            admin.run_admin_dashboard()

        # ── 4. View logs ──────────────────────────────────────────────────
        elif choice == "4":
            access_log.display_logs(limit=30)

        # ── 5. Daily report ───────────────────────────────────────────────
        elif choice == "5":
            access_log.generate_daily_report()

        # ── 6. Statistics ─────────────────────────────────────────────────
        elif choice == "6":
            admin.menu_statistics()

        # ── 7. PIN fallback ───────────────────────────────────────────────
        elif choice == "7":
            uid = prompt("Enter User ID for PIN authentication")
            if uid:
                loc = prompt("Location (default: Main Entrance)") or "Main Entrance"
                authentication.authenticate_with_pin(uid, location=loc)

        # ── Quit ──────────────────────────────────────────────────────────
        elif choice == "q":
            print_status("INFO", "System shutting down. Goodbye.")
            sys.exit(0)

        else:
            print_status("ERROR", f"Unknown option '{choice}'. Please try again.")


# ─── Entry ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("INFO", "\nInterrupted by user. Exiting.")
        sys.exit(0)
