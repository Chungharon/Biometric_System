# Biometric Authentication System

A production-ready Python biometric authentication system featuring real-time facial recognition, anti-spoofing, secure PIN fallback, SQLite persistence, and a full CLI admin dashboard.

---

## Features

| Module | What it does |
|---|---|
| `enrollment.py` | Webcam capture (5–10 frames), liveness blink check, 128-d encoding storage |
| `authentication.py` | Real-time face matching, confidence threshold, anti-spoof heuristic, lockout |
| `database.py` | SQLite CRUD — users, encodings, access logs, lockout tracking |
| `access_log.py` | Filtered log viewer, suspicious-activity flagging, daily/weekly CSV reports |
| `admin.py` | Interactive CLI dashboard — register, deactivate, delete, unlock, stats |
| `utils.py` | bcrypt PIN hashing, ANSI colour output, EAR liveness helper, ID generator |
| `config.py` | All tuneable settings in one place |

---

## Quick Start

### 1 — Prerequisites

```bash
# macOS
brew install cmake

# Ubuntu / Debian
sudo apt-get install -y cmake build-essential libopenblas-dev liblapack-dev

# Windows
# Download cmake from https://cmake.org/download/ and add to PATH
```

### 2 — Create & activate virtual environment

```bash
cd biometric_system
python3 -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

### 3 — Install dependencies

```bash
pip install -r requirements.txt
# face_recognition + dlib (may take a few minutes to compile)
pip install dlib face_recognition
```

### 4 — Run

```bash
python main.py
```

---

## Main Menu

```[1]  Authenticate (face scan)
[2]  Enroll new user
[3]  Admin dashboard
[4]  View access logs
[5]  Generate daily report
[6]  System statistics
[7]  PIN fallback authentication
[q]  Quit
```

---

## Configuration (`config.py`)

| Setting | Default | Description |
|---|---|---|
| `FACE_TOLERANCE` | `0.6` | Max L2 distance for a positive match (lower = stricter) |
| `MIN_FACE_SAMPLES` | `5` | Frames captured during enrollment |
| `MAX_FACE_SAMPLES` | `10` | Maximum enrollment frames |
| `LOCKOUT_ATTEMPTS` | `3` | Failed attempts before temporary lockout |
| `LOCKOUT_DURATION` | `300` | Lockout time in seconds (5 min) |
| `CAMERA_INDEX` | `0` | Webcam index |
| `DB_PATH` | `data/users.db` | SQLite database path |
| `LOG_PATH` | `data/access_logs.csv` | CSV log export path |

---

## File Structure

```biometric_system/
├── main.py               # Entry point + top-level menu
├── enrollment.py         # Face capture, liveness, registration
├── authentication.py     # Face matching, access control, anti-spoof
├── database.py           # SQLite CRUD + lockout management
├── access_log.py         # Logging, reports, suspicious-activity flags
├── admin.py              # CLI admin dashboard
├── utils.py              # bcrypt, ANSI colours, EAR, ID generator
├── config.py             # All settings
├── requirements.txt
├── .gitignore
├── __init__.py
└── data/
    ├── users.db          # SQLite database (auto-created)
    ├── access_logs.csv   # Exported logs
    ├── encodings/        # Per-user .pkl encoding sidecars
    └── reports/          # Generated daily/weekly CSV reports
```

---

## Security Features

- **Anti-spoofing** — Laplacian variance heuristic detects flat/printed face images
- **Liveness detection** — Eye Aspect Ratio (EAR) blink gate during enrollment
- **Confidence threshold** — Face distance must be ≤ `FACE_TOLERANCE` to grant access
- **Lockout** — ≥ 3 failed attempts triggers a 5-minute account lockout
- **PIN fallback** — bcrypt-hashed PIN (cost=12) stored for offline/PIN auth
- **Soft-delete** — Users are deactivated, not erased, preserving audit history

---

## Roles

| Role | Description |
|---|---|
| `admin` | Full system access |
| `employee` | Standard access |
| `visitor` | Restricted / guest access |

---

## Environment Variables

| Variable | Effect |
|---|---|
| `ADMIN_PIN` | If set, admin dashboard requires this PIN at startup |
| `CAMERA_IDX` | Override `CAMERA_INDEX` in config at runtime |

---

## Demo / No-Camera Mode

If `face_recognition` is not installed (e.g. no camera on CI), all modules
fall back to **DEMO mode** — synthetic encodings are used and auth always
returns GRANTED. This lets you test the database, logging, and admin flows
without hardware.

---

## Running Individual Modules

```bash
python enrollment.py       # Interactive CLI enrolment
python authentication.py   # Immediate face-scan sessione
python admin.py            # Admin dashboard only
python access_log.py       # Log viewer / report generator
```

---

## Generating Reports

From the admin dashboard (`[3] → Reports`) or directly:

```bash
python -c "import access_log, database; database.initialize_database(); access_log.generate_daily_report()"
python -c "import access_log, database; database.initialize_database(); access_log.generate_weekly_report()"
```

Reports are saved as CSV files in `data/reports/`.

---

## Platform Notes

| OS | Notes |
|---|---|
| **macOS** | `brew install cmake` required before `pip install dlib` |
| **Ubuntu** | `apt-get install cmake build-essential` required |
| **Windows** | CMake installer + Visual C++ Build Tools required for dlib |

---

## License

MIT — free to use, modify, and distribute.
