"""
authentication.py - Face Matching & Access Control Module.

Pipeline
--------
1. Load all active face encodings from the database.
2. Open the webcam and read frames.
3. Detect faces in each frame using face_recognition.
4. Compare live encoding against stored encodings.
5. If best match distance ≤ FACE_TOLERANCE → ACCESS GRANTED.
6. Check for account lockout, log every attempt, update lockout state.

Anti-spoofing hint
------------------
A basic photo-print detection heuristic is applied: the standard deviation
of the Laplacian (a measure of image sharpness / texture variance) is used
to flag excessively flat / blurry regions that may indicate a printed photo
held in front of the camera.

Usage (standalone):
    python authentication.py
"""

import time
import datetime
from typing import Optional, Dict, List, Tuple, Any

import cv2
import numpy as np

try:
    import face_recognition
    FACE_RECOGNITION_AVAILABLE = True
except ImportError:
    FACE_RECOGNITION_AVAILABLE = False
    print("[WARNING] face_recognition not installed – running in DEMO mode.")

import config
import database
import utils
from utils import print_status, banner, distance_to_confidence


# ─── Anti-Spoofing ────────────────────────────────────────────────────────────

def _laplacian_variance(face_region: np.ndarray) -> float:
    """
    Compute the variance of the Laplacian for a face crop.

    A low value (< ~80) suggests the region lacks natural texture depth,
    which may indicate a printed photograph.

    Parameters
    ----------
    face_region : BGR numpy array of the cropped face.

    Returns
    -------
    float variance score.
    """
    gray = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY)
    lap  = cv2.Laplacian(gray, cv2.CV_64F)
    return float(lap.var())


def is_likely_spoof(face_region: np.ndarray, threshold: float = 80.0) -> bool:
    """
    Return True if the face region appears to be a flat / printed image.

    Parameters
    ----------
    face_region : BGR crop of the detected face.
    threshold   : Laplacian variance below this → flagged as spoof.
    """
    score = _laplacian_variance(face_region)
    if score < threshold:
        print_status("SECURITY",
            f"Low texture variance ({score:.1f}) – possible photo spoof detected.")
        return True
    return False


# ─── Encoding Loader ─────────────────────────────────────────────────────────

def load_known_encodings() -> Tuple[List, List[str]]:
    """
    Load all active face encodings from the database.

    Returns
    -------
    (all_encodings, all_user_ids) — parallel lists.
    Each user may contribute multiple encodings (one per sample frame).
    """
    enc_map = database.load_all_encodings()   # {user_id: [enc, enc, ...]}
    all_encodings: List[np.ndarray] = []
    all_user_ids:  List[str]        = []
    for uid, encs in enc_map.items():
        for enc in encs:
            all_encodings.append(enc)
            all_user_ids.append(uid)
    print_status("INFO",
        f"Loaded {len(all_encodings)} encoding(s) for {len(enc_map)} user(s).")
    return all_encodings, all_user_ids


# ─── Core Matching Logic ──────────────────────────────────────────────────────

def match_face(
    live_encoding: np.ndarray,
    known_encodings: List[np.ndarray],
    known_ids:       List[str],
    tolerance:       float = config.FACE_TOLERANCE,
) -> Tuple[Optional[str], float]:
    """
    Compare a live encoding against all stored encodings.

    Strategy: compute L2 distances to every stored encoding; pick the
    stored encoding with the smallest distance.  If that distance is within
    *tolerance* the user is identified.

    Parameters
    ----------
    live_encoding    : 128-d numpy array from the webcam frame.
    known_encodings  : List of 128-d arrays.
    known_ids        : Parallel list of user_id strings.
    tolerance        : Maximum distance for a positive match.

    Returns
    -------
    (user_id, confidence) — user_id is None if no match found.
    confidence is in [0, 1]; higher is better.
    """
    if not known_encodings:
        return None, 0.0

    distances = face_recognition.face_distance(known_encodings, live_encoding)
    best_idx  = int(np.argmin(distances))
    best_dist = float(distances[best_idx])
    confidence = distance_to_confidence(best_dist)

    if best_dist <= tolerance:
        return known_ids[best_idx], confidence
    return None, confidence


# ─── Authentication Result ────────────────────────────────────────────────────

def _build_result(
    status: str,
    user_id: Optional[str],
    user:    Optional[Dict[str, Any]],
    confidence: float,
    location: str,
) -> Dict[str, Any]:
    """Create a standardised authentication result dictionary."""
    return {
        "status":     status,                 # 'GRANTED' or 'DENIED'
        "user_id":    user_id,
        "name":       user["name"] if user else "Unknown",
        "role":       user["role"] if user else None,
        "confidence": round(confidence, 4),
        "timestamp":  utils.now_iso(),
        "location":   location,
    }


# ─── Single-Frame Authentication ─────────────────────────────────────────────

def authenticate_frame(
    frame:           np.ndarray,
    known_encodings: List[np.ndarray],
    known_ids:       List[str],
    location:        str = "Main Entrance",
    anti_spoof:      bool = True,
) -> Optional[Dict[str, Any]]:
    """
    Attempt to authenticate one BGR frame from the webcam.

    Returns a result dict (see _build_result) or None if no face is found.

    Parameters
    ----------
    frame            : BGR numpy array.
    known_encodings  : Pre-loaded known encodings.
    known_ids        : Parallel user_id list.
    location         : Access-point label for the log.
    anti_spoof       : Whether to run the spoof heuristic.
    """
    rgb   = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    locs  = face_recognition.face_locations(rgb, model="hog")
    encs  = face_recognition.face_encodings(rgb, locs)

    if not locs or not encs:
        return None   # No face detected in this frame

    # Use the first detected face only
    top, right, bottom, left = locs[0]
    live_enc   = encs[0]
    face_crop  = frame[top:bottom, left:right]

    # Anti-spoofing check
    if anti_spoof and face_crop.size > 0 and is_likely_spoof(face_crop):
        result = _build_result("DENIED", None, None, 0.0, location)
        result["reason"] = "Spoof detected"
        database.log_access(None, "Spoof Attempt", "DENIED", 0.0, location)
        return result

    # Face matching
    user_id, confidence = match_face(live_enc, known_encodings, known_ids)

    if user_id is None:
        result = _build_result("DENIED", None, None, confidence, location)
        database.log_access(None, "Unknown", "DENIED", confidence, location)
        return result

    # Lockout check
    if database.is_locked_out(user_id):
        user = database.get_user(user_id)
        result = _build_result("DENIED", user_id, user, confidence, location)
        result["reason"] = "Account locked"
        database.log_access(user_id, user["name"] if user else "?",
                            "DENIED", confidence, location)
        return result

    # Account active?
    user = database.get_user(user_id)
    if not user or not user["active"]:
        result = _build_result("DENIED", user_id, user, confidence, location)
        result["reason"] = "Account inactive"
        database.log_access(user_id, user["name"] if user else "?",
                            "DENIED", confidence, location)
        return result

    # SUCCESS
    database.clear_failed_attempts(user_id)
    database.log_access(user_id, user["name"], "GRANTED", confidence, location)
    return _build_result("GRANTED", user_id, user, confidence, location)


def _handle_denied(result: Dict[str, Any]) -> None:
    """Record a failed attempt and manage lockout counter."""
    uid = result.get("user_id")
    if uid:
        attempts = database.record_failed_attempt(uid)
        remaining = config.LOCKOUT_ATTEMPTS - attempts
        if remaining > 0:
            print_status("SECURITY",
                f"Failed attempt #{attempts} for '{result['name']}'. "
                f"{remaining} attempt(s) remaining before lockout.")


# ─── Live Authentication Session ─────────────────────────────────────────────

def run_authentication_session(
    location:   str  = "Main Entrance",
    anti_spoof: bool = True,
    timeout:    int  = 30,
) -> Optional[Dict[str, Any]]:
    """
    Open the webcam and scan continuously until a face is authenticated
    or *timeout* seconds have elapsed.

    The preview window shows:
      - Green box + name  → GRANTED
      - Red box + DENIED  → DENIED
      - Confidence score

    Parameters
    ----------
    location    : Access-point label.
    anti_spoof  : Enable photo-spoof detection.
    timeout     : Seconds to scan before giving up.

    Returns
    -------
    The final authentication result dict, or None on timeout / no camera.
    """
    if not FACE_RECOGNITION_AVAILABLE:
        # DEMO mode: simulate a successful auth for user testing
        print_status("INFO", "DEMO mode – simulating GRANTED response.")
        time.sleep(1)
        return {"status": "GRANTED", "name": "Demo User", "role": "visitor",
                "confidence": 0.95, "user_id": "DEMO-001",
                "timestamp": utils.now_iso(), "location": location}

    database.initialize_database()
    known_encodings, known_ids = load_known_encodings()

    if not known_encodings:
        print_status("ERROR", "No enrolled users found. Please enroll users first.")
        return None

    try:
        cap = cv2.VideoCapture(config.CAMERA_INDEX)
        if not cap.isOpened():
            raise RuntimeError("Cannot open camera.")
        cap.set(cv2.CAP_PROP_FRAME_WIDTH,  config.FRAME_WIDTH)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, config.FRAME_HEIGHT)
    except RuntimeError as exc:
        print_status("ERROR", str(exc))
        return None

    banner("BIOMETRIC SCAN")
    print_status("SCANNING", f"Location: {location}  |  Timeout: {timeout}s  |  Press Q to quit")

    start    = time.time()
    result   = None
    final    = None

    while time.time() - start < timeout:
        ret, frame = cap.read()
        if not ret:
            continue

        elapsed  = time.time() - start
        display  = frame.copy()
        rgb      = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        locs     = face_recognition.face_locations(rgb, model="hog")

        # Draw face rectangles while scanning
        for (top, right, bottom, left) in locs:
            cv2.rectangle(display, (left, top), (right, bottom), (0, 140, 255), 2)

        # Attempt auth every frame
        if locs:
            result = authenticate_frame(
                frame, known_encodings, known_ids, location, anti_spoof
            )
            if result:
                if result["status"] == "GRANTED":
                    colour   = (0, 255, 0)
                    label    = f"GRANTED  {result['name']} ({result['confidence']*100:.1f}%)"
                    final    = result
                else:
                    colour = (0, 0, 255)
                    label  = f"DENIED  ({result.get('reason', 'Unknown face')})"
                    _handle_denied(result)

                top, right, bottom, left = locs[0]
                cv2.rectangle(display, (left, top), (right, bottom), colour, 2)
                cv2.putText(display, label, (left, top - 10),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, colour, 2)

                # Show result for 2 seconds then exit
                cv2.imshow("Biometric Scan", display)
                cv2.waitKey(2000)
                break

        # HUD overlay
        cv2.putText(display, f"[SCANNING] {location}",
                    (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 200, 255), 2)
        cv2.putText(display, f"Time: {elapsed:.1f}s / {timeout}s",
                    (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (200, 200, 200), 1)
        cv2.imshow("Biometric Scan", display)

        if cv2.waitKey(1) & 0xFF == ord("q"):
            print_status("INFO", "Scan cancelled by operator.")
            break

    cap.release()
    cv2.destroyAllWindows()

    if final is None and result is None:
        print_status("DENIED", "Timeout – no face authenticated.")

    if final:
        _print_result(final)
    elif result:
        _print_result(result)

    return final or result


# ─── PIN Fallback ─────────────────────────────────────────────────────────────

def authenticate_with_pin(user_id: str, location: str = "Main Entrance") -> Dict[str, Any]:
    """
    Fallback PIN authentication for a known user ID.

    Parameters
    ----------
    user_id  : The user's registered ID.
    location : Access-point label for logging.

    Returns
    -------
    Authentication result dict.
    """
    database.initialize_database()

    if database.is_locked_out(user_id):
        result = _build_result("DENIED", user_id, database.get_user(user_id), 0.0, location)
        result["reason"] = "Account locked"
        database.log_access(user_id, "?", "DENIED", 0.0, location, method="pin")
        _print_result(result)
        return result

    user = database.get_user(user_id)
    if not user:
        print_status("ERROR", f"User '{user_id}' not found.")
        return _build_result("DENIED", user_id, None, 0.0, location)

    if not user["pin_hash"]:
        print_status("ERROR", "No PIN registered for this user.")
        return _build_result("DENIED", user_id, user, 0.0, location)

    pin = utils.prompt("Enter PIN", hidden=True)
    if utils.verify_pin(pin, user["pin_hash"]):
        database.clear_failed_attempts(user_id)
        database.log_access(user_id, user["name"], "GRANTED", 1.0, location, method="pin")
        result = _build_result("GRANTED", user_id, user, 1.0, location)
    else:
        database.record_failed_attempt(user_id)
        database.log_access(user_id, user["name"], "DENIED", 0.0, location, method="pin")
        result = _build_result("DENIED", user_id, user, 0.0, location)
        result["reason"] = "Incorrect PIN"

    _print_result(result)
    return result


# ─── Pretty Printer ───────────────────────────────────────────────────────────

def _print_result(result: Dict[str, Any]) -> None:
    """Print a formatted authentication result to the terminal."""
    status = result["status"]
    tag    = "GRANTED" if status == "GRANTED" else "DENIED"
    banner(f"ACCESS {status}")
    print_status(tag,   f"User    : {result['name']}")
    print_status("INFO", f"ID      : {result.get('user_id', 'N/A')}")
    print_status("INFO", f"Role    : {result.get('role', 'N/A')}")
    print_status("INFO", f"Conf.   : {result['confidence']*100:.1f}%")
    print_status("INFO", f"Time    : {utils.format_timestamp(result['timestamp'])}")
    print_status("INFO", f"Location: {result['location']}")
    if "reason" in result:
        print_status("SECURITY", f"Reason  : {result['reason']}")


# ─── Standalone CLI ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    run_authentication_session()