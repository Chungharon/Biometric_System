"""
enrollment.py - User Enrollment Module for the Biometric Authentication System.

Responsibilities:
  - Open the webcam and capture MIN_FACE_SAMPLES – MAX_FACE_SAMPLES frames
    that contain exactly one detected face.
  - Optionally run a liveness blink-detection gate before storing encodings.
  - Persist the 128-d face encodings to the database.
  - Register new user records (name, role, PIN).

Usage (standalone test):
    python enrollment.py
"""

import os
import time
from typing import Optional, List, Tuple

import cv2
import numpy as np

try:
    import face_recognition
    FACE_RECOGNITION_AVAILABLE = True
except ImportError:
    FACE_RECOGNITION_AVAILABLE = False
    print("[WARNING] face_recognition not installed. Enrollment will run in DEMO mode.")

import config
import database
import utils
from utils import print_status, banner, generate_user_id, hash_pin, validate_role, prompt


# ─── Camera Helper ────────────────────────────────────────────────────────────

def _open_camera(index: int = config.CAMERA_INDEX) -> cv2.VideoCapture:
    """
    Open the webcam and set resolution.

    Raises
    ------
    RuntimeError if the camera cannot be opened.
    """
    cap = cv2.VideoCapture(index)
    if not cap.isOpened():
        raise RuntimeError(
            f"Cannot open camera at index {index}. "
            "Check that a webcam is connected and not used by another application."
        )
    cap.set(cv2.CAP_PROP_FRAME_WIDTH,  config.FRAME_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, config.FRAME_HEIGHT)
    # Warm-up: discard the first N frames (camera auto-exposure settling)
    for _ in range(config.CAMERA_WARMUP_FRAMES):
        cap.read()
    return cap


# ─── Liveness Detection ───────────────────────────────────────────────────────

def _detect_blink(frame_gray, face_landmarks: dict) -> bool:
    """
    Return True if the Eye Aspect Ratio indicates a blink in this frame.

    Uses the 'left_eye' and 'right_eye' landmark keys provided by
    face_recognition.face_landmarks().

    Parameters
    ----------
    frame_gray     : Grayscale frame (unused here but kept for extensibility).
    face_landmarks : Dict from face_recognition.face_landmarks().
    """
    left  = face_landmarks.get("left_eye",  [])
    right = face_landmarks.get("right_eye", [])
    if len(left) < 6 or len(right) < 6:
        return False
    ear_l = utils.eye_aspect_ratio(left)
    ear_r = utils.eye_aspect_ratio(right)
    avg_ear = (ear_l + ear_r) / 2.0
    return avg_ear < config.LIVENESS_EYE_BLINK_THRESHOLD


def run_liveness_check(cap: cv2.VideoCapture, timeout: float = 15.0) -> bool:
    """
    Ask the user to blink at least LIVENESS_REQUIRED_BLINKS times within
    *timeout* seconds.  Displays a live preview window.

    Returns True if liveness requirement is satisfied, False otherwise.
    """
    if not FACE_RECOGNITION_AVAILABLE:
        print_status("INFO", "DEMO mode – liveness check skipped.")
        return True

    print_status("ENROLLING", f"Liveness check: please blink {config.LIVENESS_REQUIRED_BLINKS} time(s).")
    blink_count   = 0
    eye_was_open  = True
    start         = time.time()

    while time.time() - start < timeout:
        ret, frame = cap.read()
        if not ret:
            continue

        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        landmarks_list = face_recognition.face_landmarks(rgb)

        display = frame.copy()
        cv2.putText(display, f"Blinks: {blink_count}/{config.LIVENESS_REQUIRED_BLINKS}",
                    (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 255), 2)
        cv2.putText(display, "Please blink to prove you are live",
                    (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 0), 1)
        cv2.imshow("Liveness Check", display)

        if landmarks_list:
            is_blink = _detect_blink(None, landmarks_list[0])
            if is_blink and eye_was_open:
                blink_count += 1
                eye_was_open = False
                print_status("ENROLLING", f"Blink detected! ({blink_count}/{config.LIVENESS_REQUIRED_BLINKS})")
            elif not is_blink:
                eye_was_open = True

        if blink_count >= config.LIVENESS_REQUIRED_BLINKS:
            cv2.destroyWindow("Liveness Check")
            return True

        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    cv2.destroyWindow("Liveness Check")
    return False


# ─── Face Capture ─────────────────────────────────────────────────────────────

def capture_face_encodings(
    user_name: str,
    liveness: bool = True,
) -> Tuple[List, bool]:
    """
    Open the webcam, collect MIN_FACE_SAMPLES valid face encodings,
    and return them as a list of 128-d numpy arrays.

    The live preview window shows:
      - Blue rectangle around the detected face
      - Sample counter
      - Instruction text

    Parameters
    ----------
    user_name : Used only for the window title / display text.
    liveness  : Whether to run the blink-liveness gate first.

    Returns
    -------
    (encodings, success) — encodings is [] on failure.
    """
    if not FACE_RECOGNITION_AVAILABLE:
        print_status("INFO", "DEMO mode – generating synthetic encodings.")
        synthetic = [np.random.rand(128) for _ in range(config.MIN_FACE_SAMPLES)]
        return synthetic, True

    try:
        cap = _open_camera()
    except RuntimeError as exc:
        print_status("ERROR", str(exc))
        return [], False

    # ── Liveness gate ──────────────────────────────────────────────────────
    if liveness:
        passed = run_liveness_check(cap)
        if not passed:
            print_status("DENIED", "Liveness check failed. Enrollment aborted.")
            cap.release()
            cv2.destroyAllWindows()
            return [], False

    # ── Encoding capture loop ──────────────────────────────────────────────
    encodings: List = []
    instructions = [
        "Look directly at the camera",
        "Tilt your head slightly LEFT",
        "Tilt your head slightly RIGHT",
        "Tilt your head slightly UP",
        "Tilt your head slightly DOWN",
        "Smile or change expression",
        "Turn slightly left",
        "Turn slightly right",
        "Look straight again",
        "Final sample - hold still"
    ]
    
    print_status("ENROLLING", f"Capturing face samples for '{user_name}'.")

    while len(encodings) < config.MAX_FACE_SAMPLES:
        ret, frame = cap.read()
        if not ret:
            print_status("ERROR", "Failed to read frame from camera.")
            break

        rgb    = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        locs   = face_recognition.face_locations(rgb, model="hog")
        encs   = face_recognition.face_encodings(rgb, locs)

        display = frame.copy()
        
        # Progress and Instructions
        idx = min(len(encodings), len(instructions) - 1)
        current_instruction = instructions[idx]
        
        status_txt = f"Progress: {len(encodings)}/{config.MIN_FACE_SAMPLES}"
        
        # Overlay UI
        cv2.rectangle(display, (0, 0), (config.FRAME_WIDTH, 80), (0, 0, 0), -1) # Header bg
        cv2.putText(display, f"INSTRUCTION: {current_instruction}",
                    (20, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
        cv2.putText(display, status_txt,
                    (20, 65), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)

        if len(locs) == 1 and encs:
            top, right, bottom, left = locs[0]
            cv2.rectangle(display, (left, top), (right, bottom), (255, 140, 0), 2)
            encodings.append(encs[0])
            print_status("ENROLLING", f"Sample {len(encodings)}: {current_instruction}")
            
            # Flash green rectangle on success
            cv2.rectangle(display, (left-5, top-5), (right+5, bottom+5), (0, 255, 0), 3)
            cv2.imshow("Enrollment", display)
            cv2.waitKey(500) # Short pause to show success and let user move
        elif len(locs) > 1:
            cv2.putText(display, "Multiple faces! Please be alone.",
                        (20, config.FRAME_HEIGHT - 30), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)
        else:
            cv2.putText(display, "Position your face in the frame",
                        (20, config.FRAME_HEIGHT - 30), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)

        cv2.imshow("Enrollment", display)

        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    cap.release()
    cv2.destroyAllWindows()

    if len(encodings) < config.MIN_FACE_SAMPLES:
        print_status("ERROR",
            f"Only {len(encodings)}/{config.MIN_FACE_SAMPLES} samples captured. "
            "Enrollment failed.")
        return [], False

    print_status("ENROLLING", f"{len(encodings)} samples captured successfully.")
    return encodings, True


# ─── Enrollment Workflow ──────────────────────────────────────────────────────

def enroll_user(
    name: str,
    role: str = "visitor",
    user_id: Optional[str] = None,
    pin: Optional[str] = None,
    liveness: bool = True,
) -> Optional[str]:
    """
    Full enrollment pipeline:
      1. Validate inputs
      2. Capture face encodings
      3. Persist user record and encodings to DB

    Parameters
    ----------
    name      : Full display name of the new user.
    role      : 'admin', 'employee', or 'visitor'.
    user_id   : Optional custom ID; auto-generated if None.
    pin       : Plain-text fallback PIN (will be hashed).
    liveness  : Enable liveness blink check.

    Returns
    -------
    The assigned user_id on success, None on failure.
    """
    banner("USER ENROLLMENT")

    # Validate role
    try:
        role = validate_role(role)
    except ValueError as exc:
        print_status("ERROR", str(exc))
        return None

    # Generate or validate ID
    uid = user_id or generate_user_id()
    print_status("ENROLLING", f"Starting enrollment for '{name}' | ID: {uid} | Role: {role}")

    # Capture face data
    encodings, ok = capture_face_encodings(name, liveness=liveness)
    if not ok:
        return None

    # Hash PIN if provided
    pin_hash = hash_pin(pin) if pin else None

    # Write to DB
    try:
        database.initialize_database()
        success = database.add_user(uid, name, role, pin_hash)
        if not success:
            print_status("ERROR", f"User ID '{uid}' already exists. Use a different ID.")
            return None
        for enc in encodings:
            database.save_encoding(uid, enc)
        print_status("OK", f"Enrollment complete! User '{name}' registered with ID '{uid}'.")
        return uid
    except Exception as exc:
        print_status("ERROR", f"Database error during enrollment: {exc}")
        return None


# ─── Standalone CLI ───────────────────────────────────────────────────────────

def interactive_enroll() -> None:
    """
    Interactive CLI enrollment – prompts the operator for all required fields.
    """
    database.initialize_database()
    banner("Interactive Enrollment")

    name  = prompt("Full Name")
    if not name:
        print_status("ERROR", "Name cannot be empty.")
        return

    role  = prompt("Role (admin / employee / visitor)") or config.DEFAULT_ROLE
    uid   = prompt("Custom User ID (leave blank to auto-generate)") or None
    pin   = prompt("Fallback PIN (leave blank to skip)", hidden=True) or None

    enroll_user(name=name, role=role, user_id=uid, pin=pin)


if __name__ == "__main__":
    interactive_enroll()