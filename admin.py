"""
admin.py - Admin Dashboard (CLI) for the Biometric Authentication System.

Menu tree
─────────
 1. User Management
    1a. Register new user
    1b. List all users
    1c. Deactivate user
    1d. Delete user (hard)
    1e. Update user info
 2. Access Logs
    2a. View recent logs
    2b. Filter by date / role / status
    2c. Export logs to CSV
 3. Reports
    3a. Daily report
    3b. Weekly report
 4. Security
    4a. Flag suspicious activity
    4b. Manually unlock account
 5. Statistics
 6. Exit
"""

import os
import sys
from typing import Optional

import config
import database
import enrollment
import access_log
import utils
from utils import print_status, banner, prompt, clear_screen, validate_role


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _divider(char: str = "─", width: int = 60) -> str:
    return char * width


def _menu(title: str, options: dict) -> str:
    """Render a numbered menu and return the user's stripped choice."""
    print(f"\n{_divider()}")
    print(f"  {title}")
    print(_divider())
    for key, label in options.items():
        print(f"  [{key}] {label}")
    print(_divider())
    return input("  Choice: ").strip().lower()


def _pause() -> None:
    input("\n  Press ENTER to continue…")


# ─── User Management ─────────────────────────────────────────────────────────

def menu_register_user() -> None:
    """Guided wizard to enroll a new user (delegates to enrollment module)."""
    banner("Register New User")
    name = prompt("Full Name")
    if not name:
        print_status("ERROR", "Name cannot be empty.")
        return

    role    = prompt("Role (admin / employee / visitor)") or config.DEFAULT_ROLE
    uid     = prompt("Custom User ID (blank = auto-generate)") or None
    use_pin = prompt("Set a fallback PIN? (y/n)").lower() == "y"
    pin     = None
    if use_pin:
        pin = prompt("Enter PIN (4-8 digits)", hidden=True)
        confirm = prompt("Confirm PIN", hidden=True)
        if pin != confirm:
            print_status("ERROR", "PINs do not match. Aborting.")
            return

    live = prompt("Enable liveness blink check? (y/n)").lower() != "n"

    assigned_id = enrollment.enroll_user(
        name=name, role=role, user_id=uid, pin=pin, liveness=live
    )
    if assigned_id:
        print_status("OK", f"User registered successfully with ID: {assigned_id}")
    else:
        print_status("ERROR", "Enrollment failed. Please try again.")


def menu_list_users() -> None:
    """Print a table of all registered users."""
    banner("Registered Users")
    users = database.get_all_users(active_only=False)
    if not users:
        print("  No users registered yet.")
        return

    header = f"{'ID':<14}  {'Name':<20}  {'Role':<10}  {'Active':<6}  {'Created'}"
    print(header)
    print(_divider(width=len(header)))
    for u in users:
        active_lbl = utils._col("Yes", utils.Colors.GREEN) if u["active"] else utils._col("No", utils.Colors.RED)
        ts = utils.format_timestamp(u.get("created_at", ""))
        print(f"  {u['user_id']:<12}  {u['name']:<20}  {u['role']:<10}  {active_lbl:<6}  {ts}")
    print(_divider(width=len(header)))
    print(f"  Total: {len(users)} user(s)")


def menu_deactivate_user() -> None:
    """Soft-delete (deactivate) a user account."""
    banner("Deactivate User")
    uid = prompt("Enter User ID to deactivate")
    if not uid:
        return
    user = database.get_user(uid)
    if not user:
        print_status("ERROR", f"User '{uid}' not found.")
        return
    confirm = prompt(f"Deactivate '{user['name']}' ({uid})? (yes/no)")
    if confirm.lower() == "yes":
        database.deactivate_user(uid)
        print_status("OK", f"User '{uid}' has been deactivated.")
    else:
        print_status("INFO", "Operation cancelled.")


def menu_delete_user() -> None:
    """Permanently delete a user and all their encodings."""
    banner("Delete User (Permanent)")
    uid = prompt("Enter User ID to DELETE permanently")
    if not uid:
        return
    user = database.get_user(uid)
    if not user:
        print_status("ERROR", f"User '{uid}' not found.")
        return
    confirm = prompt(
        f"⚠  This will permanently delete '{user['name']}' and all encodings. Type 'DELETE' to confirm"
    )
    if confirm == "DELETE":
        database.delete_user(uid)
        print_status("OK", f"User '{uid}' permanently deleted.")
    else:
        print_status("INFO", "Deletion cancelled.")


def menu_update_user() -> None:
    """Update a user's name or role."""
    banner("Update User Info")
    uid = prompt("Enter User ID to update")
    if not uid:
        return
    user = database.get_user(uid)
    if not user:
        print_status("ERROR", f"User '{uid}' not found.")
        return

    print_status("INFO", f"Current: Name='{user['name']}'  Role='{user['role']}'")
    new_name = prompt(f"New name (blank = keep '{user['name']}')") or None
    new_role = prompt(f"New role (blank = keep '{user['role']}')") or None

    updates = {}
    if new_name:
        updates["name"] = new_name
    if new_role:
        try:
            updates["role"] = validate_role(new_role)
        except ValueError as exc:
            print_status("ERROR", str(exc))
            return

    if updates:
        database.update_user(uid, **updates)
        print_status("OK", "User updated.")
    else:
        print_status("INFO", "No changes made.")


# ─── Access Log Menus ────────────────────────────────────────────────────────

def menu_view_logs() -> None:
    """View recent access logs with optional filters."""
    banner("Access Log Viewer")
    uid    = prompt("Filter by User ID   (blank = all)") or None
    date   = prompt("Filter by Date      (YYYY-MM-DD, blank = all)") or None
    role   = prompt("Filter by Role      (blank = all)") or None
    status = prompt("Filter by Status    (GRANTED / DENIED / blank = all)") or None
    try:
        limit  = int(prompt("Max rows            (default 50)") or "50")
    except ValueError:
        limit = 50

    access_log.display_logs(
        user_id=uid, date=date, role=role, status=status, limit=limit
    )


def menu_export_logs() -> None:
    """Export all access logs to CSV."""
    banner("Export Logs to CSV")
    custom_path = prompt(f"Output path (blank = {config.LOG_PATH})") or None
    path = database.export_logs_to_csv(custom_path)
    print_status("OK", f"Logs exported to: {path}")


# ─── Reports ─────────────────────────────────────────────────────────────────

def menu_daily_report() -> None:
    """Generate and display a daily access report."""
    date = prompt("Date (YYYY-MM-DD, blank = today)") or None
    access_log.generate_daily_report(date)


def menu_weekly_report() -> None:
    """Generate and display a 7-day access report."""
    end = prompt("End date (YYYY-MM-DD, blank = today)") or None
    access_log.generate_weekly_report(end)


# ─── Security ────────────────────────────────────────────────────────────────

def menu_flag_suspicious() -> None:
    """Flag accounts with repeated recent failures."""
    banner("Suspicious Activity Check")
    try:
        window = int(prompt("Look-back window in minutes (default 10)") or "10")
    except ValueError:
        window = 10
    flagged = access_log.flag_suspicious_activity(window_minutes=window)
    if not flagged:
        print_status("OK", "No suspicious activity detected in this window.")


def menu_unlock_account() -> None:
    """Manually clear lockout for a user."""
    banner("Unlock Account")
    uid = prompt("Enter User ID to unlock")
    if not uid:
        return
    user = database.get_user(uid)
    if not user:
        print_status("ERROR", f"User '{uid}' not found.")
        return
    database.clear_failed_attempts(uid)
    print_status("OK", f"Lockout cleared for '{user['name']}' ({uid}).")


# ─── Statistics ───────────────────────────────────────────────────────────────

def menu_statistics() -> None:
    """Display system-wide statistics."""
    banner("System Statistics")
    stats = database.get_statistics()
    print_status("INFO", f"Total Active Users   : {stats['total_users']}")
    print_status("INFO", f"Total Auth Attempts  : {stats['total_logs']}")
    print_status("INFO", f"Attempts Today       : {stats['today_total']}")
    print_status("GRANTED",  f"Granted Today        : {stats['today_granted']}")
    print_status("DENIED",  f"Denied Today         : {stats['today_denied']}")
    print_status("INFO", f"Success Rate Today   : {stats['success_rate']}%")


# ─── Main Dashboard Loop ──────────────────────────────────────────────────────

def run_admin_dashboard() -> None:
    """
    Launch the interactive admin dashboard.

    The operator navigates nested menus to manage users, review logs,
    generate reports, and monitor security events.
    """
    database.initialize_database()

    # Simple admin PIN gate
    banner("Biometric Admin Dashboard")
    admin_pin = os.environ.get("ADMIN_PIN", "")
    if admin_pin:
        entered = prompt("Admin PIN", hidden=True)
        if entered != admin_pin:
            print_status("DENIED", "Incorrect admin PIN. Access refused.")
            sys.exit(1)

    while True:
        choice = _menu(
            "MAIN MENU",
            {
                "1": "User Management",
                "2": "Access Logs",
                "3": "Reports",
                "4": "Security",
                "5": "System Statistics",
                "q": "Exit",
            },
        )

        # ── User Management ────────────────────────────────────────────────
        if choice == "1":
            sub = _menu(
                "USER MANAGEMENT",
                {
                    "a": "Register new user",
                    "b": "List all users",
                    "c": "Deactivate user",
                    "d": "Delete user (permanent)",
                    "e": "Update user info",
                    "b": "Back",
                },
            )
            actions = {
                "a": menu_register_user,
                "b": menu_list_users,
                "c": menu_deactivate_user,
                "d": menu_delete_user,
                "e": menu_update_user,
            }
            if sub in actions:
                actions[sub]()
            _pause()

        # ── Access Logs ────────────────────────────────────────────────────
        elif choice == "2":
            sub = _menu(
                "ACCESS LOGS",
                {
                    "a": "View logs (with filters)",
                    "b": "Export all logs to CSV",
                    "x": "Back",
                },
            )
            if sub == "a":
                menu_view_logs()
            elif sub == "b":
                menu_export_logs()
            _pause()

        # ── Reports ───────────────────────────────────────────────────────
        elif choice == "3":
            sub = _menu(
                "REPORTS",
                {
                    "a": "Daily report",
                    "b": "Weekly report",
                    "x": "Back",
                },
            )
            if sub == "a":
                menu_daily_report()
            elif sub == "b":
                menu_weekly_report()
            _pause()

        # ── Security ──────────────────────────────────────────────────────
        elif choice == "4":
            sub = _menu(
                "SECURITY",
                {
                    "a": "Flag suspicious activity",
                    "b": "Unlock account",
                    "x": "Back",
                },
            )
            if sub == "a":
                menu_flag_suspicious()
            elif sub == "b":
                menu_unlock_account()
            _pause()

        # ── Statistics ────────────────────────────────────────────────────
        elif choice == "5":
            menu_statistics()
            _pause()

        # ── Exit ──────────────────────────────────────────────────────────
        elif choice == "q":
            print_status("INFO", "Goodbye.")
            break
        else:
            print_status("ERROR", f"Unknown option: '{choice}'")


if __name__ == "__main__":
    run_admin_dashboard()
