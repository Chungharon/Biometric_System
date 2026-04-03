"""
access_log.py - Logging & Reporting Module for the Biometric Authentication System.

Responsibilities:
  - Query and display access logs with filters (user / date / role / status)
  - Detect repeated failed attempts and flag suspicious activity
  - Generate daily / weekly summary reports (CSV + console)
  - Export logs on demand
"""

import os
import csv
import datetime
from typing import Optional, List, Dict, Any

import config
import database
import utils
from utils import print_status, banner, format_timestamp, today_iso


# ─── Flagging / Suspicious Activity ─────────────────────────────────────────

def flag_suspicious_activity(window_minutes: int = 10) -> List[Dict[str, Any]]:
    """
    Scan recent access logs for users with more than LOCKOUT_ATTEMPTS
    consecutive DENIED entries within *window_minutes*.

    Parameters
    ----------
    window_minutes : Time window to inspect (default 10 minutes).

    Returns
    -------
    List of dicts: {user_id, name, denied_count, first_seen, last_seen}
    """
    cutoff = (
        datetime.datetime.utcnow() - datetime.timedelta(minutes=window_minutes)
    ).isoformat()

    with database.get_connection() as conn:
        rows = conn.execute(
            """
            SELECT user_id, name,
                   COUNT(*) AS denied_count,
                   MIN(timestamp) AS first_seen,
                   MAX(timestamp) AS last_seen
            FROM access_logs
            WHERE status = 'DENIED'
              AND timestamp >= ?
              AND user_id IS NOT NULL
            GROUP BY user_id
            HAVING denied_count >= ?
            ORDER BY denied_count DESC
            """,
            (cutoff, config.LOCKOUT_ATTEMPTS),
        ).fetchall()

    flagged = [dict(r) for r in rows]
    if flagged:
        print_status("SECURITY",
            f"{len(flagged)} suspicious account(s) detected in the last {window_minutes} min:")
        for entry in flagged:
            print_status("SECURITY",
                f"  {entry['name']} ({entry['user_id']}) — "
                f"{entry['denied_count']} failures  "
                f"[{format_timestamp(entry['first_seen'])} → "
                f"{format_timestamp(entry['last_seen'])}]")
    return flagged


# ─── Log Display ─────────────────────────────────────────────────────────────

def _row_to_line(log: Dict[str, Any], width: int = 100) -> str:
    """Format a single log entry as a fixed-width terminal line."""
    ts   = format_timestamp(log.get("timestamp", ""))
    uid  = (log.get("user_id") or "Unknown")[:12].ljust(12)
    name = (log.get("name")    or "Unknown")[:18].ljust(18)
    role = (log.get("role")    or "—")[:10].ljust(10)
    loc  = (log.get("location") or "")[:16].ljust(16)
    st   = log.get("status", "")
    conf = log.get("confidence")
    conf_str = f"{conf*100:5.1f}%" if conf is not None else "  N/A "
    return f"{ts}  {uid}  {name}  {role}  {loc}  {st:<7}  {conf_str}"


HEADER = (
    f"{'Timestamp':<26}  {'UserID':<12}  {'Name':<18}  "
    f"{'Role':<10}  {'Location':<16}  {'Status':<7}  {'Conf':>6}"
)
DIVIDER = "─" * len(HEADER)


def display_logs(
    user_id: Optional[str] = None,
    date:    Optional[str] = None,
    role:    Optional[str] = None,
    status:  Optional[str] = None,
    limit:   int = 50,
) -> None:
    """
    Print a formatted access-log table to the terminal.

    Parameters
    ----------
    user_id : Filter by exact user_id.
    date    : Filter by date string 'YYYY-MM-DD'.
    role    : Filter by role ('admin', 'employee', 'visitor').
    status  : Filter by status ('GRANTED' or 'DENIED').
    limit   : Max rows to display.
    """
    logs = database.get_access_logs(user_id=user_id, date=date, role=role, limit=limit)

    # Apply status filter (not directly in DB query to keep it simple)
    if status:
        logs = [l for l in logs if l.get("status") == status.upper()]

    banner(f"Access Logs  ({len(logs)} entries)")
    print(HEADER)
    print(DIVIDER)

    if not logs:
        print("  — No records found for the given filters —")
    else:
        for log in logs:
            line = _row_to_line(log)
            if log.get("status") == "GRANTED":
                print(utils._col(line, utils.Colors.GREEN))
            else:
                print(utils._col(line, utils.Colors.RED))

    print(DIVIDER)


# ─── Report Generation ────────────────────────────────────────────────────────

def _compute_report_stats(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute aggregate statistics from a list of log records."""
    total    = len(logs)
    granted  = sum(1 for l in logs if l.get("status") == "GRANTED")
    denied   = total - granted
    rate     = round(granted / total * 100, 1) if total else 0.0

    by_role: Dict[str, int] = {}
    for l in logs:
        r = l.get("role") or "unknown"
        by_role[r] = by_role.get(r, 0) + 1

    avg_conf_list = [l["confidence"] for l in logs
                     if l.get("confidence") is not None and l.get("status") == "GRANTED"]
    avg_conf = round(sum(avg_conf_list) / len(avg_conf_list) * 100, 1) if avg_conf_list else 0.0

    return {
        "total":        total,
        "granted":      granted,
        "denied":       denied,
        "success_rate": rate,
        "by_role":      by_role,
        "avg_conf_pct": avg_conf,
    }


def _print_report(title: str, stats: Dict[str, Any], period_label: str) -> None:
    """Print a report summary block to the terminal."""
    banner(title)
    print_status("INFO", f"Period     : {period_label}")
    print_status("INFO", f"Total Auths: {stats['total']}")
    print_status("GRANTED", f"Granted    : {stats['granted']}")
    print_status("DENIED",  f"Denied     : {stats['denied']}")
    print_status("INFO",    f"Success    : {stats['success_rate']}%")
    print_status("INFO",    f"Avg Conf.  : {stats['avg_conf_pct']}%")
    if stats["by_role"]:
        print_status("INFO", "By Role    :")
        for role, count in stats["by_role"].items():
            print(f"             {role:<12}: {count}")


def generate_daily_report(date: Optional[str] = None) -> str:
    """
    Generate a daily access report for *date* (ISO 'YYYY-MM-DD').

    Defaults to today if date is not provided.
    Saves a CSV to REPORT_DIR and prints a summary to the terminal.

    Returns
    -------
    Path to the generated CSV file.
    """
    date = date or today_iso()
    logs = database.get_access_logs(date=date, limit=100_000)
    stats = _compute_report_stats(logs)
    _print_report("Daily Access Report", stats, date)

    filepath = os.path.join(config.REPORT_DIR, f"daily_{date}.csv")
    _write_report_csv(filepath, logs)
    print_status("OK", f"Daily report saved to: {filepath}")
    return filepath


def generate_weekly_report(end_date: Optional[str] = None) -> str:
    """
    Generate a weekly access report for the 7-day window ending on *end_date*.

    Defaults to today if end_date is not provided.
    Saves a CSV to REPORT_DIR and prints a summary.

    Returns
    -------
    Path to the generated CSV file.
    """
    end   = datetime.date.fromisoformat(end_date or today_iso())
    start = end - datetime.timedelta(days=6)

    all_logs: List[Dict[str, Any]] = []
    for i in range(7):
        day  = (start + datetime.timedelta(days=i)).isoformat()
        all_logs.extend(database.get_access_logs(date=day, limit=100_000))

    label = f"{start.isoformat()} → {end.isoformat()}"
    stats = _compute_report_stats(all_logs)
    _print_report("Weekly Access Report", stats, label)

    filepath = os.path.join(config.REPORT_DIR, f"weekly_{start}_{end}.csv")
    _write_report_csv(filepath, all_logs)
    print_status("OK", f"Weekly report saved to: {filepath}")
    return filepath


def _write_report_csv(filepath: str, logs: List[Dict[str, Any]]) -> None:
    """Write a list of log records to a CSV file."""
    if not logs:
        print_status("INFO", "No log entries to write.")
        return
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)


# ─── Export ───────────────────────────────────────────────────────────────────

def export_all_logs() -> str:
    """
    Export the complete access_logs table to LOG_PATH (CSV).

    Returns the output file path.
    """
    path = database.export_logs_to_csv(config.LOG_PATH)
    return path


# ─── Standalone CLI ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    database.initialize_database()
    banner("Access Log Viewer")
    choice = input(
        "Options:\n"
        "  1) View today's logs\n"
        "  2) Daily report\n"
        "  3) Weekly report\n"
        "  4) Flag suspicious activity\n"
        "  5) Export all logs to CSV\n"
        "Choice: "
    ).strip()

    if choice == "1":
        display_logs(date=today_iso())
    elif choice == "2":
        generate_daily_report()
    elif choice == "3":
        generate_weekly_report()
    elif choice == "4":
        flag_suspicious_activity()
    elif choice == "5":
        export_all_logs()
    else:
        print("Invalid choice.")
