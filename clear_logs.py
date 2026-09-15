"""
CIPHER IDPS — Log Cleaner
Run this file to wipe all recorded events, incidents, and blocklist entries.

Usage:
    python clear_logs.py
"""

import sqlite3
import os
import sys

# Fix Windows terminal encoding
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DB_PATH = os.path.join(os.path.dirname(__file__), "backend", "cipher.db")

TABLES_TO_CLEAR = [
    "incident_events",   # Must be cleared before incidents (foreign key)
    "incidents",
    "security_events",
    "ip_blocklist",
]

def clear_logs():
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database not found at: {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    print("=" * 45)
    print("  CIPHER IDPS -- Clearing All Logs")
    print("=" * 45)

    for table in TABLES_TO_CLEAR:
        try:
            cur.execute(f"DELETE FROM {table}")
            deleted = cur.rowcount
            print(f"  [OK] {table:<22} -> {deleted} rows deleted")
        except Exception as e:
            print(f"  [!!] {table:<22} -> ERROR: {e}")

    conn.commit()

    # Show final counts
    print()
    print("  Final row counts:")
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    for (t,) in cur.fetchall():
        cur.execute(f"SELECT COUNT(*) FROM {t}")
        count = cur.fetchone()[0]
        print(f"    {t:<25} = {count}")

    conn.close()
    print()
    print("  Done. Database is clean.")
    print("=" * 45)


if __name__ == "__main__":
    clear_logs()
