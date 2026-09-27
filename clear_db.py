import sqlite3
import os

backend_root = r"d:\Advait251206\College\5th Sem\IDPS\Project\backend"
db_path = os.path.join(backend_root, "cipher.db")

conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("DELETE FROM threat_intel_iocs")
deleted_iocs = cursor.rowcount
cursor.execute("DELETE FROM security_events")
deleted_events = cursor.rowcount
cursor.execute("DELETE FROM ip_blocklist")
deleted_blocks = cursor.rowcount
conn.commit()
conn.close()

print(f"Cleared DB: {deleted_iocs} IOCs, {deleted_events} events, {deleted_blocks} blocklist entries")
