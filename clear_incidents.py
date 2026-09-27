import sqlite3
import os

backend_root = r"d:\Advait251206\College\5th Sem\IDPS\Project\backend"
db_path = os.path.join(backend_root, "cipher.db")

conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("DELETE FROM incidents")
deleted_inc = cursor.rowcount
cursor.execute("DELETE FROM incident_events")
deleted_inc_ev = cursor.rowcount
conn.commit()
conn.close()

print(f"Cleared DB: {deleted_inc} incidents, {deleted_inc_ev} incident events")
