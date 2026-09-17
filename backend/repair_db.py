import sqlite3
db = sqlite3.connect('cipher.db')

# Wipe all DOS / DDOS events to clean the slate
res = db.execute("SELECT event_id FROM security_events WHERE attack_type LIKE '%DOS%'").fetchall()

to_delete = [row[0] for row in res]

if to_delete:
    print(f"Deleting {len(to_delete)} DOS/DDOS events")
    placeholders = ",".join("?" * len(to_delete))
    db.execute(f"DELETE FROM security_events WHERE event_id IN ({placeholders})", to_delete)
    
    print("Deleting related DOS/DDOS incidents")
    db.execute("DELETE FROM incidents WHERE attack_categories LIKE '%DOS%'")
    db.commit()
else:
    print("No DOS/DDOS events found.")
