import sqlite3
db = sqlite3.connect('cipher.db')
db.row_factory = sqlite3.Row

print("EVENTS:")
res = db.execute("SELECT event_id, source_ip, destination_ip, attack_type, detection_method, reasons FROM security_events WHERE attack_type LIKE '%DOS%' ORDER BY timestamp DESC LIMIT 10").fetchall()
for row in res:
    print(dict(row))

print("\nINCIDENTS:")
res = db.execute("SELECT incident_id, source_ip, destination_ip, attack_categories, first_seen, last_seen FROM incidents WHERE attack_categories LIKE '%DOS%' ORDER BY first_seen DESC LIMIT 10").fetchall()
for row in res:
    print(dict(row))
