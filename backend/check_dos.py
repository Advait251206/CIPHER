import sqlite3
db = sqlite3.connect('cipher.db')
db.row_factory = sqlite3.Row
res = db.execute("SELECT source_ip, destination_ip, protocol, attack_type, detection_method FROM security_events WHERE attack_type LIKE '%DOS%' ORDER BY timestamp DESC LIMIT 10").fetchall()
for row in res:
    print(dict(row))
