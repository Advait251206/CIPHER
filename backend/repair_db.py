import sqlite3
db = sqlite3.connect('cipher.db')

# Find false positive events
res = db.execute("SELECT event_id, destination_ip FROM security_events WHERE attack_type LIKE '%DOS%'").fetchall()

import ipaddress
def is_broadcast_or_multicast(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_multicast:
            return True
        if ip.version == 4 and (str(ip) == "255.255.255.255" or ip.exploded.endswith(".255")):
            return True
    except ValueError:
        pass
    return False

to_delete = []
for event_id, dst_ip in res:
    if is_broadcast_or_multicast(dst_ip):
        to_delete.append(event_id)

if to_delete:
    print(f"Deleting {len(to_delete)} false positive events")
    placeholders = ",".join("?" * len(to_delete))
    db.execute(f"DELETE FROM security_events WHERE event_id IN ({placeholders})", to_delete)
    
    print("Deleting false positive incidents")
    db.execute("DELETE FROM incidents WHERE attack_categories LIKE '%DOS%'")
    db.commit()
else:
    print("No false positives found.")
