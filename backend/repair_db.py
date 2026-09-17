import sqlite3
db = sqlite3.connect('cipher.db')

print("Deleting all DOS/DDOS incidents")
db.execute("DELETE FROM incidents WHERE attack_categories LIKE '%DOS%'")
db.commit()
