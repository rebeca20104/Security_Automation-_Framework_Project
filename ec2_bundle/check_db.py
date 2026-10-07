import sqlite3
db = sqlite3.connect("output/security.db")
print("INDICATORS:")
for r in db.execute("SELECT indicator,type,malicious,verdict FROM indicators ORDER BY rowid DESC LIMIT 5"):
    print(r)
print("NOTIFS:")
for r in db.execute("SELECT alert_id,indicator,status FROM notifications ORDER BY sent_at DESC LIMIT 5"):
    print(r)
