import sqlite3, sys
db = sqlite3.connect("output/security.db")
print("== per-agent alert counts ==")
for r in db.execute("SELECT agent, COUNT(*) FROM alerts GROUP BY agent ORDER BY 2 DESC"):
    print(r)
print("== latest indicators (file/ip + verdict) ==")
for r in db.execute("SELECT indicator,type,malicious,verdict FROM indicators ORDER BY rowid DESC LIMIT 10"):
    print(r)
print("== latest notifications ==")
for r in db.execute("SELECT alert_id,indicator,status FROM notifications ORDER BY sent_at DESC LIMIT 10"):
    print(r)
