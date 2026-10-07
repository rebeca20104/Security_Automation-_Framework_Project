"""Clear the local cache: indicators + alerts tables in security.db.

NOTE: this wipes triage history (alerts and indicators), not just VT cache
entries — run it after a key rotation or when stale verdicts mislead triage.
Run from the folder that contains output/security.db.
"""
import sqlite3

db = sqlite3.connect("output/security.db")
db.execute("DELETE FROM indicators")
db.execute("DELETE FROM alerts")
db.commit()
print("cache cleared")
