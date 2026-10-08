#!/usr/bin/env python3
"""SAF — minimal triage console (read-only).

Run on the manager host next to the pipeline:
    streamlit run dashboard.py --server.port 8501 --server.address localhost --server.headless true
View: ssh -L 8501:localhost:8501 ubuntu@<EC2_PUBLIC_IP>  ->  http://localhost:8501
Reads security.db read-only. No secrets in code.
"""
import csv
import io
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import streamlit as st

IST = timezone(timedelta(hours=5, minutes=30))


def to_ist(ts):
    """UTC ISO string ('...+0000', with or without millis) or epoch seconds
    -> 'YYYY-MM-DD HH:MM:SS AM/PM' IST (12-hour)."""
    if not ts and ts != 0:
        return "?"
    try:
        dt = datetime.fromisoformat(ts.replace("+0000", "+00:00")) \
            if isinstance(ts, str) else datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.astimezone(IST).strftime("%Y-%m-%d %I:%M:%S %p")
    except (ValueError, TypeError):
        return str(ts)

HERE = Path(__file__).resolve().parent
DB = HERE / "ec2_bundle" / "output" / "security.db"
if not DB.exists():
    DB = HERE / "output" / "security.db"


def q(sql, args=()):
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


st.set_page_config(page_title="SAF triage console", layout="wide")
st.title("SAF triage console")
st.caption("All times shown in IST (UTC+5:30). Database stores UTC.")

if not DB.exists():
    st.error(f"Database not found: {DB}")
    st.stop()

m1, m2, m3, m4 = st.columns(4)
m1.metric("Alerts processed", q("SELECT COUNT(*) FROM alerts")[0][0])
m2.metric("Indicators enriched", q("SELECT COUNT(*) FROM indicators")[0][0])
m3.metric("Critical verdicts", q("SELECT COUNT(*) FROM indicators WHERE verdict='critical'")[0][0])
m4.metric("Discord sends", q("SELECT COUNT(*) FROM notifications WHERE status='sent'")[0][0])

recent = q("""SELECT agent, MAX(ts) AS last_seen FROM alerts
              WHERE ts >= strftime('%Y-%m-%dT%H:%M:%S', 'now', '-1 day')
              GROUP BY agent ORDER BY MAX(rowid) DESC""")
agents = [r[0] for r in recent]
last_seen = {r[0]: to_ist(r[1]) for r in recent}
if not agents:  # nothing in 24h (e.g. outage) -> fall back to all-time list
    agents = [r[0] for r in q("SELECT DISTINCT agent FROM alerts ORDER BY 1")]
    last_seen = {}
verdicts = [r[0] for r in q("SELECT DISTINCT verdict FROM indicators ORDER BY 1")]
f1, f2, f3 = st.columns(3)
agent_f = f1.selectbox(
    "Agent (active, last 24h)",
    ["(all)"] + agents,
    format_func=lambda a: "(all)" if a == "(all)"
    else (f"{a} — {last_seen[a]}" if a in last_seen else a))
verdict_f = f2.selectbox("Verdict", ["(all)"] + verdicts)
limit = f3.slider("Rows", 10, 200, 50)

st.subheader("Indicators")
rows = q("""SELECT i.indicator, i.type, i.malicious, i.suspicious, i.verdict,
             i.checked_at,
             (SELECT a.file_path FROM alert_indicators ai JOIN alerts a ON a.id = ai.alert_id
              WHERE ai.indicator = i.indicator ORDER BY a.rowid DESC LIMIT 1),
             (SELECT a.agent FROM alert_indicators ai JOIN alerts a ON a.id = ai.alert_id
              WHERE ai.indicator = i.indicator ORDER BY a.rowid DESC LIMIT 1)
             FROM indicators i ORDER BY i.rowid DESC LIMIT 500""")


def _name(r):
    ind, typ, path = r[0], r[1], r[6] or ""
    if typ == "ip" or not path:
        return ind
    base = path.rsplit("/", 1)[-1]
    return f"{base} ({ind[:8]}…{ind[-6:]})"


def _vt_url(r):
    ind, typ = r[0], r[1]
    gui = "file" if typ == "file" else ("ip-address" if typ == "ip" else "domain")
    return f"https://www.virustotal.com/gui/{gui}/{ind}"


view = [{"file": _name(r), "type": r[1], "engines": f"{r[2]} mal / {r[3]} susp",
         "verdict": r[4], "agent": r[7] or "-", "checked_ist": to_ist(r[5]),
         "report": _vt_url(r),
         "_sort_verdict": r[4], "_indicator": r[0]} for r in rows
        if verdict_f in ("(all)", r[4])]
st.dataframe([{k: v for k, v in r.items() if not k.startswith("_")}
              for r in view[:limit]],
             column_config={"report": st.column_config.LinkColumn("report")},
             use_container_width=True)

buf = io.StringIO()
w = csv.writer(buf)
w.writerow(["file", "type", "engines", "verdict", "agent", "full_indicator"])
w.writerows([(r["file"], r["type"], r["engines"], r["verdict"], r["agent"], r["_indicator"])
             for r in view])
st.download_button("Download indicators CSV", buf.getvalue(), "saf_indicators.csv", "text/csv")

st.subheader("Alerts per agent")
st.dataframe([{"agent": r[0], "alerts": r[1], "last_seen_ist": to_ist(r[2])} for r in
              q("SELECT agent, COUNT(*), MAX(ts) FROM alerts GROUP BY 1 ORDER BY 2 DESC")],
             use_container_width=True)

if agent_f != "(all)":
    st.subheader(f"Latest alerts — {agent_f}")
    st.dataframe(
        [{"ts_ist": to_ist(r[0]), "rule": r[1], "level": r[2], "desc": (r[3] or "")[:100]} for r in
         q("SELECT ts, rule_id, level, description FROM alerts WHERE agent=? ORDER BY rowid DESC LIMIT 20",
           (agent_f,))],
        use_container_width=True)

st.subheader("Notification log")
st.dataframe(
    [{"alert": r[0], "indicator": r[1][:20] + "…" if len(r[1]) > 21 else r[1],
      "status": r[2],
      "sent_ist": to_ist(r[3])} for r in
     q("SELECT alert_id, indicator, status, sent_at"
       " FROM notifications ORDER BY sent_at DESC LIMIT 20")],
    use_container_width=True)
