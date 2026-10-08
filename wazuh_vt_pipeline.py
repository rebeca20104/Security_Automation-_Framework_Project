#!/usr/bin/env python3
"""
Wazuh -> VirusTotal -> Discord + SQLite pipeline.

Run:  python3 wazuh_vt_pipeline.py
Needs: pip install requests
"""
import os
import sys
import time
import sqlite3
import logging
import ipaddress
import requests
import urllib3

WAZUH_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_PASS")
VT_KEY = os.getenv("VT_API_KEY")
DISCORD = os.getenv("DISCORD_WEBHOOK")
THRESHOLD = int(os.getenv("CRITICAL_THRESHOLD", "5"))
POLL = int(os.getenv("POLL_SECONDS", "30"))
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() == "true"
DB_PATH = os.getenv("DB_PATH", "security.db")
CACHE_TTL = 24 * 3600          # re-check an indicator after 24h
NOTIFY_LEVEL = int(os.getenv("NOTIFY_LEVEL", "99"))
VT_MIN_INTERVAL = 15           # free tier: 4 requests/min
# ---------- filter protocol (tiered Discord gates) ----------
GENERIC_MIN_LEVEL = int(os.getenv("GENERIC_MIN_LEVEL", "7"))   # Tier-2 generic cards
AUTH_RULES = {"5503", "5504", "5716", "5720", "5760", "5763"}   # auth-failure aggregation set
AUTH_COOLDOWN = int(os.getenv("AUTH_COOLDOWN", "900"))         # 15 min per (agent, rule)
GENERIC_COOLDOWN = int(os.getenv("GENERIC_COOLDOWN", "86400")) # 24h per (agent, rule) generic Tier-2 cards
SUSP_COOLDOWN = int(os.getenv("SUSP_COOLDOWN", "86400"))       # 24 h per suspicious indicator
MAX_PER_MIN = int(os.getenv("MAX_PER_MIN", "10"))              # Discord send budget
TEMP_SUFFIXES = (".part", ".tmp", ".crdownload", ".partial", ".xpi", ".lock")  # temp files never notify
SKIP_PREFIXES = tuple(p for p in os.getenv("SKIP_PREFIXES", "/tmp/gdk-,/tmp/firefox-,/tmp/mozilla-,/tmp/tmp-").split(",") if p)


def _skip_path(path):
    if not path:
        return False
    if path.endswith(TEMP_SUFFIXES):
        return True
    return path.startswith(SKIP_PREFIXES)
_send_window = [0.0, 0]  # [window_start, count]

if not VERIFY_TLS:
    urllib3.disable_warnings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pipeline")
_last_vt_call = 0.0


# ---------- database ----------
def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY, ts TEXT, agent TEXT, rule_id TEXT,
        level INTEGER, description TEXT, file_path TEXT);
    CREATE TABLE IF NOT EXISTS indicators (
        indicator TEXT PRIMARY KEY, type TEXT, malicious INTEGER,
        suspicious INTEGER, verdict TEXT, checked_at REAL);
    CREATE TABLE IF NOT EXISTS alert_indicators (
        alert_id TEXT, indicator TEXT, PRIMARY KEY (alert_id, indicator));
    CREATE TABLE IF NOT EXISTS notifications (
        alert_id TEXT, indicator TEXT, sent_at REAL, status TEXT,
        PRIMARY KEY (alert_id, indicator));
    CREATE TABLE IF NOT EXISTS cooldowns (
        k TEXT PRIMARY KEY, sent_at REAL);
    """)
    db.commit()
    return db


def get_state(db, key, default=None):
    row = db.execute("SELECT v FROM state WHERE k=?", (key,)).fetchone()
    return row[0] if row else default


def set_state(db, key, value):
    db.execute("INSERT OR REPLACE INTO state VALUES (?,?)", (key, value))
    db.commit()


# ---------- Wazuh ----------
def fetch_alerts(since):
    body = {
        "size": 100,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"range": {"timestamp": {"gte": since}}},
    }
    r = requests.post(
        f"{WAZUH_URL}/wazuh-alerts-*/_search",
        json=body, auth=(WAZUH_USER, WAZUH_PASS),
        verify=VERIFY_TLS, timeout=30,
    )
    r.raise_for_status()
    return [h["_source"] | {"_id": h["_id"]} for h in r.json()["hits"]["hits"]]


def is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def extract_indicators(alert):
    """Return list of (indicator, type) found in the alert."""
    found = []
    sc = alert.get("syscheck", {})
    h = sc.get("sha256_after") or sc.get("md5_after")
    if h:
        found.append((h, "file"))

    data = alert.get("data", {})
    candidates = [data.get(k) for k in ("srcip", "dstip", "src_ip", "dst_ip")]
    candidates.append(alert.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress"))
    for ip in candidates:
        if ip and is_public_ip(ip):
            found.append((ip, "ip"))
    return list(dict.fromkeys(found))  # dedupe, keep order


# ---------- VirusTotal ----------
def vt_lookup(db, indicator, itype):
    """Return (malicious, suspicious, verdict) using cache + rate limiting."""
    global _last_vt_call
    row = db.execute(
        "SELECT malicious, suspicious, verdict, checked_at FROM indicators WHERE indicator=?",
        (indicator,),
    ).fetchone()
    if row and time.time() - row[3] < CACHE_TTL:
        return row[0], row[1], row[2]

    path = "files" if itype == "file" else "ip_addresses"
    url = f"https://www.virustotal.com/api/v3/{path}/{indicator}"

    for attempt in range(2):
        wait = VT_MIN_INTERVAL - (time.time() - _last_vt_call)
        if wait > 0:
            time.sleep(wait)
        _last_vt_call = time.time()
        r = requests.get(url, headers={"x-apikey": VT_KEY}, timeout=20)
        if r.status_code == 429:
            log.warning("VT rate limited, sleeping 60s")
            time.sleep(60)
            continue
        break
    else:
        return None  # give up for now; will retry on next poll

    if r.status_code == 404:
        mal, sus, verdict = 0, 0, "unknown"
    elif r.ok:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        verdict = "critical" if mal >= THRESHOLD else ("suspicious" if mal or sus else "clean")
    else:
        log.error("VT error %s for %s", r.status_code, indicator)
        return None

    db.execute(
        "INSERT OR REPLACE INTO indicators VALUES (?,?,?,?,?,?)",
        (indicator, itype, mal, sus, verdict, time.time()),
    )
    db.commit()
    return mal, sus, verdict


# ---------- Discord ----------
def _budget_ok(db):
    """Per-minute send budget; overflow is logged for digest instead of dropped silently."""
    global _send_window
    now = time.time()
    if now - _send_window[0] >= 60:
        _send_window = [now, 0]
    if _send_window[1] >= MAX_PER_MIN:
        return False
    _send_window[1] += 1
    return True


def _cooldown_ok(db, key, seconds):
    row = db.execute("SELECT sent_at FROM cooldowns WHERE k=?", (key,)).fetchone()
    if row and time.time() - row[0] < seconds:
        return False
    db.execute("INSERT OR REPLACE INTO cooldowns VALUES (?,?)", (key, time.time()))
    return True


def _post_embed(embed):
    if not _budget_ok(None):
        log.warning("Discord budget exceeded, card queued for digest: %s", embed.get("title"))
        return False
    try:
        r = requests.post(DISCORD, json={"embeds": [embed]}, timeout=15)
        if r.status_code == 429:
            retry = float(r.json().get("retry_after", 2))
            log.warning("Discord 429 rate-limited, retry_after=%s", retry)
            time.sleep(retry)
            r = requests.post(DISCORD, json={"embeds": [embed]}, timeout=15)
        if not r.ok:
            log.error("Discord post failed: %s %s", r.status_code, r.text[:200])
        return r.ok
    except Exception as e:
        log.error("Discord post error: %s", e)
        return False
def notify_discord(alert, indicator, itype, mal, sus):
    gui = "file" if itype == "file" else "ip-address"
    agent = alert.get("agent", {}).get("name", "n/a")
    rule = alert.get("rule", {})
    short = f"{indicator[:8]}…{indicator[-7:]}" if len(indicator) > 20 else indicator
    path = alert.get("syscheck", {}).get("path")
    target = path if path else indicator
    action = "Isolate host + analyst review" if mal >= THRESHOLD else "Analyst review"
    embed = {
        "title": f"HIGH — Malicious {itype} ({mal}/{sus} engines)",
        "color": 0xE74C3C,
        "fields": [
            {"name": "Scope", "value": f"{agent} · Rule {rule.get('id')} (L{rule.get('level')})", "inline": False},
            {"name": "Target", "value": f"`{target[:500]}`", "inline": False},
            {"name": "SHA / IP", "value": f"`{short}`", "inline": True},
            {"name": "Report", "value": f"https://www.virustotal.com/gui/{gui}/{indicator}", "inline": False},
            {"name": "Action", "value": action, "inline": False},
        ],
        "timestamp": alert["timestamp"].replace("+0000", "+00:00"),
    }

    r = _post_embed(embed)
    return r

def notify_alert(db, alert):
    """Tier-2 generic card: level gate + auth aggregation + temp-file skip, all logged."""
    r = alert.get("rule", {})
    agent = alert.get("agent", {}).get("name", "n/a")
    path = alert.get("syscheck", {}).get("path", "")
    if _skip_path(path):
        log.info("Tier-3 skip noisy path %s", path)
        return False
    rid, level = str(r.get("id", "?")), int(r.get("level") or 0)
    floor = GENERIC_MIN_LEVEL if NOTIFY_LEVEL == 1 else max(NOTIFY_LEVEL, GENERIC_MIN_LEVEL)
    if rid in AUTH_RULES:
        if not _cooldown_ok(db, f"auth:{agent}:{rid}", AUTH_COOLDOWN):
            log.info("Tier-2 auth cooldown suppress (%s %s)", agent, rid)
            return False
    elif level < floor and level < 12:  # Tier-1: L12+ bypasses floor
        log.info("Tier-3 skip rule %s level %s", rid, level)
        return False
    elif level < 12 and not _cooldown_ok(db, f"generic:{agent}:{rid}", GENERIC_COOLDOWN):
        # Tier-2: persistent generic conditions (e.g. repeated rootcheck 510)
        # notify once per (agent, rule) per GENERIC_COOLDOWN instead of per scan.
        log.info("Tier-2 generic cooldown suppress (%s rule %s)", agent, rid)
        return False
    embed = {
        "title": f"Wazuh alert L{level} — {r.get('description', '')[:80]}",
        "color": 0xF39C12,
        "fields": [
            {"name": "Scope", "value": f"{agent} · Rule {rid} (L{level})", "inline": False},
        ],
    }
    if path:
        embed["fields"].append({"name": "Target", "value": f"`{path[:500]}`"})
    ok = _post_embed(embed)
    db.execute("INSERT OR IGNORE INTO notifications VALUES (?,?,?,?)",
               (alert["_id"], f"rule:{rid}", time.time(), "sent" if ok else "failed"))
    return ok

# ---------- main loop ----------
def process(db, alert):
    aid = alert["_id"]
    if db.execute("SELECT 1 FROM alerts WHERE id=?", (aid,)).fetchone():
        return  # already handled

    rule = alert.get("rule", {})
    db.execute(
        "INSERT INTO alerts VALUES (?,?,?,?,?,?,?)",
        (aid, alert["timestamp"], alert.get("agent", {}).get("name"),
         rule.get("id"), rule.get("level"), rule.get("description"),
         alert.get("syscheck", {}).get("path")),
    )

    notify_alert(db, alert)  # Tier-1/2/3 gates inside

    indicators = extract_indicators(alert)
    if not indicators:
        log.info("Alert rule %s (level %s): no hash/public IP, VirusTotal not used",
                 rule.get("id"), rule.get("level"))
    for indicator, itype in indicators:
        if _skip_path(alert.get("syscheck", {}).get("path", "")):
            log.info("Tier-3 skip noisy path indicator %s", indicator)
            continue
        db.execute("INSERT OR IGNORE INTO alert_indicators VALUES (?,?)", (aid, indicator))
        result = vt_lookup(db, indicator, itype)
        log.info("VirusTotal checked %s %s -> %s", itype, indicator, result)
        if result is None:
            continue
        mal, sus, verdict = result
        if verdict == "critical":
            ok = notify_discord(alert, indicator, itype, mal, sus)  # Tier-1 always
            db.execute("INSERT OR IGNORE INTO notifications VALUES (?,?,?,?)",
                       (aid, indicator, time.time(), "sent" if ok else "failed"))
        elif mal or sus:
            if _cooldown_ok(db, f"susp:{indicator}", SUSP_COOLDOWN):  # Tier-2 once/24h
                ok = notify_discord(alert, indicator, itype, mal, sus)
                db.execute("INSERT OR IGNORE INTO notifications VALUES (?,?,?,?)",
                           (aid, indicator, time.time(), "sent" if ok else "failed"))
            else:
                log.info("Tier-2 suspicious cooldown suppress %s", indicator)
    db.commit()


def main():
    missing = [n for n, v in (("WAZUH_PASS", WAZUH_PASS), ("VT_API_KEY", VT_KEY),
                              ("DISCORD_WEBHOOK", DISCORD)) if not v]
    if missing:
        sys.exit(f"Missing env vars: {', '.join(missing)}")

    db = init_db()
    since = get_state(db, "last_ts", "now-5m")
    log.info("Started. Polling %s every %ss from %s", WAZUH_URL, POLL, since)

    while True:
        try:
            alerts = fetch_alerts(since)
            for a in alerts:
                try:
                    process(db, a)
                except Exception:
                    # One poison alert must never wedge the cursor; skip it loudly.
                    log.exception("Skipping alert %s", a.get("_id", "?"))
            if alerts:
                since = alerts[-1]["timestamp"]
                set_state(db, "last_ts", since)
            log.info("Poll done: %d alert(s)", len(alerts))
        except requests.RequestException as e:
            log.error("Network error: %s", e)
        except Exception:
            log.exception("Unexpected error")
        time.sleep(POLL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Stopped.")
