"""Discord notifier — compact card. Works offline (dry-run) when no webhook configured."""
import logging
import requests

logger = logging.getLogger(__name__)

def send_discord(webhook_url: str, alert_id: str, indicator: str,
                 itype: str, risk: str, vt: dict, description: str = "",
                 target: str = "", rule: str = "") -> bool:
    if not webhook_url:
        logger.warning("No Discord webhook — dry-run, skipping send.")
        print(f"[DRY-RUN Discord] {alert_id} {indicator} risk={risk} vt={vt}")
        return False
    color = {"HIGH": 0xE74C3C, "MEDIUM": 0xF39C12, "LOW": 0x2ECC71}.get(risk, 0x95A5A6)
    mal, sus = vt.get("malicious", 0), vt.get("suspicious", 0)
    short = f"{indicator[:8]}…{indicator[-7:]}" if len(indicator) > 20 else indicator
    gui = "file" if itype in ("file", "hash") else ("ip-address" if itype == "ip" else "domain")
    action = {"HIGH": "Isolate host + analyst review",
              "MEDIUM": "Analyst review",
              "LOW": "Log only"}.get(risk, "Analyst review")
    embed = {
        "title": f"{risk} — {itype} ({mal}/{sus} engines)",
        "color": color,
        "fields": [
            {"name": "Scope", "value": f"{alert_id}" + (f" · Rule {rule}" if rule else ""), "inline": False},
            {"name": "Target", "value": f"`{(target or indicator)[:500]}`", "inline": False},
            {"name": "SHA / IP", "value": f"`{short}`", "inline": True},
            {"name": "Report", "value": f"https://www.virustotal.com/gui/{gui}/{indicator}", "inline": False},
            {"name": "Action", "value": action, "inline": False},
        ],
    }
    try:
        r = requests.post(webhook_url, json={"embeds": [embed]}, timeout=15)
        if r.status_code == 429:
            logger.warning("Discord rate-limited")
            return False
        r.raise_for_status()
        return True
    except Exception as e:
        logger.error("Discord send failed: %s", e)
        return False
