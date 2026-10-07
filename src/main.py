#!/usr/bin/env python3
"""Unified local pipeline: sample/Wazuh alert -> VT enrich -> risk -> Discord -> audit log.

Usage:
  python src/main.py --sample data/sample_alert.json --dry-run
  python src/main.py --sample data/sample_alert.json   (needs .env with VT_API_KEY + DISCORD_WEBHOOK)
"""
import os, sys, json, argparse, logging
from pathlib import Path
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from vt_client import enrich_indicator
from risk_engine import calculate_risk
from notifier import send_discord
from logger import write_audit

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("rescue")

def extract_indicators(alert: dict):
    inds = list(alert.get("indicators", []))
    # Also support raw Wazuh format (syscheck hash / srcip)
    sc = alert.get("syscheck", {})
    h = sc.get("sha256_after") or sc.get("md5_after")
    if h:
        inds.append({"type": "hash", "value": h})
    for k in ("srcip", "dstip"):
        ip = alert.get("data", {}).get(k)
        if ip:
            inds.append({"type": "ip", "value": ip})
    # dedupe
    seen, out = set(), []
    for i in inds:
        key = (i.get("type"), i.get("value"))
        if key[1] and key not in seen:
            seen.add(key); out.append({"type": key[0], "value": key[1]})
    return out

def triage(alert: dict, dry_run: bool = False):
    alert_id = alert.get("alert_id") or alert.get("_id", "ALERT-LOCAL")
    severity = alert.get("severity", "medium")
    desc = alert.get("rule", {}).get("description", alert.get("description", ""))
    results = []
    for ind in extract_indicators(alert):
        vt = {"indicator": ind["value"], "type": ind["type"],
              "malicious": 0, "suspicious": 0, "status": "DRY_RUN"} \
             if dry_run else enrich_indicator(ind["type"], ind["value"])
        risk, action = calculate_risk(severity, vt)
        wh = None if dry_run else os.getenv("DISCORD_WEBHOOK", "")
        sent = send_discord(wh, alert_id, ind["value"], ind["type"], risk, vt, desc)
        rec = write_audit({"alert_id": alert_id, "indicator": ind["value"],
                           "indicator_type": ind["type"], "local_severity": severity,
                           "virustotal_result": vt, "final_risk": risk,
                           "action": action, "notified": sent})
        log.info("%s %s -> risk=%s action=%s notified=%s", ind["type"], ind["value"], risk, action, sent)
        results.append(rec)
    if not results:
        log.warning("No indicators found in alert %s", alert_id)
    return results

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default="data/sample_alert.json")
    ap.add_argument("--dry-run", action="store_true", help="skip VT + Discord, still writes audit log")
    args = ap.parse_args()
    alert = json.loads(Path(args.sample).read_text(encoding="utf-8"))
    triage(alert, dry_run=args.dry_run)

if __name__ == "__main__":
    main()
