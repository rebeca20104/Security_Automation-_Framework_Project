"""Send a test Discord card to verify the notify path (no Wazuh/VT needed).

Usage:
    set DISCORD_WEBHOOK=https://discord.com/api/webhooks/...   (or source .env)
    python3 test_card.py

Prints the HTTP status: 204/200 means the webhook accepted the card.
"""
import os
import sys

import requests

webhook = os.getenv("DISCORD_WEBHOOK", "")
if not webhook:
    sys.exit("DISCORD_WEBHOOK not set — export it first (e.g. `set -a; . ./.env; set +a`)")

r = requests.post(
    webhook,
    json={'embeds': [{
        'title': 'HIGH — Malicious file (60/0 engines)',
        'color': 15158332,
        'fields': [
            {'name': 'Scope', 'value': '<AGENT_NAME> · Rule 550 (L7)'},
            {'name': 'Target', 'value': '`<WATCHED_PATH>/eicar.com`'},
            {'name': 'SHA / IP', 'value': '`e038b516…7529494`', 'inline': True},
            {'name': 'Report',
             'value': 'https://www.virustotal.com/gui/file/e038b5168d9209267058112d845341cae83d92b1d1af0a10b66830acb7529494'},
            {'name': 'Action', 'value': 'Isolate host + analyst review'},
        ]}]},
    timeout=15)
print(r.status_code)
