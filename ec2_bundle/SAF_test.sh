#!/bin/bash
# SAF end-to-end test — run on any enrolled agent. Prints PASS/FAIL per step.
# Expects: agent installed, FIM paths added, EC2 pipeline running.
set -u
echo "=== 1/4 agent running? ==="
sudo /var/ossec/bin/wazuh-control status | grep -q "wazuh-agentd is running" \
  && echo "PASS agentd running" || echo "FAIL agentd not running"
echo "=== 2/4 FIM test file ==="
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_final.txt \
  && echo "PASS dropped /tmp/eicar_final.txt" || echo "FAIL cannot write /tmp"
echo "=== 3/4 auth test event ==="
logger -t wazuh-test "final demo probe $(date +%s)" \
  && echo "PASS logger event sent" || echo "FAIL logger failed"
echo "=== 4/4 sudo failure probe ==="
sudo -n true 2>/dev/null; echo "PASS sudo probe done (a PAM alert may follow)"
echo ""
echo "NEXT: wait 90s, then on EC2 run: tail -5 pipeline.log ; python3 check_db.py"
echo "EXPECT: 'VirusTotal checked file' line + Discord embed for EICAR/file or malicious IP."
