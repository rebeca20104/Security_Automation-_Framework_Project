#!/bin/bash
# Run on EACH enrolled agent. No args needed.
# Prints PASS/FAIL per step. Tag output with the agent name for correlation.
set -u
AGENT="$(hostname)-$(whoami)-$(date +%s)"
echo "== agent: $AGENT =="
sudo /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-agentd is running" \
  && echo "PASS agentd running" || echo "FAIL agentd — reinstall/re-enroll needed"
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_multi.txt \
  && echo "PASS FIM probe dropped tag=$AGENT" || echo "FAIL cannot write /tmp"
logger -t wazuh-test "multi-endpoint probe tag=$AGENT" \
  && echo "PASS logger probe tag=$AGENT" || echo "FAIL logger"
echo "Wrote tag: $AGENT — keep it, EC2 check will grep for it."
