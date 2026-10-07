#!/bin/bash
# ⚠️  DESTRUCTIVE FULL TEARDOWN: stops the pipeline, removes its @reboot cron
# entry, and DELETES ~/live (code, .env, database, logs) plus test zips.
# Run only when deliberately decommissioning the deployment.
set -e

echo "This will:"
echo "  1. Stop the wazuh_vt_pipeline process"
echo "  2. Remove the pipeline's @reboot cron entry"
echo "  3. DELETE ~/live and ~/*_live_test.zip (ALL data + .env + DB)"
read -r -p "Type 'DELETE' to continue: " CONFIRM
if [ "$CONFIRM" != "DELETE" ]; then
  echo "Aborted."
  exit 1
fi

pkill -f "[w]azuh_vt_pipeline" || true
sleep 2
ps aux | grep "[w]azuh_vt" | head -3
echo "--- cron before ---"
crontab -l 2>/dev/null | grep "wazuh_vt" || echo "no cron line"
crontab -l 2>/dev/null | grep -v "wazuh_vt_pipeline" | crontab - || true
echo "--- cron after ---"
crontab -l 2>/dev/null | grep "wazuh_vt" || echo "cron clean"
rm -rf ~/live ~/*_live_test.zip
ls ~
echo CLEAN-DONE
