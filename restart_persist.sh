#!/bin/bash
# Start the pipeline and guarantee the @reboot cron entry exists.
# Safe to run repeatedly — cron is only added if missing.
cd ~/live/ec2_bundle
set -a
. ./.env
set +a
nohup python3 wazuh_vt_pipeline.py > pipeline.log 2>&1 &
sleep 15
tail -5 pipeline.log
ps aux | grep "[w]azuh_vt" | head -3
CRON_OK=$(crontab -l 2>/dev/null | grep -c "wazuh_vt_pipeline" || true)
if [ "$CRON_OK" = "0" ]; then
  (crontab -l 2>/dev/null; echo "@reboot cd $HOME/live/ec2_bundle && set -a && . ./.env && set +a && nohup python3 wazuh_vt_pipeline.py > pipeline.log 2>&1 &") | crontab -
  echo "cron @reboot installed"
else
  echo "cron already present"
fi
