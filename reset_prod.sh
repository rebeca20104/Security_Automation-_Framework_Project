#!/bin/bash
# ⚠️  DESTRUCTIVE: restores production .env defaults and WIPES the local
# alert/indicator history (clear_cache.py), then restarts the pipeline.
# Use after noisy experiments (demo tuning, test keys) to return to defaults.
set -e
cd ~/live/ec2_bundle

echo "This will:"
echo "  1. Set CRITICAL_THRESHOLD=5 and NOTIFY_LEVEL=99 in .env"
echo "  2. DELETE all rows from alerts + indicators in security.db"
echo "  3. Restart the pipeline"
read -r -p "Type 'yes' to continue: " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  echo "Aborted."
  exit 1
fi

sed -i "s/^CRITICAL_THRESHOLD=.*/CRITICAL_THRESHOLD=5/" .env
sed -i "s/^NOTIFY_LEVEL=.*/NOTIFY_LEVEL=99/" .env
grep -E "^CRITICAL|^NOTIFY" .env
python3 clear_cache.py
pkill -f "[w]azuh_vt_pipeline" || true
sleep 3
set -a
. ./.env
set +a
nohup python3 wazuh_vt_pipeline.py > pipeline.log 2>&1 &
sleep 35
tail -4 pipeline.log
python3 check_db.py
