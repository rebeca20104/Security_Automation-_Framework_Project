#!/bin/bash
# Rotate the VirusTotal API key: update .env, clear the VT cache, restart.
# Usage: ./rotate_key.sh <NEW_VT_API_KEY>
# Tip: run ./snapshot.sh first so the old .env is backed up.
cd ~/live/ec2_bundle
if [ $# -ne 1 ]; then
  echo "usage: $0 <NEW_VT_API_KEY>"
  exit 1
fi
sed -i "s/^VT_API_KEY=.*/VT_API_KEY=$1/" .env
grep -c VT_API .env
python3 clear_cache.py
pkill -f "[w]azuh_vt_pipeline"
sleep 3
set -a
. ./.env
set +a
nohup python3 wazuh_vt_pipeline.py > pipeline.log 2>&1 &
sleep 40
tail -4 pipeline.log
python3 check_db.py
