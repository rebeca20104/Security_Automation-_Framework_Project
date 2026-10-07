#!/bin/bash
# Save a timestamped backup of the live .env before making any change.
# Restoring is just: cp .env.saved-YYYYMMDD .env  (then restart the pipeline)
cd ~/live/ec2_bundle
cp .env ".env.saved-$(date -u +%Y%m%d)"
grep POLL .env
grep THRESHOLD .env
grep NOTIFY .env
grep VERIFY .env
echo SNAPSHOT-OK
