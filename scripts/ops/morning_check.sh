#!/bin/bash
# Morning status: recent pipeline activity + latest EICAR evidence in Wazuh alerts.
cd ~/live/ec2_bundle
date -u
grep -n "eicar" pipeline.log | tail -10
tail -30 pipeline.log
echo "---MANAGER-EICAR---"
sudo grep -h "eicar" /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -3 | cut -c1-350
