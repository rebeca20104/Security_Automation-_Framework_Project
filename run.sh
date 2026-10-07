#!/bin/bash
# Run on the Wazuh manager host (e.g. ubuntu@<EC2_PUBLIC_IP>)
set -e
pip3 install -q requests urllib3
export $(grep -v '^#' .env | xargs) 2>/dev/null || true
echo "Starting pipeline... (Ctrl+C to stop)"
python3 wazuh_vt_pipeline.py
