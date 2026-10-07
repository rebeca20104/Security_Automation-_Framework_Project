#!/bin/bash
# Health check: is the pipeline process alive and is the log moving?
cd ~/live/ec2_bundle
date -u
ps aux | grep "[w]azuh_vt" | head -5
ls -la pipeline.log
tail -3 pipeline.log
