# EC2 Deployment Checklist

A copy-paste checklist for deploying the SAF pipeline + dashboard on the Wazuh manager
host. If you haven't done the full walkthrough yet, use **[../SETUP.md](../SETUP.md)**
instead — this file assumes you're at the terminal right now.

**Labels:** 💻 = your workstation · 🖥️ = manager

---

## Pre-flight

- [ ] Server running (Ubuntu 22.04, t3.xlarge recommended), Elastic IP attached
- [ ] Security group: 22 (SSH), 443 (Wazuh dashboard), 1514 + 1515 (agents)
- [ ] Wazuh installed; admin password saved (`WAZUH_PASS`)
- [ ] At least one agent enrolled and **green** on the Wazuh dashboard
- [ ] FIM paths configured on agents (SETUP.md Phase 5)
- [ ] VirusTotal API key + Discord webhook in hand
- [ ] SSH key ready (`chmod 400 <KEY>.pem`)

---

## 1 · Copy the bundle 💻 workstation

```powershell
scp -i <KEY>.pem wazuh_vt_pipeline.py dashboard.py .env run.sh check_db.py check_agents.py ubuntu@<EC2_PUBLIC_IP>:~/live/
```

> **Better practice:** build `.env` *on the manager* from `.env.example` instead of
> copying your workstation's file. The server copy needs:
> `WAZUH_INDEXER_URL=https://localhost:9200`, `WAZUH_USER=admin`,
> `WAZUH_PASS=<generated admin password>`, plus `VT_API_KEY` and `DISCORD_WEBHOOK`.

---

## 2 · Start the pipeline 🖥️ manager

```bash
cd ~/live
mkdir -p output
chmod +x run.sh
./run.sh
```

**Expected:**

```
Started. Polling https://localhost:9200 every 5s from now-5m
Poll done: 0 alert(s)
```

❌ Anything else → check `.env` values and that Wazuh services are `active`
(`sudo systemctl status wazuh-manager wazuh-indexer`).

---

## 3 · Verify with a real trigger

📟 **agent** — drop the test file:

```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_test.txt
```

🖥️ **manager** — after ~90 seconds:

```bash
tail -f pipeline.log        # expect: VirusTotal checked file ... (63, 0, 'critical')
python3 check_db.py         # expect: 'critical' indicator + notification status 'sent'
```

Also confirm on Discord: a HIGH card with a VirusTotal report link.

---

## 4 · Dashboard (optional) 🖥️ manager

```bash
pip install --break-system-packages streamlit
nohup python3 -m streamlit run dashboard.py --server.port 8501 --server.address localhost --server.headless true > dashboard.log 2>&1 &

curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8501   # → 200
```

**View** (localhost-only — never open 8501 publicly), from 💻 workstation:

```powershell
ssh -i <KEY>.pem -L 8501:localhost:8501 ubuntu@<EC2_PUBLIC_IP>
# open http://localhost:8501
```

---

## 5 · Persist across reboots 🖥️ manager

A reboot silently kills `nohup` processes — install both entries **now**:

```bash
crontab -e
```

```cron
@reboot cd $HOME/live/ec2_bundle && set -a && . ./.env && set +a && nohup python3 wazuh_vt_pipeline.py > pipeline.log 2>&1 &
@reboot cd $HOME/live && nohup python3 -m streamlit run dashboard.py --server.port 8501 --server.address localhost --server.headless true > dashboard.log 2>&1 &
```

---

## 6 · Post-deployment verification

| Check | Command (manager) | Expected |
|-------|-------------------|----------|
| Pipeline alive | `ps aux \| grep "[w]azuh_vt"` | process listed |
| Logs flowing | `tail -5 pipeline.log` | `Poll done` lines |
| Database created | `ls -la output/security.db` | file > 0 bytes |
| Cron installed | `crontab -l \| grep -c @reboot` | `2` |
| Dashboard up | `curl -s -o /dev/null -w '%{http_code}' http://localhost:8501` | `200` |
| Agents green | Wazuh dashboard → Agents | all expected agents Active |
| Test end-to-end | (re-run step 3) | Discord card + `sent` row in `check_db.py` |

All seven boxes ticked → **deployment complete.**

---

## Rollback 🖥️ manager

```bash
pkill -f "wazuh_vt_pipeline"          # stop pipeline
pkill -f "streamlit run dashboard"    # stop dashboard
crontab -e                            # delete the two @reboot lines
```

Full teardown (deletes everything, asks for confirmation):
`bash scripts/ops/danger/cleanup_ec2.sh`

---

## Security reminders

- Never commit `.env`, `*.db`, `*.pem`, `*.zip` — `.gitignore` already covers them.
- Keep the dashboard on `localhost`; reach it only through an SSH tunnel.
- Rotate the VT key / webhook if either ever leaks
  (`scripts/ops/rotate_key.sh`, then `snapshot.sh` beforehand).
