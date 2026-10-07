# SAF — Setup Guide

A guided, first-time setup. Work through the phases in order — **Phase 2 needs no server
at all**, so you'll see the system work before you build any infrastructure.

**Where commands run** — every step is labeled:

| Label | Meaning |
|-------|---------|
| 💻 **workstation** | Your own computer (Windows/macOS/Linux) |
| 🖥️ **manager** | The server that will run Wazuh + the SAF pipeline |
| 📟 **agent** | A machine you want to monitor |

**Values to collect first** — you'll substitute these throughout (see README for the full
list): `<EC2_PUBLIC_IP>`, `<KEY>.pem`, `<NAME>`, `<generated admin password>`,
your VirusTotal key, and a Discord webhook URL.

---

## Phase 0 — Gather credentials (10 minutes)

You need three free things before Phase 3:

| Credential | Where to get it | Notes |
|------------|-----------------|-------|
| **VirusTotal API key** | virustotal.com → join → API key | Free tier: 4 lookups/min (the pipeline self-throttles) |
| **Discord webhook** | Your Discord server → Settings → Integrations → New Webhook | Copy the URL; this is your alert channel |
| **Cloud server** | Any provider (AWS EC2, etc.) | Ubuntu 22.04, 4 vCPU / 16 GB recommended for Wazuh |

✅ **Checkpoint:** you have a VT key string, a `https://discord.com/api/webhooks/…` URL,
and a running Ubuntu server you can SSH into with `<KEY>.pem`.

---

## Phase 1 — Install on your workstation (5 minutes)

💻 **workstation**

```powershell
# Windows (use bash/macOS/Linux equivalents otherwise)
git clone <YOUR_REPO_URL>
cd SAF
pip install -r requirements.txt
Copy-Item .env.example .env
```

Now edit `.env` and fill in at minimum:

```
VT_API_KEY=<YOUR_VT_KEY>
DISCORD_WEBHOOK=<YOUR_DISCORD_WEBHOOK_URL>
```

✅ **Checkpoint:** `requirements.txt` installed, `.env` exists with your two keys.

---

## Phase 2 — Prove it works locally, no server (5 minutes)

💻 **workstation** — this runs the whole chain (enrich → risk → notify → audit) against
a sample alert. Do this *before* touching any server: it isolates config problems early.

```powershell
# Step 2a — offline dry run (no API calls, no keys needed):
python src/main.py --sample data/sample_alert.json --dry-run

# Step 2b — live run (uses your VT key + webhook):
python src/main.py --sample data/sample_alert.json

# Step 2c — inspect the audit trail:
Get-Content output/audit_log.json | Select-Object -Last 1
```

**What success looks like:**

* Console: `example.com -> risk=MEDIUM action=ALERT_AND_INVESTIGATE notified=True`
* Audit JSON: `"status": "OK"` inside `virustotal_result`
* Discord: an embed appeared in your channel (step 2b only)

❌ **Not working?**
* `ModuleNotFoundError` → rerun step 1's `pip install`
* `notified=False` + a dry-run message → you ran 2a, run 2b
* `status: INVALID_API_KEY` → fix `VT_API_KEY` in `.env`
* Nothing in Discord → check `DISCORD_WEBHOOK` has no trailing spaces/newline

✅ **Checkpoint:** audit line written, Discord card received. Your toolchain is proven —
everything after this is infrastructure.

---

## Phase 3 — Install the Wazuh manager (15–20 minutes)

🖥️ **manager**

```bash
# 3a — update and install Wazuh single-node (all-in-one)
sudo apt update && sudo apt -y upgrade
curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

At the end the installer prints a **username and generated admin password** — save the
password now as `<generated admin password>`. The dashboard is at
`https://<EC2_PUBLIC_IP>`.

```bash
# 3b — verify every service is up
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat --no-pager
```

**Firewall / security group** — open only these inbound ports:

| Port | Who connects |
|------|--------------|
| 22 | You (SSH) |
| 443 | You (Wazuh dashboard) |
| 1514 / 1515 | Your agents (log stream / enrollment) |

✅ **Checkpoint:** all four services show `active (running)`; the dashboard loads in your
browser at `https://<EC2_PUBLIC_IP>`.

---

## Phase 4 — Enroll your first agent (10 minutes)

**Step 4a — create a key on the manager** 🖥️ **manager**

```bash
sudo /var/ossec/bin/manage_agents -a any -n "<NAME>"
sudo /var/ossec/bin/manage_agents -e "<NAME>"     # prints a long KEY — copy it
```

**Step 4b — install the agent on the machine you monitor** 📟 **agent**

```bash
# Linux (Debian/Ubuntu/Kali). Windows agents: see Wazuh docs, same key step.
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.8-1_amd64.deb
sudo WAZUH_MANAGER='<EC2_PUBLIC_IP>' dpkg -i wazuh-agent_*.deb

# Import the key you copied in 4a:
sudo /var/ossec/bin/manage_agents -i "<KEY>"

# Tell the agent where to connect (edit /var/ossec/etc/ossec.conf, inside <client>):
#   <address><EC2_PUBLIC_IP></address>
#   <port>1514</port>
#   <protocol>tcp</protocol>

sudo /var/ossec/bin/wazuh-control restart
sudo systemctl enable wazuh-agent      # survive reboots
```

**Step 4c — verify**

📟 **agent:** `sudo /var/ossec/bin/wazuh-control status` → `wazuh-agentd is running`
🖥️ **manager:** Wazuh dashboard → Agents → your `<NAME>` is **green/Active**

❌ **Agent stays red?** The key or address is wrong. Re-do 4a (remove and re-add the
agent), re-import the key, re-check `ossec.conf`, restart.

✅ **Checkpoint:** agent green in the dashboard.

---

## Phase 5 — Tell Wazuh what to watch (5 minutes)

📟 **agent** — SAF only sees what Wazuh monitors. Add high-risk folders inside
`<syscheck>` in `/var/ossec/etc/ossec.conf`:

```xml
<directories check_all="yes" realtime="yes">/tmp</directories>
<directories check_all="yes" realtime="yes">/var/tmp</directories>
<directories check_all="yes">/dev/shm</directories>
<directories check_all="yes">/usr/local/bin,/opt</directories>
<directories check_all="yes" realtime="yes">/home/<user>/Downloads</directories>
<directories check_all="yes">/etc/cron.d,/etc/systemd/system</directories>
```

```bash
sudo /var/ossec/bin/wazuh-control restart
```

> **Remember:** file-integrity monitoring is a *change* detector. Files that already
> existed before you added a folder stay silent until someone modifies them.

✅ **Checkpoint:** agent restarted with no config errors.

---

## Phase 6 — Deploy the SAF pipeline (10 minutes)

The pipeline must run **on the manager** (it reads the indexer at `https://localhost:9200`).

**Step 6a — copy the files** 💻 **workstation**

```powershell
scp -i <KEY>.pem wazuh_vt_pipeline.py dashboard.py ec2_bundle/* ubuntu@<EC2_PUBLIC_IP>:~/live/
```

**Step 6b — create the server-side `.env`** 🖥️ **manager**

```bash
cd ~/live
cp .env.example .env
nano .env        # fill in EVERYTHING:
```

```
VT_API_KEY=<YOUR_VT_KEY>
DISCORD_WEBHOOK=<YOUR_DISCORD_WEBHOOK_URL>
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_USER=admin
WAZUH_PASS=<generated admin password>
POLL_SECONDS=5
NOTIFY_LEVEL=7
```

**Step 6c — start it**

```bash
mkdir -p output
chmod +x run.sh
./run.sh
```

**What success looks like:**

```
Started. Polling https://localhost:9200 every 5s from now-5m
Poll done: 0 alert(s)        ← repeats every 5 seconds
```

❌ **`Missing env vars: …`** → a required key is blank in `.env`
❌ **Network error / 401** → wrong `WAZUH_PASS`, or indexer not running (Phase 3b)

✅ **Checkpoint:** `Poll done` lines every 5s. Stop it with Ctrl+C for now — Phase 8
makes it start automatically.

---

## Phase 7 — Dashboard (optional, 5 minutes)

🖥️ **manager**

```bash
cd ~/live
pip install --break-system-packages streamlit      # or use a virtualenv

nohup python3 -m streamlit run dashboard.py \
  --server.port 8501 --server.address localhost --server.headless true \
  > dashboard.log 2>&1 &

curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8501   # expect: 200
```

**View it from your machine** (it's localhost-only by design — never expose port 8501):

💻 **workstation**

```powershell
ssh -i <KEY>.pem -L 8501:localhost:8501 ubuntu@<EC2_PUBLIC_IP>
# then open http://localhost:8501 in your browser
```

✅ **Checkpoint:** the console shows four KPI numbers (they're 0 until the first alert
passes — that's Phase 8).

---

## Phase 8 — First live test (5 minutes)

**Step 8a — drop the EICAR test file** 📟 **agent**

```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_test.txt
logger -t wazuh-test "SAF first test $(date +%s)"
```

> Tip: generate test files with `echo`, not a browser download — network filters often
> intercept them.

**Step 8b — wait ~90 seconds** (file-integrity + indexing lag), then check 🖥️ **manager**:

```bash
cd ~/live
tail -f pipeline.log
# expect: VirusTotal checked file … -> (63, 0, 'critical')

python3 ec2_bundle/check_db.py
# expect: a 'critical' indicator row + notification status 'sent'
```

✅ **Final checkpoint:** a HIGH Discord card with a VirusTotal link, a `critical` row in
the database, and (if Phase 7) KPIs > 0 on the dashboard. **You have a working system.**

---

## Phase 9 — Make it survive reboots (2 minutes)

The pipeline and dashboard are ordinary processes — a server reboot kills them silently
(this has cost real coverage hours). Install both `@reboot` entries:

🖥️ **manager**

```bash
crontab -e
```

Add these two lines:

```cron
@reboot cd $HOME/live/ec2_bundle && set -a && . ./.env && set +a && nohup python3 wazuh_vt_pipeline.py > pipeline.log 2>&1 &
@reboot cd $HOME/live && nohup python3 -m streamlit run dashboard.py --server.port 8501 --server.address localhost --server.headless true > dashboard.log 2>&1 &
```

```bash
# verify
crontab -l | grep -c @reboot        # → 2
ps aux | grep "[w]azuh_vt"          # → pipeline process listed
```

> **Health-check habit:** if Discord goes quiet for more than 5 minutes, run the `ps`
> check above *before* suspecting the files. Also `sudo systemctl enable wazuh-agent`
> on every agent so endpoints survive reboots too.

✅ **Checkpoint:** reboot the manager (or just wait for one) — pipeline and dashboard
come back on their own.

---

## Troubleshooting

| Symptom | Where to look | Fix |
|---------|---------------|-----|
| Discord silent after a while | `tail -f pipeline.log` on manager | `Network error` → indexer down, restart Wazuh services; `401` → wrong `WAZUH_PASS` |
| Process dead after a server reboot | `crontab -l` | Re-add the Phase 9 `@reboot` lines, then `restart_persist.sh` |
| `VT rate limited` in logs | `pipeline.log` | Normal under bursts — the pipeline backs off 60s automatically. Don't lower the 15s throttle |
| `INVALID_API_KEY` | `.env` | Create a fresh key at virustotal.com, update, restart |
| No file-change alerts | agent's `ossec.conf` | Confirm `<directories>` entries exist (Phase 5), restart the agent |
| Agent red / offline | agent's `ossec.conf` + network | Re-do Phase 4: remove agent, re-add, re-import key, check `<address>` and port 1514 reachability |
| `Database not found` on dashboard | manager | Run the dashboard from the folder containing `output/security.db` (`~/live`) |
| EICAR gives `unknown` verdict | how you created the file | Recreate with `echo` (browser downloads get intercepted/modified) |
| VT verdict looks stale | database | 24h cache — run `python3 scripts/ops/clear_cache.py` to force re-checks |
| Too many Discord cards | `.env` | Leave `GENERIC_COOLDOWN`/`AUTH_COOLDOWN` at defaults (24h/15min); see README filter tiers |

---

## Secrets hygiene

* `.env` holds **every** secret (VT key, webhook, Wazuh password) and is **git-ignored** —
  only `.env.example` gets committed.
* `*.db`, `*.log`, `*.pem`, `*.zip` are git-ignored too (see `.gitignore`).
* Rotate the VT key / webhook immediately if either ever appears in a public post
  (`scripts/ops/rotate_key.sh` automates the key rotation).

---

## Day-2 operations (`scripts/ops/`)

Ongoing maintenance once the system is live. Copy them to the manager alongside the
pipeline (`~/live/ec2_bundle/`) — they assume that path.

### Safe scripts

| Script | Purpose | When to use |
|--------|---------|-------------|
| `alive_check.sh` | Process + last 3 log lines | Discord quiet >5 min, or any "is it up?" doubt |
| `morning_check.sh` | Recent log activity + test-evidence hunt | Daily status / demo prep |
| `snapshot.sh` | Timestamped `.env` backup (`.env.saved-YYYYMMDD`) | **Before** any config change |
| `restart_persist.sh` | Start pipeline + ensure `@reboot` cron exists | After restarts, or if cron went missing |
| `rotate_key.sh <NEW_VT_API_KEY>` | Update VT key, clear cache, restart | Key rotation (run `snapshot.sh` first) |
| `clear_cache.py` | Wipe `alerts` + `indicators` tables | Stale VT verdicts after a key change |
| `test_card.py` | Send a test Discord card (reads `DISCORD_WEBHOOK` from env) | Verify notify path without dropping test files |

```bash
# typical key-rotation flow
./snapshot.sh
./rotate_key.sh <NEW_VT_API_KEY>
./alive_check.sh
```

### ⚠️ Destructive scripts (`scripts/ops/danger/`)

Both prompt for explicit confirmation before doing anything:

| Script | What it destroys |
|--------|------------------|
| `reset_prod.sh` | Resets `.env` to production defaults **and deletes all alert/indicator history** |
| `cleanup_ec2.sh` | Full teardown: stops pipeline, removes cron, **deletes `~/live`** (code, `.env`, DB, logs) |

> Never run these on a deployment you intend to keep — they're for decommissioning or
> recovering from badly-tuned experiments.
