# Test Matrix

Two guided test runs with copy-pasteable commands. **Run A** needs nothing but Python —
do it first. **Run B** needs a live deployment ([SETUP.md](../SETUP.md)).

Every test answers the same four questions: *goal → command → expected output → where
the evidence lands.*

---

## Run A — Local (5 minutes, no Wazuh)

💻 **workstation**, from the repository root. Prerequisite: Phase 1–2 of SETUP.md
(`pip install`, `.env` filled in).

### A1 · Offline dry run — proves the chain without any API calls

```powershell
python src/main.py --sample data/sample_alert.json --dry-run
```

✅ **Expect:** `example.com -> risk=MEDIUM action=ALERT_AND_INVESTIGATE notified=False`
✅ **Evidence:** `output/audit_log.json` gets a line with `"status": "DRY_RUN"`
❌ If this fails, nothing after it can work — fix your Python environment first.

### A2 · Live enrichment — real VirusTotal + real Discord

```powershell
python src/main.py --sample data/sample_alert.json
Get-Content output/audit_log.json | Select-Object -Last 1
```

✅ **Expect:** `notified=True`; audit shows `"status": "OK"`; a Discord embed arrives
❌ `INVALID_API_KEY` → fix `VT_API_KEY` · `RATE_LIMITED` → wait 60s, rerun (4/min free tier)

### A3 · No-indicator alert — noise must not notify

Use an alert with no hashes/IPs (e.g. remove the `indicators` block from the sample).

✅ **Expect:** `No indicators found in alert` warning, **no** Discord message

### A4 · Offline notifier — webhook absent must not crash

Unset `DISCORD_WEBHOOK` and run A2 again.

✅ **Expect:** `No Discord webhook — dry-run, skipping send.` — process exits cleanly

---

## Run B — Live deployment (needs SETUP.md Phases 3–9)

### B1 · Known-bad file — the headline test 📟 agent

```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_test.txt
```

Wait ~90s, then 🖥️ manager:

```bash
tail -50 ~/live/pipeline.log | grep VirusTotal     # → (63, 0, 'critical')
python3 ~/live/ec2_bundle/check_db.py             # → verdict 'critical', notification 'sent'
```

✅ **Expect:** HIGH Discord card with a VirusTotal link · **Evidence:** `pipeline.log`,
`security.db` (`indicators` + `notifications` tables)

> Generate test files with `echo`, not a browser — network filters intercept downloads.

### B2 · Malicious IP — enrichment beyond files 📟 agent / alert source

Trigger any alert whose `srcip` is `213.108.220.58` (known-bad in VirusTotal).

✅ **Expect:** VT `(6, 2, 'critical')`, Discord HIGH card

### B3 · Unknown file — unknowns must stay silent 📟 agent

```bash
head -c 512 /dev/urandom > /tmp/watchedfolder/random_$RANDOM.bin
```

✅ **Expect:** verdict `unknown` in `check_db.py`, **no** Discord card (correct behavior)

### B4 · No-IOC noise — VT must not be called 🖥️ manager

Trigger any PAM/sudo event (e.g. `sudo -n true`).

✅ **Expect:** `pipeline.log` shows `no hash/public IP, VirusTotal not used`

### B5 · Filter tiers — verify the cooldowns 🖥️ manager

Drop two *different* weak indicators or trigger the same generic rule twice.

✅ **Expect (in `pipeline.log`):**
- repeated generic rule → `Tier-2 generic cooldown suppress (<agent> rule <id>)`
- repeated auth failure → `Tier-2 auth cooldown suppress (<agent> <id>)`
- temp file (`.part`/`.tmp`) or noisy path → `Tier-3 skip noisy path`

### B6 · Rate limits — must survive, not crash 🖥️ manager

Burst more than 4 VT lookups within a minute (drop several unique files quickly).

✅ **Expect:** `VT rate limited, sleeping 60s` in the log, pipeline keeps polling.
Discord side: `Discord budget exceeded` / `429 … retry_after` — overflow is logged,
never silently dropped.

### B7 · Bad API key — must fail loudly, not die 🖥️ manager

Set `VT_API_KEY=invalid` in `.env`, restart, drop a new test file.

✅ **Expect:** `INVALID_API_KEY` status logged, `Poll done` lines **continue**
✅ Restore the real key afterward (`snapshot.sh` first, `rotate_key.sh` for rotation).

### B8 · Dormant file — document the FIM limit 📟 agent

Place a file in a watched folder *before* adding that folder to `<syscheck>`, or note
that pre-existing files stay quiet.

✅ **Expect:** silence until the file is **modified** — this is the documented
change-detector behavior (README → Known limits), not a bug.

### B9 · Reboot persistence 🖥️ manager

```bash
crontab -l | grep -c @reboot     # → 2
sudo reboot                      # then, after boot:
ps aux | grep "[w]azuh_vt"       # → pipeline listed again
curl -s -o /dev/null -w '%{http_code}' http://localhost:8501   # → 200
```

✅ **Expect:** pipeline + dashboard return automatically via `@reboot` cron.

### Quick probe

`ec2_bundle/SAF_test.sh` (run on the agent) covers B1 plus auth/sudo probes and prints
PASS/FAIL per step:

```bash
bash SAF_test.sh
# NEXT: wait 90s, then on the manager: tail -5 pipeline.log ; python3 check_db.py
```

---

## Evidence collection (for reports/demos)

| Artifact | Where it lives |
|----------|----------------|
| Discord cards | your alert channel |
| Pipeline log | `~/live/pipeline.log` (manager) |
| SQLite evidence | `output/security.db` — `alerts`, `indicators`, `notifications` |
| JSON audit trail | `output/audit_log.json` (local runs) |
| Per-agent summary | `python3 ec2_bundle/check_agents.py` |
| Dashboard KPIs | `localhost:8501` via SSH tunnel |

**Suggested screenshots** (drop into `screenshots/`): Wazuh agents tab green ·
threat-hunting view of the FIM event · Discord HIGH card · `pipeline.log` VT line ·
`check_db.py` output · dashboard KPIs.

---

## Pre-demo checklist

- [ ] Pipeline alive: `ps aux | grep "[w]azuh_vt"`
- [ ] Cron present: `crontab -l | grep -c @reboot` → 2
- [ ] Dashboard answers: `curl … http://localhost:8501` → 200
- [ ] Expected agents green on the Wazuh dashboard
- [ ] `.env` has valid keys (never committed)
- [ ] One fresh B1 run landed in Discord end-to-end
