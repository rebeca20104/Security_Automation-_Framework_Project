# SAF — Security Automation Framework

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Wazuh](https://img.shields.io/badge/Wazuh-4.x-e65c00)
![VirusTotal](https://img.shields.io/badge/VirusTotal-APIv3-31a354)
![Status](https://img.shields.io/badge/status-live--tested-brightgreen)

**SAF** watches a Wazuh SIEM, enriches every suspicious indicator with VirusTotal, scores
the risk, sends a Discord alert, and keeps a full audit trail — no commercial SOAR needed.

```
Wazuh SIEM  →  Python pipeline  →  VirusTotal  →  Risk engine  →  Discord  →  SQLite + JSON audit
```

Everything in the live path is real: real agents, a real manager, real VirusTotal
verdicts, real Discord cards. No mocks.

> **New here?** Start with **[SETUP.md](SETUP.md)** — it takes you from an empty machine
> to a working deployment, one checkpoint at a time. Come back to this file for the
> big picture.

---

## Values you'll replace

Every file in this project uses the same `<>` markers. Collect your own values before
you start:

| Marker | What it means |
|--------|---------------|
| `<EC2_PUBLIC_IP>` | Public IP of your Wazuh manager server |
| `<MANAGER>` / `<MANAGER_IP>` | Same thing — the manager's address |
| `<KEY>.pem` | Your SSH private key file |
| `<NAME>` / `<AGENT_NAME>` | A name you choose for each monitored machine |
| `<generated admin password>` | Wazuh's admin password (shown at install time) |
| `<NEW_VT_API_KEY>` | Your VirusTotal API key |
| `<WATCHED_PATH>` | A folder you told Wazuh to monitor (e.g. `/tmp`) |
| `<user>` | Your Linux username |

> ⚠️ Never put real secrets (keys, passwords, webhook URLs) into a file you might
> commit — they belong in `.env`, which is git-ignored.

---

## How it works

A Wazuh alert fires on an endpoint → the pipeline polls the indexer, extracts file hashes
and public IPs → each indicator is enriched via the VirusTotal API → a risk level and
recommended action are computed → malicious verdicts post a compact Discord card → every
step is written to an auditable SQLite + JSON trail.

**Proven live:** EICAR file **63/0** engines, malicious IP **6/2**, Mimikatz-family
**56–65/0** — all delivered to Discord with VirusTotal report links.

```
Wazuh agent ──────1514/TCP──────▶ Wazuh manager + indexer :9200
                                        │  poll every 5s
                                        ▼
                              wazuh_vt_pipeline.py
                              ├─ extract: syscheck sha256/md5, public src/dst IP
                              ├─ enrich: VirusTotal v3 (15s throttle, 24h cache)
                              ├─ risk:   HIGH / MEDIUM / LOW (+ action)
                              ├─ notify: Discord embed (tiered filter protocol)
                              └─ audit:  security.db + audit_log.json
```

---

## Two ways to try it

| Path | Time | What you need | Guide |
|------|------|---------------|-------|
| **A. Local test** | ~5 min | Just Python | [SETUP.md §2](SETUP.md) |
| **B. Full live system** | ~30–45 min | A server, a second machine to monitor, free API keys | [SETUP.md §3 onward](SETUP.md) |

**Path A** runs the whole enrich → risk → notify → audit chain on a sample alert — no
Wazuh, no server. Do this first; it proves your Python environment and (optionally) your
Discord webhook before you invest in infrastructure.

**Path B** builds the real thing: Wazuh manager on a server, an agent on a machine you
monitor, the pipeline running 24/7, and a web dashboard.

---

## What you get

| Feature | What it does |
|---------|--------------|
| **IOC extraction** | Pulls SHA256/MD5 hashes and public IPs out of Wazuh alerts |
| **VirusTotal enrichment** | Checks each indicator, throttled for the free tier (4 req/min), cached 24h |
| **Risk engine** | Classifies CRITICAL / SUSPICIOUS / CLEAN / UNKNOWN with a recommended action |
| **Tiered Discord alerts** | 3-tier filter so Discord shows signal, not noise (details below) |
| **Full audit trail** | SQLite tables + JSON-lines log for every alert and notification |
| **Web dashboard** | Read-only Streamlit console: KPIs, indicators, per-agent counts, CSV export |
| **Self-healing** | Cron `@reboot` restarts the pipeline and dashboard after a reboot |
| **Ops scripts** | Health checks, key rotation, backups — see [SETUP.md §11](SETUP.md) |

---

## Repository layout

| Path | Purpose |
|------|---------|
| `wazuh_vt_pipeline.py` | The live pipeline (runs on the manager, polls forever) |
| `dashboard.py` | Streamlit triage console (read-only) |
| `src/` | Local test harness — runs a single alert on your machine |
| `data/sample_alert.json` | Sample alert for the local test |
| `ec2_bundle/` | Deploy + verify scripts ([DEPLOY.md](ec2_bundle/DEPLOY.md), `run.sh`, `SAF_test.sh`) |
| `scripts/ops/` | Day-2 operations: health checks, backups, key rotation ([SETUP.md §11](SETUP.md)) |
| `docs/` | [Test matrix](docs/TEST_MATRIX.md) · [SOAR equivalence](docs/SOAR.md) |
| `screenshots/` | Add your own demo captures here |
| `output/` | Runtime artifacts (git-ignored, kept via `.gitkeep`) |

---

## Alert filtering (why Discord stays readable)

A raw SIEM floods a chat channel. SAF applies three tiers:

| Tier | Trigger | Behavior |
|------|---------|----------|
| **Tier 1 — always** | VT `malicious ≥ 5` or Wazuh level ≥ 12 | Immediate card |
| **Tier 2 — once + cooldown** | Weak VirusTotal hits | Once per indicator per 24h |
| | Auth-failure rules (5503, 5504, 5716, 5720, 5760, 5763) | One card per agent per 15 min |
| | Generic alerts at level 7+ | One card per agent+rule per 24h (`GENERIC_COOLDOWN`) |
| **Tier 3 — log only** | PAM/session noise, temp files (`.part`, `.tmp`, `.crdownload`…), noisy paths | Logged, never sent |

Plus a hard guard: max 10 Discord posts/minute with automatic backoff — overflow is
logged, never silently dropped.

**What a card looks like:**

```
HIGH — Malicious file (63/0 engines)
Scope:  agent-01 · Rule 550 (L7)
Target: /home/user/Downloads/eicar.com
SHA:    131f95c5…ffbdfd8267        Report: <VirusTotal link>
Action: Isolate host + analyst review
```

---

## Configuration reference (`.env`)

Copy `.env.example` → `.env`, fill in the two required keys, and optionally tune these:

| Variable | Default | Meaning |
|----------|---------|---------|
| `VT_API_KEY` | *(required)* | VirusTotal API key |
| `DISCORD_WEBHOOK` | *(required)* | Discord channel webhook URL |
| `WAZUH_INDEXER_URL` | `https://localhost:9200` | Indexer endpoint (manager host only) |
| `WAZUH_USER` / `WAZUH_PASS` | `admin` / *(required)* | Indexer credentials |
| `CRITICAL_THRESHOLD` | `5` | VT malicious count for a CRITICAL verdict |
| `POLL_SECONDS` | `30` (demo: `5`) | Indexer poll interval |
| `NOTIFY_LEVEL` | `99` = malicious-only | Minimum Wazuh level for generic cards (demo: `7`) |
| `GENERIC_MIN_LEVEL` | `7` | Floor for Tier-2 generic cards |
| `AUTH_COOLDOWN` | `900` | Auth-failure card cooldown, seconds (15 min) |
| `GENERIC_COOLDOWN` | `86400` | Generic card cooldown, seconds (24h per agent+rule) |
| `SUSP_COOLDOWN` | `86400` | Suspicious indicator cooldown, seconds (24h) |
| `MAX_PER_MIN` | `10` | Discord send budget per minute |
| `SKIP_PREFIXES` | `/tmp/gdk-,/tmp/firefox-,…` | Comma-separated noisy path prefixes |
| `VERIFY_TLS` | `false` | Indexer TLS verification (self-signed certs) |
| `DB_PATH` | `output/security.db` | SQLite location |

Fixed in code: VT throttle 15s, result cache 24h.

---

## Expected results (does my install work?)

| Case | Input | Expected |
|------|-------|----------|
| Clean domain | `sample_alert.json` | MEDIUM risk, VT 0/0, Discord sent |
| Known-bad file | EICAR test file in a watched folder | HIGH, VT 63/0, Discord card ~90s later |
| Malicious IP | Alert containing `213.108.220.58` | HIGH, VT 6/2 |
| Unknown file | Fresh random bytes | `unknown` verdict, **no** Discord (correct: no spam) |
| Noise alert | PAM/sudo noise | Skipped with `no hash/public IP` in the log |

Full runbook with exact commands and evidence locations: **[docs/TEST_MATRIX.md](docs/TEST_MATRIX.md)**.

---

## Known limits (honest)

* **FIM watches paths, not disks.** Files outside the configured `<syscheck>` folders are
  invisible, and files that existed before watching stay quiet until modified — it's a
  change detector, not an antivirus scan.
* **Container zips score as containers** — unzip the exe inside for a reliable verdict.
* **Drop-to-Discord ≈ 60–90s** (file-integrity + indexing lag dominates; the pipeline
  itself adds only ~10s).
* **No Shuffle/Tines node** — the pipeline is the orchestrator
  (see [docs/SOAR.md](docs/SOAR.md)).
* **Free VirusTotal quota is 4/min** — the throttle and 24h cache are sized for it.

---

## Security notes

* `.env` (all secrets), `*.db`, `*.log`, `*.pem`, `*.zip` are git-ignored — commit only
  `.env.example`. Share keys over a private channel, never in issues or chats.
* Use synthetic test indicators (EICAR) for demos — never real customer data.
* The dashboard binds to `localhost` only — reach it through an SSH tunnel
  (`ssh -L 8501:localhost:8501 …`), never by opening port 8501 to the internet.

---

## Documentation

| Document | Read it when |
|----------|--------------|
| [SETUP.md](SETUP.md) | You're setting this up for the first time (start here) |
| [ec2_bundle/DEPLOY.md](ec2_bundle/DEPLOY.md) | You're at the terminal deploying right now |
| [docs/TEST_MATRIX.md](docs/TEST_MATRIX.md) | You want to verify each feature with evidence |
| [docs/SOAR.md](docs/SOAR.md) | You're comparing SAF against a SOAR design (reviewers) |
