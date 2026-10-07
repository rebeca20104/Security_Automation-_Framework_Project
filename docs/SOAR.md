# SOAR Equivalence Note

> **Who needs this file:** reviewers and architects comparing SAF against a SOAR design
> (Shuffle, Tines, Cortex XSOAR…). **If you're just installing SAF, skip this page** —
> nothing here is needed to run the system.

## Why this file exists

The reference design for this project describes a SOAR workflow with Shuffle/Tines nodes:
**parse → enrich → decide → notify → audit**. SAF performs the same five functions
inside the pipeline + Wazuh manager, so no separate SOAR product is required.

## Mapping

| SOAR function | Reference tool | SAF implementation |
|---------------|----------------|--------------------|
| **Parse** | Alert ingestion + IOC extraction | `extract_indicators()` — syscheck SHA256/MD5, public src/dst IPs |
| **Enrich** | Threat-intel API lookups | `vt_client.enrich_indicator()` — VirusTotal v3, 15s throttle, 24h cache |
| **Decide** | Playbook / risk scoring | `risk_engine.calculate_risk()` → level (HIGH/MEDIUM/LOW) + action |
| **Notify** | Slack / email / ticketing | `notifier.send_discord()` — tiered filter (always / cooldown / log-only) |
| **Audit** | Case management | SQLite (`alerts`, `indicators`, `notifications`, `cooldowns`) + JSON-lines log |

## Handoff contract

`notify_discord()` carries everything a downstream SOAR would need:

| Field | Source |
|-------|--------|
| `alert_id`, `timestamp` | Wazuh alert |
| `agent`, rule id, rule level | Wazuh rule context |
| `indicator`, `indicator_type` | `extract_indicators()` |
| malicious / suspicious engine counts, VT report URL | VirusTotal lookup |
| Risk level + recommended action | `calculate_risk()` |

To integrate a real SOAR, replace the Discord webhook call with a POST to your SOAR's
webhook endpoint — same payload, same contract. Decision logic and the audit trail stay
untouched.

## Why the pipeline *is* the orchestrator

* **One process, one audit trail** — enrichment, decision, notification, and audit share
  the same SQLite database, so every action is traceable end-to-end.
* **No extra infrastructure** — nothing to host, license, or keep in sync.
* **Same extensibility point** — swapping the notification sink is a single function
  call, exactly like replacing a node in a visual playbook.

## When you'd still want an external SOAR

* Multi-tenant/MSSP case queues per customer
* Complex approval chains (legal/HR/compliance sign-off)
* 50+ pre-built third-party connectors
* Pre-built compliance report templates

For single-organization alert triage, the built-in pipeline covers the SOAR value
without the platform cost.
