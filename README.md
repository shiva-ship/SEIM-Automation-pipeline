# SIEM Automation Pipeline

**Detection-as-code pipeline that turns the SecurOTy firmware manager's audit log into normalized, enriched, SIEM-ready events and tested alerts.**

Companion to [firmware-updater-gruppe3](https://github.com/shiva-ship/firmware-updater-gruppe3) (SecurOTy). It works with any SIEM: events go out as RFC 5424 syslog over TLS, Splunk HEC or NDJSON over HTTP, and the detections are standard Sigma rules that convert to Splunk SPL and Elastic ES|QL/EQL.

```
 SecurOTy audit.log ──► collect ──► normalize ──► enrich ──► detect ──► forward ──► SIEM
   (JSON lines,         (tail +     (ECS fields)  (asset,    (Sigma     (syslog-TLS,
    rotating)           checkpoint)               maint.     rules,     HEC, NDJSON;
                                                  window)    tested)    disk spool)
```

## Why it's built this way

Most SIEM automation fails on **noisy alerts and inconsistent data**, not on missing tools. This pipeline addresses that directly:

| Problem | What the pipeline does |
|---|---|
| Parsers break silently | One parser per source, unit-tested against SecurOTy's real line format; unparseable lines are counted |
| Every source uses different field names | Everything is mapped to the **Elastic Common Schema** (`event.action`, `source.ip`, `user.id`, ...) |
| Alerts without context can't be triaged | Asset inventory (zone, criticality, owner) and maintenance windows are added **before** detection |
| Untested rules create noise | Every rule must have true-positive **and** true-negative test cases, or CI fails |
| SIEM lock-in | Rules are **Sigma**; `siempipe convert` produces Splunk / Elastic queries |
| Lost events during SIEM outages | Checkpointed file tailing (at-least-once) plus a disk spool with retry/backoff per sink |
| Secrets in configs | Tokens only come from environment variables; the SecurOTy audit log itself never contains secrets |

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev,sigma]"

# 1. Run the detection test suite
siempipe test-rules

# 2. Replay an attack scenario and see the alerts
siempipe replay samples/securoty_audit_attack.log --timezone Europe/Berlin -c config/pipeline.example.yml

# 3. Convert the rules for your SIEM
siempipe convert --target splunk      # or esql | eql | lucene

# 4. Run continuously against a live SecurOTy installation
cp config/pipeline.example.yml config/pipeline.yml   # adjust paths and outputs
cp config/assets.example.yml   config/assets.yml
export SIEMPIPE_HEC_TOKEN=...                        # only if you use an HTTP sink with a token
siempipe run -c config/pipeline.yml
```

The replay of the sample log (one simulated night: a device swap, a rogue MAC, brute force, KeePass guessing, covering tracks, a rogue agent and an insecure redeploy) prints:

```
# 31 lines, 31 events, 0 unparsed, 13 alerts
#      1  SecurOTy agent found device not matching the KeePass inventory
#      1  SecurOTy agent saw new devices on the OT network
#      1  SecurOTy login brute force from one source
#      1  SecurOTy KeePass master password guessing
#      ...
```

## Detections

All rules live in [`detections/rules/`](detections/rules), with test cases in [`detections/tests/`](detections/tests).

| Rule | Level | Logic | ATT&CK |
|---|---|---|---|
| Login brute force from one source | high | ≥5 `auth.login_failed` per `source.ip` in 5 min | T1110.001 |
| KeePass master password guessing | high | ≥3 `keepass.unlock_failed` per `user.id` in 10 min | T1555.005 |
| Agent with unknown/revoked/expired certificate | high | `agent.auth_failed` reason `unknown_revoked_or_expired` | ICS T0848 |
| Device does not match KeePass inventory | high | `agent.result` overall `mismatch` | ICS T0849 |
| Firmware update run failed or aborted | high | `update.finished`, not a dry run, failed or aborted > 0 | ICS T0857 |
| Agent deployed over insecure Docker connection | high | `agent.deploy_start` with `insecure: true` | T1562 |
| Agent API: disallowed source / no certificate | medium | `agent.auth_failed` reason `source_not_allowed` or `no_peer_certificate` | ICS T0846 |
| New devices on the OT network | medium | `assets.neighbors_new` | ICS T0848 |
| Update outside a maintenance window | medium | `update.started` while `in_maintenance_window` is false | ICS T0857 |
| Discovered-asset inventory cleared | medium | `assets.cleared` | ICS T0872 |
| Agent result for a task it does not own | medium | `agent.result_rejected` | ICS T0856 |
| Agent PKI (re)initialized | medium | `pki.initialized` | T1553.004 |
| Firmware released without STOP/RUN test | low | `firmware.released` with `stop_run_tested: false` | – |
| Agent revoked or decommissioned | low | `agent.revoked`, `agent.decommissioned` | – |

### Adding a rule

1. Add `detections/rules/<name>.yml` (Sigma, `logsource: {product: securoty, service: audit}`, a new UUID `id`).
2. Add `detections/tests/<name>.yml` with at least one `expect: >0` and one `expect: 0` case, using raw SecurOTy log lines.
3. Run `siempipe test-rules` and `siempipe convert --target splunk`.

The in-pipeline engine supports a practical Sigma subset: selections, value lists, the `contains` / `startswith` / `endswith` / `re` / `cidr` / `all` / `gt` / `gte` / `lt` / `lte` modifiers, `and` / `or` / `not` / `1 of` / `all of` conditions, and `event_count` correlation rules. Anything outside that subset is rejected at load time, so unsupported rules never fail silently.

> **Window semantics:** the in-pipeline engine uses a sliding window. Splunk and ES|QL conversions use fixed time buckets (`bin _time span=5m`), so a burst that spans a bucket boundary can be missed there. EQL `sequence ... with maxspan` is the closest match.

## Event model

Every SecurOTy audit action is mapped to ECS `event.category`, `event.type` and `event.outcome` (see `ACTIONS` in [`src/siempipe/sources/securoty.py`](src/siempipe/sources/securoty.py)). The original fields are kept under `securoty.*`, and the raw line under `event.original`.

```json
{
  "@timestamp": "2026-11-16T22:47:01.111Z",
  "event": {"kind": "event", "module": "securoty", "dataset": "securoty.audit",
            "action": "auth.login_failed", "category": ["authentication"],
            "type": ["start"], "outcome": "failure", "original": "..."},
  "source": {"ip": "10.20.0.66"},
  "observer": {"vendor": "Gruppe 3", "product": "SecurOTy"},
  "securoty": {"ip": "10.20.0.66"}
}
```

Alerts use `event.kind: alert`, together with `rule.*`, `event.severity` (1–99), `tags` (ATT&CK), the asset context of the triggering event, and `siempipe.related_events` (the raw lines that caused the alert).

## Outputs

| `type` | Use for | Notes |
|---|---|---|
| `syslog` | Any SIEM (Splunk, Sentinel via AMA, QRadar, Wazuh, Graylog, Elastic Agent) | RFC 5424, `udp` / `tcp` / `tls`, RFC 6587 octet counting, facility 13 (log audit) |
| `http` | Splunk HEC (`format: splunk_hec`), Logstash / Vector / webhooks (`format: ndjson`) | `token_env` names the environment variable that holds the token |
| `file` | Local archive, debugging | JSON lines |
| `stdout` | Containers, piping | JSON lines |

`syslog` and `http` sinks are wrapped in a disk spool (`state/<sink>.spool.jsonl`, capped at 100k records) with exponential backoff, so nothing is lost while the SIEM is unreachable.

## Notes on the SecurOTy log format

These are findings from building the parser. They could be improved in SecurOTy itself:

- **Timestamps are local time without an offset** (Python logging `asctime`). Set `timezone:` on the source; logging ISO 8601 UTC would remove that ambiguity.
- **Dicts and lists are logged as Python `repr`**, because `_safe()` calls `str()`. Examples are `update.finished.summary` and `assets.neighbors_new.macs`. The parser decodes them, but values over 200 characters are truncated and can't be decoded. Emitting nested JSON would be more robust.
- **`update.started` does not record whether a PLC STOP/RUN was approved** (`approve_plc_stop_run`), or which devices were in the plan. Adding both would allow a high-severity rule for "PLC stopped outside maintenance window".
- **Successful agent authentications are not logged**, only failures. A success event would allow correlations like "agent connects from a new IP".

## Repository layout

```
src/siempipe/
  sources/securoty.py   parser: audit line -> ECS event
  enrich.py             asset inventory + maintenance windows
  detect.py             Sigma-subset engine with event_count correlations
  ruletest.py           detection test runner (true-positive and true-negative cases required)
  tail.py               rotation-safe file follower with checkpoint
  sinks.py              stdout / file / syslog / HTTP + disk-spooled retry
  pipeline.py, cli.py   wiring and `siempipe` command
detections/rules/       Sigma rules
detections/tests/       rule test cases (raw SecurOTy log lines)
config/                 example pipeline and asset configs
samples/                attack scenario for replay and demos
tests/                  unit tests (pytest)
```

## Roadmap

- Response playbooks in tiers: notify → create ticket → human-approved actions such as revoking an agent or pausing update runs. Nothing touches the OT network automatically.
- Additional sources: firewall (ads-tec) syslog, and switch / PLC event logs.
- Persisted correlation state across restarts.
- Docker image and a compose file with a local Wazuh or Elastic for demos.
