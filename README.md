# EdgeSight - local-first, secure AIOps observability (CICADA 2026)

Tier 1 **Collector** (customer environment) keeps raw logs and secrets local. Tier 2 **SaaS** (multi-tenant) receives
allow-listed metadata only and turns it into health states, correlated incidents and explainable recommendations.

## Run
    docker compose up --build            # or locally: pip install -r requirements.txt, then
                                         #   python saas/app.py   and   python collector/collector.py
    SaaS dashboard      http://localhost:8000          (tenant switcher: acme / globex)
    Collector (acme)    http://localhost:9000          raw logs + EGRESS PROOF PANEL + scenario buttons
    Collector (globex)  http://localhost:9001
Warm-up: ~40s of baseline learning before anomaly detection starts (WARMUP_WINDOWS, WINDOW_SECONDS are env vars).

## Architecture (trust boundary between the two tiers)
    [sources] -> collect -> parse -> aggregate (5s windows, UTC) -> local anomaly detection (EWMA baselines)
              -> POLICY allow-list (default deny) -> secret scanner (2nd net) -> EGRESS LOG (proof) -> OUTBOX (SQLite, durable)
    ============================== TRUST BOUNDARY: HTTPS + collector token ==============================
    SaaS ingest -> token->tenant, residency check, server-side allow-list, dedupe by payload_id, order by event time
              -> health (Excellent/Good/Fair/Poor) -> correlation -> explainable recommendation -> approval + audit

## What leaves / what stays (allow-list = collector/policy.yaml)
Leaves: payload_id, collector_id, region, source_tz, UTC event time, pseudonymous source_id, role, metrics (cpu, mem, disk,
latency, loss, bandwidth), failed-login count + risk, error/warn counts, anomalies (metric/value/baseline/z/severity), collector health.
Stays: raw log lines, user emails, client IPs, hostnames, card numbers, passwords, tokens, sample error text.

## Rubric map
| Requirement | Where |
|---|---|
| Egress proof panel | Collector UI :9000, right side (allowed/blocked, dropped fields, delivered flag, full payload) |
| Raw stays local | Collector UI left side shows secrets (highlighted red); SaaS "Run leak scan" returns 0 matches |
| Two-tier + auth | token per collector; tenant derived from token only; TLS in production (see limitations) |
| Local AIOps | collector `detect()` adaptive EWMA baselines (not static thresholds) |
| Correlation + explainability | SaaS `incidents()`: 28 alerts -> 1 incident, weighted contributing signals, reasoning path, confidence |
| 4 health states | SaaS `health()`: configurable thresholds (`/api/thresholds`), reasons shown, stale data => Poor |
| Failure handling | outbox + ack; "Cut SaaS link" then "Restore": backlog drains, 0 lost, 0 duplicates |
| Idempotent + out-of-order | PK on payload_id; "Replay duplicates"; "Out-of-order ON"; SaaS orders by event time |
| Global-ready | UTC + source_tz everywhere, per-tenant region, residency rejection (403), INGEST_REGION per regional deploy |
| Multi-tenant | acme / globex; every query is tenant-scoped; switch tenant in the dashboard header |
| Safe remediation | Approve button: policy checks, named approver, SIMULATED action, rollback plan, audit trail |

## 5-minute demo script
1. Show architecture + trust boundary (30s).
2. Open collector :9000 and SaaS :8000 side by side. Click **Log with secrets**: red secrets in raw logs; egress panel shows
   `dropped by policy: client_ips, hostname, sample_error_line`; SaaS feed shows metrics only. Click **Run leak scan** -> 0 matches.
3. Click **Network latency + loss**: incident "Network degradation at gateway impacting web", N alerts -> 1, contributing signals,
   reasoning, confidence. Click **Approve** -> audit entry with checks + rollback.
4. **CPU spike** -> "Resource saturation" with a different cause (network ruled out) - shows it is not one canned alert.
5. **Failed-login burst** -> security incident from local detection; no raw auth records exported.
6. **Cut SaaS link** 60s -> collector flips to Poor/offline; **Restore** -> backlog drains, run the ID comparison below.
7. **Out-of-order ON** + **Replay duplicates** -> dashboard stays correct; "duplicates ignored" counter increments.

ID check (zero loss / zero duplicates):
    sqlite3 collector.db "select count(*) from outbox where state!='sent'"   # 0 pending
    SaaS /api/overview -> stats.duplicates_ignored, total_records

## Honest limitations (say these - it is scored)
- Telemetry is simulated (`sample()` / `make_logs()` in collector.py): swap in the organizer stream, the pipeline stays the same.
- Demo uses HTTP between containers: production needs TLS + mTLS and per-collector certificates + token rotation.
- SQLite in both tiers: production = TimescaleDB/Postgres per region, Kafka/NATS ingest, row-level tenant security.
- Dashboard keys are demo auth: production needs SSO/RBAC. Regex secret scanner is best-effort; the allow-list is the real control.
- Correlation is rule + topology based (explainable by design); a learned model could rank incidents later.
- Autonomous Ops is simulated only (approval + audit + rollback), as the guide intends.
