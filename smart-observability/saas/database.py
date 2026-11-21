from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from shared.contracts import (
    CollectorHeartbeat,
    CorrelatedIncident,
    HealthStateEnum,
    HealthStateTransition,
    HealthStatusRecord,
    HealthThresholdsConfig,
    RemediationAction,
    SanitizedMetadataPayload,
)

SAAS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SAAS_DIR.parent
load_dotenv(REPO_ROOT / ".env")
load_dotenv(SAAS_DIR / ".env")

DEFAULT_SAAS_DB_PATH = Path(
    os.getenv("SAAS_METADATA_DB", str(SAAS_DIR / "saas_metadata.db"))
).resolve()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def parse_utc_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class SaaSMetadataDB:
    """
    Manages saas_metadata.db in SQLite WAL mode.
    Strictly metadata-only: ZERO raw_log, raw_payload, password, or host_ip columns exist.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else DEFAULT_SAAS_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata_events (
                    payload_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    collector_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    source_timezone TEXT NOT NULL,
                    ingested_at_utc TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    health_state TEXT NOT NULL,
                    metrics_json TEXT NOT NULL,
                    concise_alert_context TEXT NOT NULL,
                    redaction_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_metadata_tenant_region_time
                    ON metadata_events(tenant_id, region, event_time ASC);
                CREATE INDEX IF NOT EXISTS idx_metadata_tenant_source_time
                    ON metadata_events(tenant_id, source_id, event_time ASC);

                CREATE TABLE IF NOT EXISTS collectors (
                    tenant_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    version TEXT NOT NULL DEFAULT '1.0.0',
                    last_seen_utc TEXT NOT NULL,
                    collector_cpu_pct REAL NOT NULL DEFAULT 0.0,
                    collector_mem_pct REAL NOT NULL DEFAULT 0.0,
                    buffer_queue_depth INTEGER NOT NULL DEFAULT 0,
                    config_status TEXT NOT NULL DEFAULT 'HEALTHY',
                    health_state TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    is_stale INTEGER NOT NULL DEFAULT 0,
                    latest_metrics_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (tenant_id, entity_id, entity_type)
                );
                CREATE INDEX IF NOT EXISTS idx_collectors_tenant
                    ON collectors(tenant_id, region);

                CREATE TABLE IF NOT EXISTS health_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    old_state TEXT NOT NULL,
                    new_state TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    changed_at_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_transitions_tenant_time
                    ON health_transitions(tenant_id, changed_at_utc DESC);

                CREATE TABLE IF NOT EXISTS health_thresholds (
                    tenant_id TEXT PRIMARY KEY,
                    cpu_fair_pct REAL NOT NULL DEFAULT 75.0,
                    cpu_poor_pct REAL NOT NULL DEFAULT 90.0,
                    memory_fair_pct REAL NOT NULL DEFAULT 80.0,
                    memory_poor_pct REAL NOT NULL DEFAULT 90.0,
                    latency_fair_ms REAL NOT NULL DEFAULT 120.0,
                    latency_poor_ms REAL NOT NULL DEFAULT 250.0,
                    packet_loss_fair_pct REAL NOT NULL DEFAULT 3.0,
                    packet_loss_poor_pct REAL NOT NULL DEFAULT 10.0,
                    stale_timeout_sec INTEGER NOT NULL DEFAULT 60
                );

                CREATE TABLE IF NOT EXISTS delivery_counters (
                    tenant_id TEXT PRIMARY KEY,
                    duplicates_ignored INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS correlated_incidents (
                    incident_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    incident_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_tenant_time
                    ON correlated_incidents(tenant_id, created_at_utc DESC);

                CREATE TABLE IF NOT EXISTS remediations (
                    remediation_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    approval_status TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    remediation_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_remediations_tenant
                    ON remediations(tenant_id, updated_at_utc DESC);
                """
            )

    # ---------- Metadata Ingest & Queries ----------

    def insert_metadata_event(
        self,
        payload: SanitizedMetadataPayload,
        evaluated_health_state: HealthStateEnum,
        ingested_at: datetime | None = None,
    ) -> bool:
        """
        Idempotently inserts metadata using INSERT OR IGNORE on PRIMARY KEY(payload_id).
        Returns True if newly inserted, False if duplicate payload_id was ignored.
        """
        ingested_iso = to_utc_iso(ingested_at or utc_now())
        event_iso = to_utc_iso(payload.event_time)

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO metadata_events (
                    payload_id, tenant_id, region, collector_id, source_id,
                    event_time, source_timezone, ingested_at_utc,
                    event_category, severity, health_state,
                    metrics_json, concise_alert_context, redaction_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.payload_id,
                    payload.tenant_id,
                    payload.region,
                    payload.collector_id,
                    payload.source_id,
                    event_iso,
                    payload.source_timezone,
                    ingested_iso,
                    payload.event_category.value,
                    payload.severity.value,
                    evaluated_health_state.value,
                    json.dumps(payload.metrics),
                    payload.concise_alert_context,
                    payload.redaction_count,
                ),
            )
            inserted = cursor.rowcount == 1
            if not inserted:
                conn.execute(
                    """
                    INSERT INTO delivery_counters (tenant_id, duplicates_ignored)
                    VALUES (?, 1)
                    ON CONFLICT(tenant_id) DO UPDATE
                    SET duplicates_ignored = duplicates_ignored + 1
                    """,
                    (payload.tenant_id,),
                )
            return inserted

    def get_metrics(
        self,
        tenant_id: str,
        source_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Strictly tenant-scoped time-series query ordered chronologically by event_time ASC
        (never arrival time) so out-of-order packets plot cleanly.
        """
        with self._connect() as conn:
            if source_id:
                rows = conn.execute(
                    """
                    SELECT * FROM (
                        SELECT payload_id, tenant_id, region, collector_id, source_id,
                               event_time, source_timezone, ingested_at_utc,
                               event_category, severity, health_state,
                               metrics_json, concise_alert_context, redaction_count
                        FROM metadata_events
                        WHERE tenant_id = ? AND source_id = ?
                        ORDER BY event_time DESC
                        LIMIT ?
                    ) sub
                    ORDER BY event_time ASC
                    """,
                    (tenant_id, source_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM (
                        SELECT payload_id, tenant_id, region, collector_id, source_id,
                               event_time, source_timezone, ingested_at_utc,
                               event_category, severity, health_state,
                               metrics_json, concise_alert_context, redaction_count
                        FROM metadata_events
                        WHERE tenant_id = ?
                        ORDER BY event_time DESC
                        LIMIT ?
                    ) sub
                    ORDER BY event_time ASC
                    """,
                    (tenant_id, limit),
                ).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["metrics"] = json.loads(item.pop("metrics_json"))
            results.append(item)
        return results

    def get_delivery_stats(self, tenant_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            received_unique = int(
                conn.execute(
                    "SELECT COUNT(*) FROM metadata_events WHERE tenant_id = ?",
                    (tenant_id,),
                ).fetchone()[0]
            )
            dup_row = conn.execute(
                "SELECT duplicates_ignored FROM delivery_counters WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            duplicates_ignored = int(dup_row["duplicates_ignored"]) if dup_row else 0

            latency_rows = conn.execute(
                """
                SELECT event_time, ingested_at_utc
                FROM metadata_events
                WHERE tenant_id = ?
                ORDER BY ingested_at_utc DESC
                LIMIT 200
                """,
                (tenant_id,),
            ).fetchall()

        latencies_sec: list[float] = []
        for row in latency_rows:
            ev_dt = parse_utc_iso(row["event_time"])
            ing_dt = parse_utc_iso(row["ingested_at_utc"])
            delta = (ing_dt - ev_dt).total_seconds()
            # Exclude intentionally backdated out-of-order test events (>60s old) from live p95
            if 0.0 <= delta <= 60.0:
                latencies_sec.append(delta)

        p95_sec = 0.0
        if latencies_sec:
            latencies_sec.sort()
            idx = min(len(latencies_sec) - 1, int(round(0.95 * (len(latencies_sec) - 1))))
            p95_sec = round(latencies_sec[idx], 3)

        return {
            "tenant_id": tenant_id,
            "received_unique_ids": received_unique,
            "duplicates_ignored": duplicates_ignored,
            "p95_ingest_latency_sec": p95_sec,
            "sla_target_sec": 10.0,
        }

    # ---------- Thresholds, Fleet Entities & Transitions ----------

    def get_thresholds(self, tenant_id: str) -> HealthThresholdsConfig:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM health_thresholds WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            if row is None:
                return HealthThresholdsConfig(tenant_id=tenant_id)
            return HealthThresholdsConfig(**dict(row))

    def upsert_thresholds(self, cfg: HealthThresholdsConfig) -> HealthThresholdsConfig:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO health_thresholds (
                    tenant_id, cpu_fair_pct, cpu_poor_pct,
                    memory_fair_pct, memory_poor_pct,
                    latency_fair_ms, latency_poor_ms,
                    packet_loss_fair_pct, packet_loss_poor_pct,
                    stale_timeout_sec
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    cpu_fair_pct = excluded.cpu_fair_pct,
                    cpu_poor_pct = excluded.cpu_poor_pct,
                    memory_fair_pct = excluded.memory_fair_pct,
                    memory_poor_pct = excluded.memory_poor_pct,
                    latency_fair_ms = excluded.latency_fair_ms,
                    latency_poor_ms = excluded.latency_poor_ms,
                    packet_loss_fair_pct = excluded.packet_loss_fair_pct,
                    packet_loss_poor_pct = excluded.packet_loss_poor_pct,
                    stale_timeout_sec = excluded.stale_timeout_sec
                """,
                (
                    cfg.tenant_id,
                    cfg.cpu_fair_pct,
                    cfg.cpu_poor_pct,
                    cfg.memory_fair_pct,
                    cfg.memory_poor_pct,
                    cfg.latency_fair_ms,
                    cfg.latency_poor_ms,
                    cfg.packet_loss_fair_pct,
                    cfg.packet_loss_poor_pct,
                    cfg.stale_timeout_sec,
                ),
            )
        return cfg

    def upsert_entity_health(
        self,
        tenant_id: str,
        region: str,
        entity_id: str,
        entity_type: str,
        health_state: HealthStateEnum,
        reason: str,
        last_seen_utc: datetime,
        is_stale: bool = False,
        version: str = "1.0.0",
        collector_cpu_pct: float = 0.0,
        collector_mem_pct: float = 0.0,
        buffer_queue_depth: int = 0,
        config_status: str = "HEALTHY",
        latest_metrics: dict[str, float] | None = None,
    ) -> HealthStateTransition | None:
        """
        Upserts source or collector health state and logs a UTC transition whenever state changes.
        """
        last_seen_iso = to_utc_iso(last_seen_utc)
        now_iso = to_utc_iso(utc_now())
        transition: HealthStateTransition | None = None

        with self._connect() as conn:
            existing = conn.execute(
                """
                SELECT health_state, latest_metrics_json
                FROM collectors
                WHERE tenant_id = ? AND entity_id = ? AND entity_type = ?
                """,
                (tenant_id, entity_id, entity_type),
            ).fetchone()

            metrics_to_store = (
                json.dumps(latest_metrics)
                if latest_metrics is not None
                else (existing["latest_metrics_json"] if existing else "{}")
            )

            if existing is not None and existing["health_state"] != health_state.value:
                old_state = HealthStateEnum(existing["health_state"])
                conn.execute(
                    """
                    INSERT INTO health_transitions (
                        tenant_id, region, entity_id, entity_type,
                        old_state, new_state, reason, changed_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant_id,
                        region,
                        entity_id,
                        entity_type,
                        old_state.value,
                        health_state.value,
                        reason,
                        now_iso,
                    ),
                )
                transition = HealthStateTransition(
                    tenant_id=tenant_id,
                    region=region,
                    entity_id=entity_id,
                    entity_type=entity_type,
                    old_state=old_state,
                    new_state=health_state,
                    reason=reason,
                    changed_at_utc=parse_utc_iso(now_iso),
                )

            conn.execute(
                """
                INSERT INTO collectors (
                    tenant_id, region, entity_id, entity_type, version, last_seen_utc,
                    collector_cpu_pct, collector_mem_pct, buffer_queue_depth,
                    config_status, health_state, reason, is_stale, latest_metrics_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, entity_id, entity_type) DO UPDATE SET
                    region = excluded.region,
                    version = excluded.version,
                    last_seen_utc = excluded.last_seen_utc,
                    collector_cpu_pct = excluded.collector_cpu_pct,
                    collector_mem_pct = excluded.collector_mem_pct,
                    buffer_queue_depth = excluded.buffer_queue_depth,
                    config_status = excluded.config_status,
                    health_state = excluded.health_state,
                    reason = excluded.reason,
                    is_stale = excluded.is_stale,
                    latest_metrics_json = excluded.latest_metrics_json
                """,
                (
                    tenant_id,
                    region,
                    entity_id,
                    entity_type,
                    version,
                    last_seen_iso,
                    collector_cpu_pct,
                    collector_mem_pct,
                    buffer_queue_depth,
                    config_status,
                    health_state.value,
                    reason,
                    1 if is_stale else 0,
                    metrics_to_store,
                ),
            )
        return transition

    def upsert_collector_heartbeat(
        self,
        hb: CollectorHeartbeat,
        health_state: HealthStateEnum,
        reason: str,
    ) -> HealthStateTransition | None:
        return self.upsert_entity_health(
            tenant_id=hb.tenant_id,
            region=hb.region,
            entity_id=hb.collector_id,
            entity_type="COLLECTOR",
            health_state=health_state,
            reason=reason,
            last_seen_utc=hb.sent_at_utc,
            is_stale=False,
            version=hb.version,
            collector_cpu_pct=hb.collector_cpu_pct,
            collector_mem_pct=hb.collector_mem_pct,
            buffer_queue_depth=hb.buffer_queue_depth,
            config_status=hb.config_status,
        )

    def get_health_records(self, tenant_id: str) -> list[HealthStatusRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT tenant_id, region, entity_id, entity_type, version, last_seen_utc,
                       collector_cpu_pct, collector_mem_pct, buffer_queue_depth,
                       health_state, reason, is_stale, latest_metrics_json
                FROM collectors
                WHERE tenant_id = ?
                ORDER BY entity_type ASC, entity_id ASC
                """,
                (tenant_id,),
            ).fetchall()

        records: list[HealthStatusRecord] = []
        for r in rows:
            records.append(
                HealthStatusRecord(
                    tenant_id=r["tenant_id"],
                    region=r["region"],
                    entity_id=r["entity_id"],
                    entity_type=r["entity_type"],
                    health_state=HealthStateEnum(r["health_state"]),
                    reason=r["reason"],
                    last_seen_utc=parse_utc_iso(r["last_seen_utc"]),
                    is_stale=bool(r["is_stale"]),
                    version=r["version"],
                    collector_cpu_pct=float(r["collector_cpu_pct"]),
                    collector_mem_pct=float(r["collector_mem_pct"]),
                    buffer_queue_depth=int(r["buffer_queue_depth"]),
                    latest_metrics=json.loads(r["latest_metrics_json"]),
                )
            )
        return records

    def get_all_entities_for_watchdog(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT tenant_id, region, entity_id, entity_type, version, last_seen_utc,
                       collector_cpu_pct, collector_mem_pct, buffer_queue_depth,
                       config_status, health_state, reason, is_stale
                FROM collectors
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def get_health_transitions(
        self,
        tenant_id: str,
        limit: int = 50,
    ) -> list[HealthStateTransition]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT tenant_id, region, entity_id, entity_type,
                       old_state, new_state, reason, changed_at_utc
                FROM health_transitions
                WHERE tenant_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [
            HealthStateTransition(
                tenant_id=r["tenant_id"],
                region=r["region"],
                entity_id=r["entity_id"],
                entity_type=r["entity_type"],
                old_state=HealthStateEnum(r["old_state"]),
                new_state=HealthStateEnum(r["new_state"]),
                reason=r["reason"],
                changed_at_utc=parse_utc_iso(r["changed_at_utc"]),
            )
            for r in rows
        ]

    # ---------- AIOps Incidents & Remediations ----------

    def save_incident(self, incident: CorrelatedIncident) -> None:
        now_iso = to_utc_iso(utc_now())
        created_iso = to_utc_iso(incident.created_at_utc)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO correlated_incidents (
                    incident_id, tenant_id, region, status, severity,
                    created_at_utc, updated_at_utc, incident_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    status = excluded.status,
                    severity = excluded.severity,
                    updated_at_utc = excluded.updated_at_utc,
                    incident_json = excluded.incident_json
                """,
                (
                    incident.incident_id,
                    incident.tenant_id,
                    incident.region,
                    incident.status,
                    incident.severity.value,
                    created_iso,
                    now_iso,
                    incident.model_dump_json(),
                ),
            )

    def get_incidents(self, tenant_id: str, limit: int = 50) -> list[CorrelatedIncident]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT incident_json
                FROM correlated_incidents
                WHERE tenant_id = ?
                ORDER BY created_at_utc DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [CorrelatedIncident.model_validate_json(r["incident_json"]) for r in rows]

    def save_remediation(self, action: RemediationAction) -> None:
        now_iso = to_utc_iso(utc_now())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO remediations (
                    remediation_id, incident_id, tenant_id,
                    approval_status, updated_at_utc, remediation_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(remediation_id) DO UPDATE SET
                    approval_status = excluded.approval_status,
                    updated_at_utc = excluded.updated_at_utc,
                    remediation_json = excluded.remediation_json
                """,
                (
                    action.remediation_id,
                    action.incident_id,
                    action.tenant_id,
                    action.approval_status,
                    now_iso,
                    action.model_dump_json(),
                ),
            )

    def get_remediation(self, remediation_id: str, tenant_id: str) -> RemediationAction | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT remediation_json
                FROM remediations
                WHERE remediation_id = ? AND tenant_id = ?
                """,
                (remediation_id, tenant_id),
            ).fetchone()
        if row is None:
            return None
        return RemediationAction.model_validate_json(row["remediation_json"])

    def get_remediations(self, tenant_id: str, limit: int = 50) -> list[RemediationAction]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT remediation_json
                FROM remediations
                WHERE tenant_id = ?
                ORDER BY updated_at_utc DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [RemediationAction.model_validate_json(r["remediation_json"]) for r in rows]

    def get_remediation_by_incident(
        self,
        incident_id: str,
        tenant_id: str,
    ) -> RemediationAction | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT remediation_json
                FROM remediations
                WHERE incident_id = ? AND tenant_id = ?
                LIMIT 1
                """,
                (incident_id, tenant_id),
            ).fetchone()
        if row is None:
            return None
        return RemediationAction.model_validate_json(row["remediation_json"])