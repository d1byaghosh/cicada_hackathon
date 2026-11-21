from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from collector.config import settings
from shared.contracts import EgressProofRecord, RawTelemetryEvent


class LocalCollectorDB:
    """Manages collector_local.db in SQLite WAL mode strictly inside Tier 1."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = Path(db_path or settings.local_db_path)
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
                CREATE TABLE IF NOT EXISTS raw_telemetry_local (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    event_time_utc TEXT NOT NULL,
                    source_timezone TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    host_ip TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    raw_log TEXT NOT NULL,
                    raw_event_json TEXT NOT NULL,
                    secrets_detected_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_raw_payload_id
                    ON raw_telemetry_local(payload_id);

                CREATE TABLE IF NOT EXISTS egress_audit_log (
                    payload_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    secrets_detected_json TEXT NOT NULL,
                    redaction_count INTEGER NOT NULL DEFAULT 0,
                    record_json TEXT NOT NULL,
                    delivery_status TEXT NOT NULL,
                    transmitted_at_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_egress_transmitted
                    ON egress_audit_log(transmitted_at_utc DESC);

                CREATE TABLE IF NOT EXISTS outbound_queue (
                    payload_id TEXT PRIMARY KEY,
                    region TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'BUFFERED',
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    created_at_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_outbound_created
                    ON outbound_queue(created_at_utc ASC);
                """
            )

    def insert_raw_event(
        self,
        payload_id: str,
        raw_event: RawTelemetryEvent,
        secrets_detected: list[str],
    ) -> None:
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO raw_telemetry_local (
                    payload_id, tenant_id, region, event_time_utc, source_timezone,
                    hostname, host_ip, event_category, severity, raw_log,
                    raw_event_json, secrets_detected_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload_id,
                    raw_event.tenant_id,
                    raw_event.region,
                    raw_event.event_time.astimezone(timezone.utc).isoformat(),
                    raw_event.source_timezone,
                    raw_event.hostname,
                    raw_event.host_ip,
                    raw_event.event_category.value,
                    raw_event.severity.value,
                    raw_event.raw_log,
                    raw_event.model_dump_json(),
                    json.dumps(secrets_detected),
                    now_utc,
                ),
            )
            # Keep local raw store bounded
            conn.execute(
                """
                DELETE FROM raw_telemetry_local
                WHERE id NOT IN (
                    SELECT id FROM raw_telemetry_local
                    ORDER BY id DESC
                    LIMIT ?
                )
                """,
                (settings.raw_retention_limit,),
            )

    def insert_egress_proof(self, record: EgressProofRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO egress_audit_log (
                    payload_id, tenant_id, region, secrets_detected_json,
                    redaction_count, record_json, delivery_status, transmitted_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.payload_id,
                    record.outbound_payload.tenant_id,
                    record.outbound_payload.region,
                    json.dumps(record.secrets_detected),
                    record.outbound_payload.redaction_count,
                    record.model_dump_json(),
                    record.delivery_status,
                    record.transmitted_at_utc.astimezone(timezone.utc).isoformat(),
                ),
            )

    def update_egress_status(
        self,
        payload_id: str,
        delivery_status: str,
        transmitted_at_utc: datetime | None = None,
    ) -> None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT record_json FROM egress_audit_log WHERE payload_id = ?",
                (payload_id,),
            ).fetchone()
            if row is None:
                return
            data = json.loads(row["record_json"])
            data["delivery_status"] = delivery_status
            ts_str = (transmitted_at_utc or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
            data["transmitted_at_utc"] = ts_str
            conn.execute(
                """
                UPDATE egress_audit_log
                SET delivery_status = ?, transmitted_at_utc = ?, record_json = ?
                WHERE payload_id = ?
                """,
                (delivery_status, ts_str, json.dumps(data), payload_id),
            )

    def enqueue_outbound(
        self,
        payload_id: str,
        region: str,
        payload_json: str,
        error: str = "",
    ) -> None:
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO outbound_queue (
                    payload_id, region, payload_json, status, retry_count, last_error, created_at_utc
                ) VALUES (?, ?, ?, 'BUFFERED', 0, ?, ?)
                """,
                (payload_id, region, payload_json, error[:500], now_utc),
            )

    def get_pending_outbound(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload_id, region, payload_json, status, retry_count, last_error, created_at_utc
                FROM outbound_queue
                WHERE status = 'BUFFERED'
                ORDER BY created_at_utc ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def mark_outbound_delivered(self, payload_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM outbound_queue WHERE payload_id = ?", (payload_id,))

    def increment_outbound_retry(self, payload_id: str, error: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE outbound_queue
                SET retry_count = retry_count + 1, last_error = ?
                WHERE payload_id = ?
                """,
                (error[:500], payload_id),
            )

    def get_raw_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload_id, tenant_id, region, event_time_utc, source_timezone,
                       hostname, host_ip, event_category, severity, raw_log,
                       secrets_detected_json, created_at_utc
                FROM raw_telemetry_local
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            results: list[dict[str, Any]] = []
            for r in rows:
                item = dict(r)
                item["secrets_detected"] = json.loads(item.pop("secrets_detected_json"))
                results.append(item)
            return results

    def get_egress_proofs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT record_json
                FROM egress_audit_log
                ORDER BY transmitted_at_utc DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [json.loads(r["record_json"]) for r in rows]

    def get_buffer_stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            queue_depth = int(
                conn.execute("SELECT COUNT(*) FROM outbound_queue WHERE status = 'BUFFERED'").fetchone()[0]
            )
            total_unique = int(conn.execute("SELECT COUNT(*) FROM egress_audit_log").fetchone()[0])
            acked_unique = int(
                conn.execute(
                    "SELECT COUNT(*) FROM egress_audit_log WHERE delivery_status = 'ACKNOWLEDGED'"
                ).fetchone()[0]
            )
            total_secrets = int(
                conn.execute(
                    "SELECT COALESCE(SUM(redaction_count), 0) FROM egress_audit_log"
                ).fetchone()[0]
            )
            return {
                "buffer_queue_depth": queue_depth,
                "sent_unique_ids": total_unique,
                "acknowledged_unique_ids": acked_unique,
                "total_secrets_scrubbed": total_secrets,
            }