from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from collector.local_db import LocalCollectorDB
from collector.privacy_engine import PrivacyEngine
from shared.contracts import (
    EventCategoryEnum,
    HealthStateEnum,
    RawTelemetryEvent,
    SanitizedMetadataPayload,
    SeverityEnum,
)


def test_secret_stays_in_local_db_and_zero_leaks_in_outbound_payload(tmp_path: Path) -> None:
    db_file = tmp_path / "collector_local_test.db"
    db = LocalCollectorDB(db_path=db_file)
    engine = PrivacyEngine(db=db)

    # Confirm SQLite WAL mode is active
    conn = sqlite3.connect(str(db_file))
    try:
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert str(mode).lower() == "wal"
    finally:
        conn.close()

    raw_event = RawTelemetryEvent(
        tenant_id="tenant-alpha",
        region="ap-south-1",
        collector_id="collector-edge-01",
        hostname="prod-db-01.internal",
        host_ip="10.20.1.99",
        auth_user="ops_admin",
        event_time=datetime.now(timezone.utc),
        source_timezone="Asia/Kolkata",
        event_category=EventCategoryEnum.SECURITY,
        severity=SeverityEnum.HIGH,
        raw_log=(
            "ERROR auth-proxy host=prod-db-01.internal ip=10.20.1.99 "
            "password=supersecret Authorization: Bearer sk_live_9876543210abcdef"
        ),
        payload={"api_secret": "sk_live_9876543210abcdef"},
        metrics={"cpu_pct": 42.0, "memory_pct": 55.0, "latency_ms": 24.0, "service_up": 1.0},
    )

    result = engine.process_event(raw_event)
    assert result is not None
    outbound, proof = result

    # 1. Raw secret MUST remain stored strictly inside collector_local.db
    raw_rows = db.get_raw_logs(limit=5)
    assert len(raw_rows) == 1
    assert "supersecret" in raw_rows[0]["raw_log"]
    assert "sk_live_9876543210abcdef" in raw_rows[0]["raw_log"]

    # 2. Outbound sanitized payload MUST contain ZERO secrets, IPs, hostnames, or raw logs
    outbound_json = outbound.model_dump_json()
    for forbidden in ("supersecret", "sk_live_9876543210abcdef", "10.20.1.99", "prod-db-01.internal", "ops_admin"):
        assert forbidden not in outbound_json

    # 3. Egress proof log records the exact secret categories caught and redaction count
    assert outbound.source_id.startswith("src-")
    assert outbound.redaction_count >= 2
    assert len(proof.secrets_detected) >= 2
    assert "PASSWORD" in proof.secrets_detected
    assert "supersecret" not in proof.raw_preview_redacted_markers

    egress_rows = db.get_egress_proofs(limit=5)
    assert len(egress_rows) == 1
    assert egress_rows[0]["payload_id"] == outbound.payload_id


def test_pseudonymization_is_deterministic_and_tenant_scoped(tmp_path: Path) -> None:
    db = LocalCollectorDB(db_path=tmp_path / "pseudo.db")
    engine = PrivacyEngine(db=db, hmac_salt="fixed-test-salt")

    src_a1 = engine.pseudonymize_source("tenant-alpha", "app-01.internal", "10.20.1.11")
    src_a2 = engine.pseudonymize_source("tenant-alpha", "APP-01.internal", "10.20.1.11")
    src_b1 = engine.pseudonymize_source("tenant-beta", "app-01.internal", "10.20.1.11")

    assert src_a1 == src_a2
    assert src_a1 != src_b1
    assert "app-01" not in src_a1
    assert "10.20.1.11" not in src_a1


def test_strict_allow_list_rejects_unapproved_fields() -> None:
    with pytest.raises(ValidationError):
        SanitizedMetadataPayload(
            payload_id="pid-001",
            tenant_id="tenant-alpha",
            region="ap-south-1",
            collector_id="collector-edge-01",
            source_id="src-1234567890",
            event_time=datetime.now(timezone.utc),
            source_timezone="Asia/Kolkata",
            event_category=EventCategoryEnum.INFRASTRUCTURE,
            severity=SeverityEnum.INFO,
            health_state=HealthStateEnum.EXCELLENT,
            metrics={"cpu_pct": 25.0},
            concise_alert_context="normal",
            raw_log="should_fail_validation",  # type: ignore[call-arg]
        )


def test_repeated_failed_logins_collapse_into_concise_local_security_summary(tmp_path: Path) -> None:
    db = LocalCollectorDB(db_path=tmp_path / "auth_agg.db")
    engine = PrivacyEngine(db=db, auth_window_sec=60, auth_threshold=5)

    base_time = datetime.now(timezone.utc)
    emitted_payloads: list[SanitizedMetadataPayload] = []

    # Feed 10 raw failed-login events within 5 seconds
    for idx in range(10):
        ev = RawTelemetryEvent(
            tenant_id="tenant-alpha",
            region="ap-south-1",
            collector_id="collector-edge-01",
            hostname="ssh-gw-01.internal",
            host_ip="10.20.1.50",
            auth_user="root",
            auth_failed=True,
            event_time=base_time + timedelta(milliseconds=idx * 400),
            source_timezone="Asia/Kolkata",
            event_category=EventCategoryEnum.SECURITY,
            severity=SeverityEnum.MEDIUM,
            raw_log=f"Failed password for invalid user root from 198.51.100.42 password=badpass_{idx}",
            payload={"src_ip": "198.51.100.42"},
            metrics={"cpu_pct": 35.0, "memory_pct": 45.0, "latency_ms": 18.0, "service_up": 1.0},
        )
        res = engine.process_event(ev)
        if res is not None:
            emitted_payloads.append(res[0])

    # All 10 raw records stay saved locally, while outbound collapses into 2 concise summaries (at count=5 & count=10)
    assert len(db.get_raw_logs(limit=20)) == 10
    assert len(emitted_payloads) == 2

    first_summary, second_summary = emitted_payloads
    assert first_summary.event_category == EventCategoryEnum.SECURITY
    assert first_summary.severity == SeverityEnum.HIGH
    assert "count=5" in first_summary.concise_alert_context

    assert second_summary.severity == SeverityEnum.CRITICAL
    assert "count=10" in second_summary.concise_alert_context

    for summary in emitted_payloads:
        serialized = summary.model_dump_json()
        assert "badpass_" not in serialized
        assert "198.51.100.42" not in serialized
        assert "root" not in serialized