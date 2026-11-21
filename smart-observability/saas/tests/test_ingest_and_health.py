from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from saas.main import create_app
from shared.contracts import (
    CollectorHeartbeat,
    EventCategoryEnum,
    HealthStateEnum,
    SeverityEnum,
)


def _make_payload(
    *,
    payload_id: str | None = None,
    tenant_id: str = "tenant-alpha",
    region: str = "ap-south-1",
    source_id: str = "src-a1b2c3d4e5",
    event_time: datetime | None = None,
    cpu_pct: float = 35.0,
    latency_ms: float = 22.0,
) -> dict:
    return {
        "payload_id": payload_id or str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "region": region,
        "collector_id": "collector-edge-01",
        "source_id": source_id,
        "event_time": (event_time or datetime.now(timezone.utc)).isoformat(),
        "source_timezone": "Asia/Kolkata",
        "event_category": EventCategoryEnum.INFRASTRUCTURE.value,
        "severity": SeverityEnum.INFO.value,
        "health_state": HealthStateEnum.EXCELLENT.value,
        "metrics": {
            "cpu_pct": cpu_pct,
            "memory_pct": 45.0,
            "disk_pct": 50.0,
            "bandwidth_mbps": 150.0,
            "latency_ms": latency_ms,
            "packet_loss_pct": 0.1,
            "service_up": 1.0,
        },
        "concise_alert_context": "infrastructure telemetry normal",
        "redaction_count": 0,
    }


def test_duplicate_payload_id_rejection(tmp_path: Path) -> None:
    app = create_app(db_path=str(tmp_path / "test_saas.db"))
    client = TestClient(app)

    dup_id = str(uuid.uuid4())
    headers = {"X-Collector-Token": "dev-token-tenant-alpha"}

    r1 = client.post("/api/v1/ap-south-1/ingest", json=_make_payload(payload_id=dup_id), headers=headers)
    assert r1.status_code == 200
    assert r1.json()["status"] == "accepted"

    r2 = client.post("/api/v1/ap-south-1/ingest", json=_make_payload(payload_id=dup_id), headers=headers)
    assert r2.status_code == 200
    assert r2.json()["status"] == "duplicate"

    stats = client.get("/api/v1/stats/delivery", params={"tenant_id": "tenant-alpha"}).json()
    assert stats["received_unique_ids"] == 1
    assert stats["duplicates_ignored"] == 1


def test_out_of_order_chronological_event_time_sorting(tmp_path: Path) -> None:
    app = create_app(db_path=str(tmp_path / "test_saas.db"))
    client = TestClient(app)
    headers = {"X-Collector-Token": "dev-token-tenant-alpha"}

    now = datetime.now(timezone.utc)
    t_latest = now
    t_oldest = now - timedelta(seconds=120)
    t_middle = now - timedelta(seconds=60)

    # Deliver intentionally out of order: latest -> oldest -> middle
    for ts, cpu in [(t_latest, 40.0), (t_oldest, 20.0), (t_middle, 30.0)]:
        res = client.post(
            "/api/v1/ap-south-1/ingest",
            json=_make_payload(event_time=ts, cpu_pct=cpu),
            headers=headers,
        )
        assert res.status_code == 200

    metrics = client.get("/api/v1/metrics", params={"tenant_id": "tenant-alpha"}).json()
    assert len(metrics) == 3
    cpus = [item["metrics"]["cpu_pct"] for item in metrics]
    assert cpus == [20.0, 30.0, 40.0]


def test_strict_tenant_isolation_and_residency_enforcement(tmp_path: Path) -> None:
    app = create_app(db_path=str(tmp_path / "test_saas.db"))
    client = TestClient(app)

    # Tenant Alpha ingests in ap-south-1
    r_alpha = client.post(
        "/api/v1/ap-south-1/ingest",
        json=_make_payload(tenant_id="tenant-alpha", region="ap-south-1", source_id="src-alpha-01"),
        headers={"X-Collector-Token": "dev-token-tenant-alpha"},
    )
    assert r_alpha.status_code == 200

    # Tenant Beta ingests in eu-central-1
    r_beta = client.post(
        "/api/v1/eu-central-1/ingest",
        json=_make_payload(tenant_id="tenant-beta", region="eu-central-1", source_id="src-beta-01"),
        headers={"X-Collector-Token": "dev-token-tenant-beta"},
    )
    assert r_beta.status_code == 200

    # Cross-tenant token spoofing must fail with 403
    r_spoof = client.post(
        "/api/v1/eu-central-1/ingest",
        json=_make_payload(tenant_id="tenant-beta", region="eu-central-1"),
        headers={"X-Collector-Token": "dev-token-tenant-alpha"},
    )
    assert r_spoof.status_code == 403

    # Tenant A cannot see Tenant B's metrics or health records
    alpha_metrics = client.get("/api/v1/metrics", params={"tenant_id": "tenant-alpha"}).json()
    beta_metrics = client.get("/api/v1/metrics", params={"tenant_id": "tenant-beta"}).json()

    assert all(m["tenant_id"] == "tenant-alpha" for m in alpha_metrics)
    assert all(m["source_id"] != "src-beta-01" for m in alpha_metrics)
    assert all(m["tenant_id"] == "tenant-beta" for m in beta_metrics)
    assert all(m["source_id"] != "src-alpha-01" for m in beta_metrics)


def test_stale_watchdog_downgrades_after_60s_silence(tmp_path: Path) -> None:
    app = create_app(db_path=str(tmp_path / "test_saas.db"))
    client = TestClient(app)

    old_time = datetime.now(timezone.utc) - timedelta(seconds=75)
    hb = CollectorHeartbeat(
        collector_id="collector-edge-01",
        tenant_id="tenant-alpha",
        region="ap-south-1",
        version="1.0.0",
        sent_at_utc=old_time,
        collector_cpu_pct=12.0,
        collector_mem_pct=18.0,
        buffer_queue_depth=0,
        config_status="HEALTHY",
    )
    res = client.post(
        "/api/v1/ap-south-1/heartbeat",
        json=hb.model_dump(mode="json"),
        headers={"X-Collector-Token": "dev-token-tenant-alpha"},
    )
    assert res.status_code == 200
    assert res.json()["health_state"] == HealthStateEnum.EXCELLENT.value

    # Run stale check now (>60s after old_time)
    transitions = asyncio.run(app.state.health_engine.run_stale_check_once())
    assert len(transitions) == 1
    assert transitions[0].old_state == HealthStateEnum.EXCELLENT
    assert transitions[0].new_state == HealthStateEnum.POOR

    health_records = client.get("/api/v1/health", params={"tenant_id": "tenant-alpha"}).json()
    collector_rec = next(r for r in health_records if r["entity_id"] == "collector-edge-01")
    assert collector_rec["health_state"] == HealthStateEnum.POOR.value
    assert collector_rec["is_stale"] is True
    assert ">60s" in collector_rec["reason"]