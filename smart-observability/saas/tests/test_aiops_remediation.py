from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from saas.aiops import ExplainableAIOpsEngine
from saas.database import SaaSMetadataDB
from saas.main import create_app
from saas.remediation import SafeRemediationSimulator
from shared.contracts import (
    EventCategoryEnum,
    HealthStateEnum,
    SanitizedMetadataPayload,
    SeverityEnum,
)


def _build_sanitized(
    *,
    event_time: datetime,
    cpu: float,
    mem: float,
    lat: float,
    loss: float,
    service_up: float = 1.0,
    severity: SeverityEnum = SeverityEnum.INFO,
    category: EventCategoryEnum = EventCategoryEnum.INFRASTRUCTURE,
    source_id: str = "src-99aa88bb77",
) -> SanitizedMetadataPayload:
    return SanitizedMetadataPayload(
        payload_id=str(uuid.uuid4()),
        tenant_id="tenant-alpha",
        region="ap-south-1",
        collector_id="collector-edge-01",
        source_id=source_id,
        event_time=event_time,
        source_timezone="Asia/Kolkata",
        event_category=category,
        severity=severity,
        health_state=HealthStateEnum.EXCELLENT if severity == SeverityEnum.INFO else HealthStateEnum.POOR,
        metrics={
            "cpu_pct": cpu,
            "memory_pct": mem,
            "disk_pct": 52.0,
            "bandwidth_mbps": 180.0,
            "latency_ms": lat,
            "packet_loss_pct": loss,
            "service_up": service_up,
        },
        concise_alert_context="test telemetry event",
        redaction_count=0,
    )


def test_baseline_points_no_false_alarms_and_5_spikes_merge_into_1_incident(tmp_path: Path) -> None:
    db = SaaSMetadataDB(db_path=tmp_path / "aiops.db")
    engine = ExplainableAIOpsEngine(db=db)
    sim = SafeRemediationSimulator(db=db)

    base_time = datetime.now(timezone.utc) - timedelta(minutes=2)

    # 1. Feed 25 normal baseline points -> zero false alarms
    for i in range(25):
        normal_ev = _build_sanitized(
            event_time=base_time + timedelta(seconds=i * 2),
            cpu=32.0 + (i % 4),
            mem=44.0 + (i % 3),
            lat=20.0 + (i % 5),
            loss=0.1,
        )
        assert engine.process_metadata_event(normal_ev) is None

    # 2. Fire 5 correlated spikes within 15 seconds -> MUST merge into 1 CorrelatedIncident
    spike_start = base_time + timedelta(seconds=60)
    spikes = [
        (0, 76.0, 62.0, 210.0, 8.5, 1.0, SeverityEnum.HIGH, EventCategoryEnum.NETWORK),
        (3, 89.0, 74.0, 230.0, 10.2, 1.0, SeverityEnum.HIGH, EventCategoryEnum.INFRASTRUCTURE),
        (6, 94.5, 91.0, 255.0, 12.0, 1.0, SeverityEnum.CRITICAL, EventCategoryEnum.INFRASTRUCTURE),
        (9, 95.8, 92.4, 305.0, 16.5, 1.0, SeverityEnum.CRITICAL, EventCategoryEnum.NETWORK),
        (12, 97.1, 94.2, 340.0, 19.0, 0.0, SeverityEnum.CRITICAL, EventCategoryEnum.INFRASTRUCTURE),
    ]

    last_incident = None
    for offset, cpu, mem, lat, loss, svc, sev, cat in spikes:
        ev = _build_sanitized(
            event_time=spike_start + timedelta(seconds=offset),
            cpu=cpu,
            mem=mem,
            lat=lat,
            loss=loss,
            service_up=svc,
            severity=sev,
            category=cat,
        )
        last_incident = engine.process_metadata_event(ev)
        assert last_incident is not None
        sim.propose_for_incident(last_incident)

    incidents = db.get_incidents(tenant_id="tenant-alpha")
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.raw_alert_count == 5
    assert inc.severity == SeverityEnum.CRITICAL
    assert inc.why_flagged
    assert len(inc.contributing_signals) >= 5
    assert inc.baseline_vs_actual
    assert 0.5 <= inc.confidence <= 0.99
    assert inc.recommended_action
    assert len(inc.reasoning_path) >= 4


def test_remediation_approve_audit_rollback_lifecycle_via_api(tmp_path: Path) -> None:
    app = create_app(db_path=str(tmp_path / "remediation_api.db"))
    client = TestClient(app)
    headers = {"X-Collector-Token": "dev-token-tenant-alpha"}

    now = datetime.now(timezone.utc)
    # Ingest a critical anomaly to create an incident and auto-proposed remediation
    critical_payload = _build_sanitized(
        event_time=now,
        cpu=96.5,
        mem=94.0,
        lat=290.0,
        loss=15.0,
        service_up=0.0,
        severity=SeverityEnum.CRITICAL,
    )
    ingest_res = client.post(
        "/api/v1/ap-south-1/ingest",
        json=critical_payload.model_dump(mode="json"),
        headers=headers,
    )
    assert ingest_res.status_code == 200
    remediation_id = ingest_res.json()["remediation_id"]
    assert remediation_id is not None

    # Verify initial PENDING state with policy check passed
    rems = client.get("/api/v1/remediations", params={"tenant_id": "tenant-alpha"}).json()
    assert len(rems) == 1
    assert rems[0]["approval_status"] == "PENDING"
    assert rems[0]["policy_check_passed"] is True
    assert len(rems[0]["audit_trail"]) == 1

    # Approve -> transitions to SIMULATED with APPROVED + SIMULATED audit entries
    approve_res = client.post(
        f"/api/v1/remediations/{remediation_id}/approve",
        params={"tenant_id": "tenant-alpha"},
        json={"approver": "alice-sre"},
    )
    assert approve_res.status_code == 200
    approved = approve_res.json()
    assert approved["approval_status"] == "SIMULATED"
    assert approved["approved_by"] == "alice-sre"
    assert [e["action"] for e in approved["audit_trail"]] == ["PROPOSED", "APPROVED", "SIMULATED"]

    # Rollback -> transitions to ROLLED_BACK with immutable audit entry
    rollback_res = client.post(
        f"/api/v1/remediations/{remediation_id}/rollback",
        params={"tenant_id": "tenant-alpha"},
        json={"actor": "alice-sre"},
    )
    assert rollback_res.status_code == 200
    rolled = rollback_res.json()
    assert rolled["approval_status"] == "ROLLED_BACK"
    assert [e["action"] for e in rolled["audit_trail"]] == [
        "PROPOSED",
        "APPROVED",
        "SIMULATED",
        "ROLLED_BACK",
    ]