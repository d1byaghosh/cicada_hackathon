from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

from collector.local_db import LocalCollectorDB
from collector.transport import CollectorTransport
from shared.contracts import (
    EgressProofRecord,
    EventCategoryEnum,
    HealthStateEnum,
    SanitizedMetadataPayload,
    SeverityEnum,
)


def _make_sanitized_payload(payload_id: str | None = None) -> SanitizedMetadataPayload:
    return SanitizedMetadataPayload(
        payload_id=payload_id or str(uuid.uuid4()),
        tenant_id="tenant-alpha",
        region="ap-south-1",
        collector_id="collector-edge-01",
        source_id="src-abcdef1234",
        event_time=datetime.now(timezone.utc),
        source_timezone="Asia/Kolkata",
        event_category=EventCategoryEnum.INFRASTRUCTURE,
        severity=SeverityEnum.INFO,
        health_state=HealthStateEnum.EXCELLENT,
        metrics={"cpu_pct": 31.5, "memory_pct": 48.0, "latency_ms": 20.0, "service_up": 1.0},
        concise_alert_context="infrastructure telemetry normal",
        redaction_count=0,
    )


def _register_egress_record(db: LocalCollectorDB, payload: SanitizedMetadataPayload) -> None:
    db.insert_egress_proof(
        EgressProofRecord(
            payload_id=payload.payload_id,
            raw_preview_redacted_markers="INFO telemetry normal",
            secrets_detected=[],
            outbound_payload=payload,
            transmitted_at_utc=datetime.now(timezone.utc),
            delivery_status="SENT",
        )
    )


def test_outage_buffering_and_zero_loss_flush_on_reconnect(tmp_path: Path) -> None:
    async def _run() -> None:
        db = LocalCollectorDB(db_path=tmp_path / "transport_outage.db")
        transport = CollectorTransport(db=db)

        state = {"saas_online": False}
        received_ids: list[str] = []
        seen_tokens: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_tokens.append(request.headers.get("x-collector-token"))
            if not state["saas_online"]:
                raise httpx.ConnectError("Tier 2 SaaS unreachable (simulated)", request=request)
            body = json.loads(request.content.decode("utf-8"))
            received_ids.append(body["payload_id"])
            return httpx.Response(200, json={"status": "accepted", "payload_id": body["payload_id"]})

        transport._client = httpx.AsyncClient(
            base_url="http://127.0.0.1:8000",
            transport=httpx.MockTransport(handler),
            headers={"X-Collector-Token": "dev-token-tenant-alpha", "Content-Type": "application/json"},
        )

        try:
            # 1. Send 10 unique payloads while Tier 2 (:8000) is unreachable
            sent_ids: list[str] = []
            for _ in range(10):
                payload = _make_sanitized_payload()
                _register_egress_record(db, payload)
                status = await transport.send_payload(payload)
                assert status == "BUFFERED"
                sent_ids.append(payload.payload_id)

            stats_down = db.get_buffer_stats()
            assert stats_down["buffer_queue_depth"] == 10
            assert stats_down["acknowledged_unique_ids"] == 0
            assert len(received_ids) == 0

            # 2. Bring Tier 2 back online and flush FIFO queue
            state["saas_online"] = True
            flushed_count = await transport.flush_outbound_once()
            assert flushed_count == 10

            # 3. Verify zero loss, zero duplicates, exact FIFO order, and auth header present
            stats_up = db.get_buffer_stats()
            assert stats_up["buffer_queue_depth"] == 0
            assert stats_up["sent_unique_ids"] == 10
            assert stats_up["acknowledged_unique_ids"] == 10
            assert received_ids == sent_ids
            assert len(set(received_ids)) == len(sent_ids)
            assert all(tok == "dev-token-tenant-alpha" for tok in seen_tokens)
        finally:
            await transport.stop()

    asyncio.run(_run())


def test_simulate_outage_toggle_and_heartbeat_pause(tmp_path: Path) -> None:
    async def _run() -> None:
        db = LocalCollectorDB(db_path=tmp_path / "transport_toggles.db")
        transport = CollectorTransport(db=db)

        ingest_calls: list[str] = []
        heartbeat_calls: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode("utf-8"))
            if request.url.path.endswith("/ingest"):
                ingest_calls.append(body["payload_id"])
            elif request.url.path.endswith("/heartbeat"):
                heartbeat_calls.append(body)
            return httpx.Response(200, json={"status": "ok"})

        transport._client = httpx.AsyncClient(
            base_url="http://127.0.0.1:8000",
            transport=httpx.MockTransport(handler),
            headers={"X-Collector-Token": "dev-token-tenant-alpha", "Content-Type": "application/json"},
        )

        try:
            # Enable simulate_outage -> payload queues locally without touching network
            transport.simulate_outage = True
            payload = _make_sanitized_payload()
            _register_egress_record(db, payload)
            assert await transport.send_payload(payload) == "BUFFERED"
            assert len(ingest_calls) == 0
            assert db.get_buffer_stats()["buffer_queue_depth"] == 1

            # Disable simulate_outage -> flush delivers queued payload
            transport.simulate_outage = False
            assert await transport.flush_outbound_once() == 1
            assert ingest_calls == [payload.payload_id]
            assert db.get_buffer_stats()["buffer_queue_depth"] == 0

            # Pause heartbeat -> skipped without network call
            transport.pause_heartbeat = True
            assert await transport.send_heartbeat_once() is False
            assert transport.last_heartbeat_status == "PAUSED"
            assert len(heartbeat_calls) == 0

            # Resume heartbeat -> delivered and acknowledged
            transport.pause_heartbeat = False
            assert await transport.send_heartbeat_once() is True
            assert transport.last_heartbeat_status == "ACKNOWLEDGED"
            assert len(heartbeat_calls) == 1
            assert heartbeat_calls[0]["buffer_queue_depth"] == 0
        finally:
            await transport.stop()

    asyncio.run(_run())