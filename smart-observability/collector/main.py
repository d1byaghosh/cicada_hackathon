from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from collector.config import settings
from collector.local_db import LocalCollectorDB
from collector.privacy_engine import PrivacyEngine
from collector.stream_adapter import OrganizerStreamAdapter
from collector.transport import CollectorTransport

local_db = LocalCollectorDB()
privacy_engine = PrivacyEngine(local_db)
stream_adapter = OrganizerStreamAdapter()
transport = CollectorTransport(local_db)


class ToggleRequest(BaseModel):
    enabled: bool


class InjectScenarioRequest(BaseModel):
    scenario: str
    tenant_id: str | None = None


async def _ingest_loop() -> None:
    """Continuously consumes stream_adapter -> privacy_engine -> transport."""
    async for raw_event in stream_adapter.stream_events():
        try:
            result = privacy_engine.process_event(raw_event)
            if result is None:
                # Individual raw failed-login lines stay local until aggregated threshold hits
                continue
            outbound_payload, _ = result
            await transport.send_payload(outbound_payload)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never crash the background ingestion loop on a single malformed event
            continue


@asynccontextmanager
async def lifespan(_: FastAPI):
    local_db.init_db()
    await transport.start()
    tasks = [
        asyncio.create_task(_ingest_loop(), name="collector-ingest-loop"),
        asyncio.create_task(transport.retry_worker_loop(), name="collector-retry-loop"),
        asyncio.create_task(transport.heartbeat_worker_loop(), name="collector-heartbeat-loop"),
    ]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with suppress(asyncio.CancelledError):
                await task
        await transport.stop()


app = FastAPI(
    title="Tier 1 Local Collector (Privacy-First Boundary)",
    version=settings.collector_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/local/health")
async def local_health() -> dict[str, Any]:
    return {
        "status": "ok",
        "tier": "tier-1-local-collector",
        "collector_id": settings.collector_id,
        "tenant_id": settings.tenant_id,
        "region": settings.region,
        "utc_time": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/local/raw-logs")
async def get_local_raw_logs(limit: int = Query(default=50, ge=1, le=500)) -> dict[str, Any]:
    """Local-only view proving raw logs and secrets remain strictly inside Tier 1."""
    return {
        "collector_id": settings.collector_id,
        "trust_boundary": "LOCAL_ONLY_NEVER_TRANSMITTED",
        "items": local_db.get_raw_logs(limit=limit),
    }


@app.get("/local/egress-proof")
async def get_local_egress_proof(limit: int = Query(default=50, ge=1, le=500)) -> dict[str, Any]:
    """Powers the mandatory Egress Proof Panel with exact pre-transmission payloads."""
    return {
        "collector_id": settings.collector_id,
        "items": local_db.get_egress_proofs(limit=limit),
    }


@app.get("/local/buffer-status")
async def get_buffer_status() -> dict[str, Any]:
    """Returns queue depth, sent/acked unique payload_id counts, and demo toggle states."""
    return transport.get_status()


@app.post("/local/simulate-outage")
async def toggle_simulate_outage(body: ToggleRequest) -> dict[str, Any]:
    transport.simulate_outage = body.enabled
    flushed = 0
    if not body.enabled:
        flushed = await transport.flush_outbound_once()
    return {
        "simulate_outage": transport.simulate_outage,
        "flushed_immediately": flushed,
        "status": transport.get_status(),
    }


@app.post("/local/simulate-heartbeat-pause")
async def toggle_heartbeat_pause(body: ToggleRequest) -> dict[str, Any]:
    transport.pause_heartbeat = body.enabled
    if not body.enabled:
        await transport.send_heartbeat_once()
    return {
        "pause_heartbeat": transport.pause_heartbeat,
        "status": transport.get_status(),
    }


@app.post("/local/inject-scenario")
async def inject_scenario(body: InjectScenarioRequest) -> dict[str, Any]:
    """
    Triggers any validation scenario on demand:
    secret_log | failed_logins | latency_spike | cpu_memory_anomaly |
    correlated_burst | duplicate_and_out_of_order | baseline
    """
    try:
        events = stream_adapter.chaos.get_scenario_events(
            body.scenario,
            tenant_id=body.tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    processed_payload_ids: list[str] = []
    delivery_statuses: list[str] = []

    for raw_event in events:
        result = privacy_engine.process_event(raw_event)
        if result is None:
            continue
        outbound_payload, _ = result
        status = await transport.send_payload(outbound_payload)
        processed_payload_ids.append(outbound_payload.payload_id)
        delivery_statuses.append(status)

    return {
        "scenario": body.scenario,
        "raw_events_generated": len(events),
        "sanitized_payloads_emitted": len(processed_payload_ids),
        "payload_ids": processed_payload_ids,
        "delivery_statuses": delivery_statuses,
    }