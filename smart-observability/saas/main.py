from __future__ import annotations

import asyncio
import json
import os
from collections import defaultdict
from contextlib import asynccontextmanager, suppress
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, Header, HTTPException, Path as FastAPIPath, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from saas.aiops import ExplainableAIOpsEngine
from saas.database import SaaSMetadataDB, utc_now
from saas.health import HealthEngine
from saas.remediation import SafeRemediationSimulator
from saas.routes_aiops import create_aiops_router
from shared.contracts import (
    CollectorHeartbeat,
    HealthStateTransition,
    HealthStatusRecord,
    HealthThresholdsConfig,
    SanitizedMetadataPayload,
)

# Token -> allowed (tenant_id, region) scopes to prevent cross-tenant spoofing and enforce residency
DEFAULT_TOKEN_SCOPES: dict[str, set[tuple[str, str]]] = {
    "dev-token-tenant-alpha": {("tenant-alpha", "ap-south-1")},
    "dev-token-tenant-beta": {("tenant-beta", "eu-central-1")},
    # Optional multi-tenant demo token for single-collector demo harness
    "dev-token-demo-multi": {
        ("tenant-alpha", "ap-south-1"),
        ("tenant-beta", "eu-central-1"),
    },
}


def _load_token_scopes() -> dict[str, set[tuple[str, str]]]:
    raw = os.getenv("COLLECTOR_TOKENS_JSON", "").strip()
    if not raw:
        return DEFAULT_TOKEN_SCOPES
    parsed = json.loads(raw)
    return {
        token: {(entry[0], entry[1]) for entry in pairs}
        for token, pairs in parsed.items()
    }


class TenantSSEBroker:
    """Per-tenant Server-Sent Events fan-out broker (strictly isolated by tenant_id)."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[str]]] = defaultdict(set)

    def subscribe(self, tenant_id: str) -> asyncio.Queue[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=200)
        self._subscribers[tenant_id].add(q)
        return q

    def unsubscribe(self, tenant_id: str, q: asyncio.Queue[str]) -> None:
        self._subscribers[tenant_id].discard(q)

    async def publish(self, tenant_id: str, event_type: str, data: dict[str, Any]) -> None:
        message = f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"
        for q in list(self._subscribers.get(tenant_id, set())):
            if q.full():
                with suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            q.put_nowait(message)


def create_app(db_path: str | None = None) -> FastAPI:
    db = SaaSMetadataDB(db_path=db_path)
    sse_broker = TenantSSEBroker()
    token_scopes = _load_token_scopes()

    async def _broadcast_transition(transition: HealthStateTransition) -> None:
        await sse_broker.publish(
            transition.tenant_id,
            "health_transition",
            transition.model_dump(mode="json"),
        )

    health_engine = HealthEngine(db=db, on_transition=_broadcast_transition)
    aiops_engine = ExplainableAIOpsEngine(db=db)
    remediation_sim = SafeRemediationSimulator(db=db)
    aiops_router = create_aiops_router(db, aiops_engine, remediation_sim)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        db.init_db()
        watchdog_task = asyncio.create_task(
            health_engine.watchdog_loop(interval_sec=10.0),
            name="saas-stale-watchdog",
        )
        try:
            yield
        finally:
            watchdog_task.cancel()
            with suppress(asyncio.CancelledError):
                await watchdog_task

    app = FastAPI(
        title="Tier 2 Central SaaS Platform (Metadata-Only, Multi-Tenant)",
        version="1.0.0",
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

    # Wire Chunk 5 AIOps & Safe Remediation router via a single include_router call
    app.include_router(aiops_router)

    def verify_collector_token(
        x_collector_token: str | None = Header(default=None, alias="X-Collector-Token"),
    ) -> set[tuple[str, str]]:
        if not x_collector_token or x_collector_token not in token_scopes:
            raise HTTPException(status_code=401, detail="Invalid or missing X-Collector-Token.")
        return token_scopes[x_collector_token]

    def enforce_tenant_region_scope(
        allowed_scopes: set[tuple[str, str]],
        tenant_id: str,
        payload_region: str,
        path_region: str,
    ) -> None:
        if payload_region != path_region:
            raise HTTPException(
                status_code=400,
                detail=f"Region residency mismatch: path '{path_region}' != payload '{payload_region}'.",
            )
        if (tenant_id, payload_region) not in allowed_scopes:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Collector token is not authorized for tenant='{tenant_id}' "
                    f"in region='{payload_region}'."
                ),
            )

    @app.get("/health")
    async def saas_health() -> dict[str, Any]:
        return {
            "status": "ok",
            "tier": "tier-2-central-saas",
            "metadata_only": True,
            "utc_time": utc_now().isoformat(),
        }

    @app.post("/api/v1/{region}/ingest")
    async def ingest_metadata(
        payload: SanitizedMetadataPayload,
        region: str = FastAPIPath(..., min_length=2),
        allowed_scopes: set[tuple[str, str]] = Depends(verify_collector_token),
    ) -> dict[str, Any]:
        enforce_tenant_region_scope(allowed_scopes, payload.tenant_id, payload.region, region)

        eval_state, eval_reason = health_engine.evaluate_payload_health(payload)
        inserted = db.insert_metadata_event(payload, evaluated_health_state=eval_state)
        if not inserted:
            return {
                "status": "duplicate",
                "payload_id": payload.payload_id,
                "tenant_id": payload.tenant_id,
                "region": payload.region,
            }

        _, _, _ = await health_engine.record_payload_health(payload)

        # Hook into Chunk 5 Explainable AIOps + Safe Remediation Simulator
        incident = aiops_engine.process_metadata_event(payload)
        remediation = remediation_sim.propose_for_incident(incident) if incident is not None else None

        await sse_broker.publish(
            payload.tenant_id,
            "telemetry",
            {
                **payload.model_dump(mode="json"),
                "evaluated_health_state": eval_state.value,
                "health_reason": eval_reason,
            },
        )
        if incident is not None:
            await sse_broker.publish(
                payload.tenant_id,
                "incident",
                incident.model_dump(mode="json"),
            )
        if remediation is not None:
            await sse_broker.publish(
                payload.tenant_id,
                "remediation",
                remediation.model_dump(mode="json"),
            )

        return {
            "status": "accepted",
            "payload_id": payload.payload_id,
            "tenant_id": payload.tenant_id,
            "region": payload.region,
            "health_state": eval_state.value,
            "incident_id": incident.incident_id if incident else None,
            "remediation_id": remediation.remediation_id if remediation else None,
        }

    @app.post("/api/v1/{region}/heartbeat")
    async def ingest_heartbeat(
        hb: CollectorHeartbeat,
        region: str = FastAPIPath(..., min_length=2),
        allowed_scopes: set[tuple[str, str]] = Depends(verify_collector_token),
    ) -> dict[str, Any]:
        enforce_tenant_region_scope(allowed_scopes, hb.tenant_id, hb.region, region)
        state, reason, _ = await health_engine.record_collector_heartbeat(hb)
        await sse_broker.publish(
            hb.tenant_id,
            "heartbeat",
            {
                **hb.model_dump(mode="json"),
                "health_state": state.value,
                "reason": reason,
            },
        )
        return {
            "status": "acknowledged",
            "collector_id": hb.collector_id,
            "health_state": state.value,
            "reason": reason,
        }

    @app.get("/api/v1/metrics")
    async def get_metrics(
        tenant_id: str = Query(..., min_length=1),
        source_id: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        return db.get_metrics(tenant_id=tenant_id, source_id=source_id, limit=limit)

    @app.get("/api/v1/health", response_model=list[HealthStatusRecord])
    async def get_health(
        tenant_id: str = Query(..., min_length=1),
    ) -> list[HealthStatusRecord]:
        return db.get_health_records(tenant_id=tenant_id)

    @app.get("/api/v1/health/transitions", response_model=list[HealthStateTransition])
    async def get_health_transitions(
        tenant_id: str = Query(..., min_length=1),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> list[HealthStateTransition]:
        return db.get_health_transitions(tenant_id=tenant_id, limit=limit)

    @app.put("/api/v1/health/thresholds", response_model=HealthThresholdsConfig)
    async def put_health_thresholds(
        config: HealthThresholdsConfig,
        tenant_id: str = Query(..., min_length=1),
    ) -> HealthThresholdsConfig:
        if config.tenant_id != tenant_id:
            raise HTTPException(
                status_code=400,
                detail="Query tenant_id must match payload tenant_id.",
            )
        return db.upsert_thresholds(config)

    @app.get("/api/v1/stats/delivery")
    async def get_delivery_stats(
        tenant_id: str = Query(..., min_length=1),
    ) -> dict[str, Any]:
        return db.get_delivery_stats(tenant_id=tenant_id)

    @app.get("/api/v1/stream")
    async def stream_tenant_events(
        request: Request,
        tenant_id: str = Query(..., min_length=1),
    ) -> StreamingResponse:
        """Live Server-Sent Events (SSE) stream strictly isolated per tenant_id."""
        queue = sse_broker.subscribe(tenant_id)

        async def event_generator() -> AsyncIterator[str]:
            try:
                yield f"event: connected\ndata: {json.dumps({'tenant_id': tenant_id, 'utc': utc_now().isoformat()})}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        chunk = await asyncio.wait_for(queue.get(), timeout=15.0)
                        yield chunk
                    except asyncio.TimeoutError:
                        # Keepalive comment every 15s to prevent proxy/browser timeouts
                        yield ": keepalive\n\n"
            finally:
                sse_broker.unsubscribe(tenant_id, queue)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # Expose internal handles cleanly for unit tests
    app.state.db = db
    app.state.health_engine = health_engine
    app.state.aiops_engine = aiops_engine
    app.state.remediation_sim = remediation_sim
    return app


app = create_app()