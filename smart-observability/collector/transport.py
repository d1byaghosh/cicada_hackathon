from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx

from collector.config import settings
from collector.host_probes import get_collector_process_usage
from collector.local_db import LocalCollectorDB
from shared.contracts import CollectorHeartbeat, SanitizedMetadataPayload


class CollectorTransport:
    """
    Authenticated (X-Collector-Token), TLS-ready httpx transport with:
    - Local SQLite outage buffering (outbound_queue)
    - Exponential-backoff FIFO retry worker (zero loss, zero duplicates)
    - 15-second collector heartbeat emitter
    """

    def __init__(self, db: LocalCollectorDB) -> None:
        self.db = db
        self.simulate_outage: bool = False
        self.pause_heartbeat: bool = False
        self.last_heartbeat_utc: str | None = None
        self.last_heartbeat_status: str = "PENDING"
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        verify_opt: str | bool = settings.tls_ca_bundle if settings.tls_ca_bundle else True
        timeout = httpx.Timeout(
            connect=settings.http_timeout_sec,
            read=settings.http_timeout_sec,
            write=settings.http_timeout_sec,
            pool=settings.http_timeout_sec,
        )
        self._client = httpx.AsyncClient(
            base_url=settings.saas_base_url,
            timeout=timeout,
            verify=verify_opt,
            headers={
                "X-Collector-Token": settings.collector_token,
                "Content-Type": "application/json",
            },
        )

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _post_ingest_json(self, region: str, payload_json: str) -> None:
        if self.simulate_outage:
            raise httpx.ConnectError("Simulated SaaS outage enabled on Tier 1 collector")
        if self._client is None:
            await self.start()
        assert self._client is not None

        response = await self._client.post(
            f"/api/v1/{region}/ingest",
            content=payload_json.encode("utf-8"),
        )
        if response.status_code >= 500 or response.status_code == 429:
            raise httpx.HTTPStatusError(
                f"Retryable Tier 2 status {response.status_code}",
                request=response.request,
                response=response,
            )
        response.raise_for_status()

    async def send_payload(self, payload: SanitizedMetadataPayload) -> str:
        """Attempts immediate delivery; buffers into SQLite outbound_queue on any outage."""
        payload_json = payload.model_dump_json()
        try:
            await self._post_ingest_json(payload.region, payload_json)
            self.db.update_egress_status(payload.payload_id, "ACKNOWLEDGED", datetime.now(timezone.utc))
            return "ACKNOWLEDGED"
        except Exception as exc:
            self.db.enqueue_outbound(
                payload_id=payload.payload_id,
                region=payload.region,
                payload_json=payload_json,
                error=str(exc),
            )
            self.db.update_egress_status(payload.payload_id, "BUFFERED", datetime.now(timezone.utc))
            return "BUFFERED"

    async def flush_outbound_once(self) -> int:
        """Flushes pending buffered records FIFO; stops immediately if outage persists."""
        if self.simulate_outage:
            return 0

        pending = self.db.get_pending_outbound(limit=50)
        delivered = 0
        for row in pending:
            try:
                await self._post_ingest_json(row["region"], row["payload_json"])
                self.db.mark_outbound_delivered(row["payload_id"])
                self.db.update_egress_status(
                    row["payload_id"],
                    "ACKNOWLEDGED",
                    datetime.now(timezone.utc),
                )
                delivered += 1
            except Exception as exc:
                self.db.increment_outbound_retry(row["payload_id"], str(exc))
                break
        return delivered

    async def retry_worker_loop(self) -> None:
        """Background exponential-backoff retry worker (1s -> 2s -> 4s, capped at 5s)."""
        backoff = 1.0
        while True:
            try:
                pending_before = self.db.get_buffer_stats()["buffer_queue_depth"]
                if pending_before > 0 and not self.simulate_outage:
                    flushed = await self.flush_outbound_once()
                    if flushed > 0:
                        backoff = 1.0
                        continue
                    backoff = min(backoff * 2.0, 5.0)
                else:
                    backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception:
                backoff = min(backoff * 2.0, 5.0)
            await asyncio.sleep(backoff)

    async def send_heartbeat_once(self) -> bool:
        if self.pause_heartbeat or self.simulate_outage:
            self.last_heartbeat_status = "PAUSED" if self.pause_heartbeat else "BLOCKED_OUTAGE"
            return False

        if self._client is None:
            await self.start()
        assert self._client is not None

        stats = self.db.get_buffer_stats()
        cpu_pct, mem_pct = get_collector_process_usage()
        now_utc = datetime.now(timezone.utc)

        hb = CollectorHeartbeat(
            collector_id=settings.collector_id,
            tenant_id=settings.tenant_id,
            region=settings.region,
            version=settings.collector_version,
            sent_at_utc=now_utc,
            collector_cpu_pct=cpu_pct,
            collector_mem_pct=mem_pct,
            buffer_queue_depth=stats["buffer_queue_depth"],
            config_status="HEALTHY",
        )
        try:
            resp = await self._client.post(
                f"/api/v1/{settings.region}/heartbeat",
                content=hb.model_dump_json().encode("utf-8"),
            )
            resp.raise_for_status()
            self.last_heartbeat_utc = now_utc.isoformat()
            self.last_heartbeat_status = "ACKNOWLEDGED"
            return True
        except Exception as exc:
            self.last_heartbeat_status = f"FAILED: {type(exc).__name__}"
            return False

    async def heartbeat_worker_loop(self) -> None:
        """Emits collector heartbeat every 15 seconds so Tier 2 detects >60s offline cleanly."""
        while True:
            try:
                await self.send_heartbeat_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            await asyncio.sleep(settings.heartbeat_interval_sec)

    def get_status(self) -> dict[str, Any]:
        stats = self.db.get_buffer_stats()
        return {
            **stats,
            "collector_id": settings.collector_id,
            "tenant_id": settings.tenant_id,
            "region": settings.region,
            "saas_base_url": settings.saas_base_url,
            "simulate_outage": self.simulate_outage,
            "pause_heartbeat": self.pause_heartbeat,
            "last_heartbeat_utc": self.last_heartbeat_utc,
            "last_heartbeat_status": self.last_heartbeat_status,
        }