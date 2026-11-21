from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Awaitable, Callable

from saas.database import SaaSMetadataDB, parse_utc_iso, utc_now
from shared.contracts import (
    CollectorHeartbeat,
    HealthStateEnum,
    HealthStateTransition,
    HealthThresholdsConfig,
    SanitizedMetadataPayload,
    SeverityEnum,
)


class HealthEngine:
    """
    Four-state health evaluator (EXCELLENT, GOOD, FAIR, POOR) with configurable
    per-tenant thresholds, UTC state transitions, and a 10-second stale watchdog (>60s -> POOR).
    """

    def __init__(
        self,
        db: SaaSMetadataDB,
        on_transition: Callable[[HealthStateTransition], Awaitable[None]] | None = None,
    ) -> None:
        self.db = db
        self.on_transition = on_transition

    def evaluate_payload_health(
        self,
        payload: SanitizedMetadataPayload,
        cfg: HealthThresholdsConfig | None = None,
    ) -> tuple[HealthStateEnum, str]:
        thresholds = cfg or self.db.get_thresholds(payload.tenant_id)
        m = payload.metrics
        cpu = float(m.get("cpu_pct", 0.0))
        mem = float(m.get("memory_pct", 0.0))
        lat = float(m.get("latency_ms", 0.0))
        loss = float(m.get("packet_loss_pct", 0.0))
        service_up = float(m.get("service_up", 1.0))

        poor_reasons: list[str] = []
        if service_up < 1.0:
            poor_reasons.append("service_up=0 (service probe failed)")
        if cpu >= thresholds.cpu_poor_pct:
            poor_reasons.append(f"CPU {cpu:.1f}% >= {thresholds.cpu_poor_pct:.1f}%")
        if mem >= thresholds.memory_poor_pct:
            poor_reasons.append(f"Memory {mem:.1f}% >= {thresholds.memory_poor_pct:.1f}%")
        if lat >= thresholds.latency_poor_ms:
            poor_reasons.append(f"Latency {lat:.1f}ms >= {thresholds.latency_poor_ms:.1f}ms")
        if loss >= thresholds.packet_loss_poor_pct:
            poor_reasons.append(f"Packet loss {loss:.1f}% >= {thresholds.packet_loss_poor_pct:.1f}%")
        if payload.severity == SeverityEnum.CRITICAL:
            poor_reasons.append(f"Critical event: {payload.concise_alert_context}")

        if poor_reasons:
            return HealthStateEnum.POOR, "; ".join(poor_reasons)

        fair_reasons: list[str] = []
        if cpu >= thresholds.cpu_fair_pct:
            fair_reasons.append(f"CPU {cpu:.1f}% >= {thresholds.cpu_fair_pct:.1f}%")
        if mem >= thresholds.memory_fair_pct:
            fair_reasons.append(f"Memory {mem:.1f}% >= {thresholds.memory_fair_pct:.1f}%")
        if lat >= thresholds.latency_fair_ms:
            fair_reasons.append(f"Latency {lat:.1f}ms >= {thresholds.latency_fair_ms:.1f}ms")
        if loss >= thresholds.packet_loss_fair_pct:
            fair_reasons.append(f"Packet loss {loss:.1f}% >= {thresholds.packet_loss_fair_pct:.1f}%")
        if payload.severity == SeverityEnum.HIGH:
            fair_reasons.append(f"High severity event: {payload.concise_alert_context}")

        if fair_reasons:
            return HealthStateEnum.FAIR, "; ".join(fair_reasons)

        if (
            cpu >= thresholds.cpu_fair_pct * 0.7
            or mem >= thresholds.memory_fair_pct * 0.75
            or lat >= thresholds.latency_fair_ms * 0.5
            or payload.severity == SeverityEnum.MEDIUM
        ):
            return (
                HealthStateEnum.GOOD,
                f"Within nominal bounds (CPU {cpu:.1f}%, Mem {mem:.1f}%, Latency {lat:.1f}ms)",
            )

        return (
            HealthStateEnum.EXCELLENT,
            f"Optimal telemetry (CPU {cpu:.1f}%, Mem {mem:.1f}%, Latency {lat:.1f}ms, Loss {loss:.1f}%)",
        )

    def evaluate_collector_heartbeat(
        self,
        hb: CollectorHeartbeat,
    ) -> tuple[HealthStateEnum, str]:
        if hb.config_status.upper() != "HEALTHY":
            return HealthStateEnum.POOR, f"Collector config status: {hb.config_status}"
        if hb.buffer_queue_depth >= 50 or hb.collector_cpu_pct >= 85.0:
            return (
                HealthStateEnum.POOR,
                f"Collector overloaded (queue={hb.buffer_queue_depth}, cpu={hb.collector_cpu_pct:.1f}%)",
            )
        if hb.buffer_queue_depth > 0 or hb.collector_cpu_pct >= 65.0:
            return (
                HealthStateEnum.FAIR,
                f"Collector draining buffer (queue={hb.buffer_queue_depth}, cpu={hb.collector_cpu_pct:.1f}%)",
            )
        if hb.collector_cpu_pct >= 35.0:
            return (
                HealthStateEnum.GOOD,
                f"Collector healthy (queue=0, cpu={hb.collector_cpu_pct:.1f}%)",
            )
        return (
            HealthStateEnum.EXCELLENT,
            f"Collector online & optimal (v{hb.version}, queue=0)",
        )

    async def record_payload_health(
        self,
        payload: SanitizedMetadataPayload,
    ) -> tuple[HealthStateEnum, str, HealthStateTransition | None]:
        state, reason = self.evaluate_payload_health(payload)
        transition = self.db.upsert_entity_health(
            tenant_id=payload.tenant_id,
            region=payload.region,
            entity_id=payload.source_id,
            entity_type="SOURCE",
            health_state=state,
            reason=reason,
            last_seen_utc=utc_now(),
            is_stale=False,
            latest_metrics=payload.metrics,
        )
        if transition is not None and self.on_transition is not None:
            await self.on_transition(transition)
        return state, reason, transition

    async def record_collector_heartbeat(
        self,
        hb: CollectorHeartbeat,
    ) -> tuple[HealthStateEnum, str, HealthStateTransition | None]:
        state, reason = self.evaluate_collector_heartbeat(hb)
        transition = self.db.upsert_collector_heartbeat(hb, state, reason)
        if transition is not None and self.on_transition is not None:
            await self.on_transition(transition)
        return state, reason, transition

    async def run_stale_check_once(
        self,
        now: datetime | None = None,
    ) -> list[HealthStateTransition]:
        """
        Checks all monitored sources and collectors; any entity silent for > stale_timeout_sec
        (default 60s) is auto-downgraded to POOR with is_stale=True and a UTC transition log.
        """
        current_time = (now or utc_now()).astimezone(timezone.utc)
        entities = self.db.get_all_entities_for_watchdog()
        transitions: list[HealthStateTransition] = []

        for row in entities:
            cfg = self.db.get_thresholds(row["tenant_id"])
            last_seen = parse_utc_iso(row["last_seen_utc"])
            age_sec = (current_time - last_seen).total_seconds()

            if age_sec > cfg.stale_timeout_sec and (
                not bool(row["is_stale"]) or row["health_state"] != HealthStateEnum.POOR.value
            ):
                label = "Collector heartbeat" if row["entity_type"] == "COLLECTOR" else "Source telemetry"
                reason = (
                    f"{label} missing for >{cfg.stale_timeout_sec}s "
                    f"({int(age_sec)}s silent) — stale data auto-downgrade"
                )
                transition = self.db.upsert_entity_health(
                    tenant_id=row["tenant_id"],
                    region=row["region"],
                    entity_id=row["entity_id"],
                    entity_type=row["entity_type"],
                    health_state=HealthStateEnum.POOR,
                    reason=reason,
                    last_seen_utc=last_seen,
                    is_stale=True,
                    version=row["version"],
                    collector_cpu_pct=float(row["collector_cpu_pct"]),
                    collector_mem_pct=float(row["collector_mem_pct"]),
                    buffer_queue_depth=int(row["buffer_queue_depth"]),
                    config_status="STALE",
                )
                if transition is not None:
                    transitions.append(transition)
                    if self.on_transition is not None:
                        await self.on_transition(transition)

        return transitions

    async def watchdog_loop(self, interval_sec: float = 10.0) -> None:
        """Runs every 10 seconds to enforce the <=60s offline detection SLA."""
        while True:
            try:
                await self.run_stale_check_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            await asyncio.sleep(interval_sec)