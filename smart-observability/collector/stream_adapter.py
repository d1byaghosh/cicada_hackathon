from __future__ import annotations

import argparse
import asyncio
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator
from zoneinfo import ZoneInfo

import httpx

from collector.config import settings
from collector.host_probes import collect_host_probe_event
from shared.contracts import EventCategoryEnum, RawTelemetryEvent, SeverityEnum


def normalize_to_utc(
    raw_ts: str | datetime | None,
    source_timezone: str | None = None,
) -> tuple[datetime, str]:
    """Converts any ISO timestamp or datetime into timezone-aware UTC + source_timezone."""
    tz_label = source_timezone or "UTC"
    if raw_ts is None:
        return datetime.now(timezone.utc), tz_label

    if isinstance(raw_ts, str):
        cleaned = raw_ts.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
    else:
        dt = raw_ts

    if dt.tzinfo is None:
        try:
            tz_obj = ZoneInfo(tz_label)
        except Exception:
            tz_obj = timezone.utc
            tz_label = "UTC"
        dt = dt.replace(tzinfo=tz_obj)
    elif source_timezone is None:
        tz_label = dt.tzname() or "UTC"

    return dt.astimezone(timezone.utc), tz_label


class ChaosTestGenerator:
    """Baseline telemetry generator + 8-scenario judge validation injector."""

    TENANT_FLEET: dict[str, dict[str, Any]] = {
        "tenant-alpha": {
            "region": "ap-south-1",
            "timezone": "Asia/Kolkata",
            "hosts": [
                ("app-blr-01.internal", "10.20.1.11"),
                ("db-blr-02.internal", "10.20.1.12"),
                ("gw-blr-edge.internal", "10.20.1.254"),
            ],
        },
        "tenant-beta": {
            "region": "eu-central-1",
            "timezone": "Europe/Berlin",
            "hosts": [
                ("api-fra-01.internal", "10.40.2.15"),
                ("cache-fra-02.internal", "10.40.2.16"),
            ],
        },
    }

    def __init__(self, collector_id: str | None = None) -> None:
        self.collector_id = collector_id or settings.collector_id
        self._tick = 0

    def generate_baseline_event(
        self,
        tenant_id: str | None = None,
        host_index: int | None = None,
    ) -> RawTelemetryEvent:
        self._tick += 1
        t_id = tenant_id or (
            settings.tenant_id
            if self._tick % 3 != 0
            else "tenant-beta"
        )
        fleet = self.TENANT_FLEET.get(t_id, self.TENANT_FLEET["tenant-alpha"])
        hosts = fleet["hosts"]
        hostname, host_ip = hosts[
            host_index % len(hosts) if host_index is not None else self._tick % len(hosts)
        ]

        cpu = round(random.uniform(22.0, 44.0), 2)
        mem = round(random.uniform(35.0, 58.0), 2)
        disk = round(random.uniform(40.0, 62.0), 2)
        latency = round(random.uniform(12.0, 32.0), 2)
        pkt_loss = round(random.uniform(0.0, 0.4), 2)
        bw = round(random.uniform(110.0, 260.0), 2)

        now_utc, tz_name = normalize_to_utc(datetime.now(timezone.utc), fleet["timezone"])
        return RawTelemetryEvent(
            tenant_id=t_id,
            region=fleet["region"],
            collector_id=self.collector_id,
            hostname=hostname,
            host_ip=host_ip,
            event_time=now_utc,
            source_timezone=tz_name,
            event_category=EventCategoryEnum.INFRASTRUCTURE,
            severity=SeverityEnum.INFO,
            raw_log=(
                f"INFO telemetry host={hostname} ip={host_ip} "
                f"cpu={cpu}% mem={mem}% latency={latency}ms status=OK"
            ),
            payload={"stream": "baseline", "service": "core-api"},
            metrics={
                "cpu_pct": cpu,
                "memory_pct": mem,
                "disk_pct": disk,
                "bandwidth_mbps": bw,
                "latency_ms": latency,
                "packet_loss_pct": pkt_loss,
                "service_up": 1.0,
            },
        )

    def inject_secret_log(self, tenant_id: str | None = None) -> list[RawTelemetryEvent]:
        """Scenario 1: Raw log containing password, Bearer JWT, and API key."""
        t_id = tenant_id or settings.tenant_id
        fleet = self.TENANT_FLEET.get(t_id, self.TENANT_FLEET["tenant-alpha"])
        hostname, host_ip = fleet["hosts"][0]
        now_utc, tz_name = normalize_to_utc(datetime.now(timezone.utc), fleet["timezone"])

        secret_log = (
            f"ERROR auth-proxy host={hostname} ip={host_ip} "
            "user=ops_admin password=supersecret_prod_99! "
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
            "aws_key=AKIAIOSFODNN7EXAMPLE api_key=sk_live_9876543210abcdef987654"
        )
        return [
            RawTelemetryEvent(
                tenant_id=t_id,
                region=fleet["region"],
                collector_id=self.collector_id,
                hostname=hostname,
                host_ip=host_ip,
                auth_user="ops_admin",
                event_time=now_utc,
                source_timezone=tz_name,
                event_category=EventCategoryEnum.SECURITY,
                severity=SeverityEnum.HIGH,
                raw_log=secret_log,
                payload={
                    "raw_header": "Bearer sk_live_9876543210abcdef987654",
                    "db_uri": "postgres://admin:TopSecretPass123@10.20.1.12:5432/prod",
                },
                metrics={
                    "cpu_pct": 48.2,
                    "memory_pct": 54.0,
                    "disk_pct": 51.0,
                    "bandwidth_mbps": 145.0,
                    "latency_ms": 24.5,
                    "packet_loss_pct": 0.0,
                    "service_up": 1.0,
                },
            )
        ]

    def inject_failed_logins(
        self,
        count: int = 12,
        tenant_id: str | None = None,
    ) -> list[RawTelemetryEvent]:
        """Scenario 3: Burst of raw authentication failures summarized locally."""
        t_id = tenant_id or settings.tenant_id
        fleet = self.TENANT_FLEET.get(t_id, self.TENANT_FLEET["tenant-alpha"])
        hostname, host_ip = fleet["hosts"][0]
        base_time = datetime.now(timezone.utc)
        events: list[RawTelemetryEvent] = []

        for idx in range(count):
            ts, tz_name = normalize_to_utc(base_time + timedelta(milliseconds=idx * 250), fleet["timezone"])
            events.append(
                RawTelemetryEvent(
                    tenant_id=t_id,
                    region=fleet["region"],
                    collector_id=self.collector_id,
                    hostname=hostname,
                    host_ip=host_ip,
                    auth_user="root",
                    auth_failed=True,
                    event_time=ts,
                    source_timezone=tz_name,
                    event_category=EventCategoryEnum.SECURITY,
                    severity=SeverityEnum.MEDIUM,
                    raw_log=(
                        f"Failed password for invalid user root from 198.51.100.42 "
                        f"port {41000 + idx} ssh2 password=wrongpass_{idx}"
                    ),
                    payload={"auth_event": "failed_login", "src_ip": "198.51.100.42"},
                    metrics={
                        "cpu_pct": 39.0,
                        "memory_pct": 49.0,
                        "disk_pct": 50.0,
                        "bandwidth_mbps": 120.0,
                        "latency_ms": 21.0,
                        "packet_loss_pct": 0.0,
                        "service_up": 1.0,
                    },
                )
            )
        return events

    def inject_latency_spike(self, tenant_id: str | None = None) -> list[RawTelemetryEvent]:
        """Scenario 4: Elevated network latency and packet loss."""
        t_id = tenant_id or settings.tenant_id
        fleet = self.TENANT_FLEET.get(t_id, self.TENANT_FLEET["tenant-alpha"])
        hostname, host_ip = fleet["hosts"][-1]
        now_utc, tz_name = normalize_to_utc(datetime.now(timezone.utc), fleet["timezone"])

        return [
            RawTelemetryEvent(
                tenant_id=t_id,
                region=fleet["region"],
                collector_id=self.collector_id,
                hostname=hostname,
                host_ip=host_ip,
                event_time=now_utc,
                source_timezone=tz_name,
                event_category=EventCategoryEnum.NETWORK,
                severity=SeverityEnum.HIGH,
                raw_log=f"WARN net-probe host={hostname} rtt=285.4ms packet_loss=14.8%",
                payload={"link": "uplink-wan-01"},
                metrics={
                    "cpu_pct": 51.0,
                    "memory_pct": 56.0,
                    "disk_pct": 48.0,
                    "bandwidth_mbps": 42.0,
                    "latency_ms": 285.4,
                    "packet_loss_pct": 14.8,
                    "service_up": 1.0,
                },
            )
        ]

    def inject_cpu_memory_anomaly(self, tenant_id: str | None = None) -> list[RawTelemetryEvent]:
        """Scenario 5: Sharp CPU and memory deviation from baseline."""
        t_id = tenant_id or settings.tenant_id
        fleet = self.TENANT_FLEET.get(t_id, self.TENANT_FLEET["tenant-alpha"])
        hostname, host_ip = fleet["hosts"][0]
        now_utc, tz_name = normalize_to_utc(datetime.now(timezone.utc), fleet["timezone"])

        return [
            RawTelemetryEvent(
                tenant_id=t_id,
                region=fleet["region"],
                collector_id=self.collector_id,
                hostname=hostname,
                host_ip=host_ip,
                event_time=now_utc,
                source_timezone=tz_name,
                event_category=EventCategoryEnum.INFRASTRUCTURE,
                severity=SeverityEnum.CRITICAL,
                raw_log=f"CRITICAL host={hostname} cpu=96.4% memory=93.8% load_avg=14.2",
                payload={"service": "checkout-worker"},
                metrics={
                    "cpu_pct": 96.4,
                    "memory_pct": 93.8,
                    "disk_pct": 71.0,
                    "bandwidth_mbps": 390.0,
                    "latency_ms": 145.0,
                    "packet_loss_pct": 2.1,
                    "service_up": 1.0,
                },
            )
        ]

    def inject_correlated_incident_burst(
        self,
        tenant_id: str | None = None,
    ) -> list[RawTelemetryEvent]:
        """Scenario 6: 5 related network + CPU + memory + service errors within 15s."""
        t_id = tenant_id or settings.tenant_id
        fleet = self.TENANT_FLEET.get(t_id, self.TENANT_FLEET["tenant-alpha"])
        hostname, host_ip = fleet["hosts"][0]
        base_time = datetime.now(timezone.utc)

        burst_specs = [
            (EventCategoryEnum.NETWORK, SeverityEnum.HIGH, 74.0, 72.0, 210.0, 9.5, "Upstream link jitter spike"),
            (EventCategoryEnum.INFRASTRUCTURE, SeverityEnum.HIGH, 89.5, 81.2, 235.0, 11.0, "Worker pool CPU saturation"),
            (EventCategoryEnum.INFRASTRUCTURE, SeverityEnum.CRITICAL, 94.8, 91.6, 260.0, 12.4, "Memory pressure rising on worker"),
            (EventCategoryEnum.NETWORK, SeverityEnum.CRITICAL, 95.1, 92.4, 310.5, 18.2, "Severe packet loss on primary route"),
            (EventCategoryEnum.INFRASTRUCTURE, SeverityEnum.CRITICAL, 97.3, 94.9, 340.0, 21.0, "Service health probe degraded"),
        ]

        events: list[RawTelemetryEvent] = []
        for idx, (cat, sev, cpu, mem, lat, loss, msg) in enumerate(burst_specs):
            ts, tz_name = normalize_to_utc(base_time + timedelta(seconds=idx * 2), fleet["timezone"])
            events.append(
                RawTelemetryEvent(
                    tenant_id=t_id,
                    region=fleet["region"],
                    collector_id=self.collector_id,
                    hostname=hostname,
                    host_ip=host_ip,
                    event_time=ts,
                    source_timezone=tz_name,
                    event_category=cat,
                    severity=sev,
                    raw_log=f"{sev.value} host={hostname} {msg} cpu={cpu}% mem={mem}% lat={lat}ms",
                    payload={"correlated_group": "burst-demo"},
                    metrics={
                        "cpu_pct": cpu,
                        "memory_pct": mem,
                        "disk_pct": 68.0,
                        "bandwidth_mbps": 410.0,
                        "latency_ms": lat,
                        "packet_loss_pct": loss,
                        "service_up": 0.0 if idx == 4 else 1.0,
                    },
                )
            )
        return events

    def inject_duplicate_and_out_of_order(
        self,
        tenant_id: str | None = None,
    ) -> list[RawTelemetryEvent]:
        """Scenario 7: Identical payload_id emitted twice + 90s backdated event."""
        t_id = tenant_id or settings.tenant_id
        fleet = self.TENANT_FLEET.get(t_id, self.TENANT_FLEET["tenant-alpha"])
        hostname, host_ip = fleet["hosts"][0]
        now_utc, tz_name = normalize_to_utc(datetime.now(timezone.utc), fleet["timezone"])
        dup_id = str(uuid.uuid4())

        original = RawTelemetryEvent(
            payload_id=dup_id,
            tenant_id=t_id,
            region=fleet["region"],
            collector_id=self.collector_id,
            hostname=hostname,
            host_ip=host_ip,
            event_time=now_utc,
            source_timezone=tz_name,
            event_category=EventCategoryEnum.INFRASTRUCTURE,
            severity=SeverityEnum.MEDIUM,
            raw_log=f"INFO idempotency test host={hostname} dup_id={dup_id}",
            payload={"test": "duplicate_delivery"},
            metrics={
                "cpu_pct": 55.5,
                "memory_pct": 60.0,
                "disk_pct": 52.0,
                "bandwidth_mbps": 180.0,
                "latency_ms": 42.0,
                "packet_loss_pct": 0.5,
                "service_up": 1.0,
            },
        )
        duplicate = original.model_copy(deep=True)
        backdated = RawTelemetryEvent(
            tenant_id=t_id,
            region=fleet["region"],
            collector_id=self.collector_id,
            hostname=hostname,
            host_ip=host_ip,
            event_time=now_utc - timedelta(seconds=90),
            source_timezone=tz_name,
            event_category=EventCategoryEnum.NETWORK,
            severity=SeverityEnum.LOW,
            raw_log=f"INFO delayed packet host={hostname} backdated_sec=90",
            payload={"test": "out_of_order_delivery"},
            metrics={
                "cpu_pct": 33.0,
                "memory_pct": 48.0,
                "disk_pct": 52.0,
                "bandwidth_mbps": 150.0,
                "latency_ms": 65.0,
                "packet_loss_pct": 1.2,
                "service_up": 1.0,
            },
        )
        return [original, duplicate, backdated]

    def get_scenario_events(
        self,
        scenario: str,
        tenant_id: str | None = None,
    ) -> list[RawTelemetryEvent]:
        key = scenario.strip().lower()
        mapping = {
            "secret_log": lambda: self.inject_secret_log(tenant_id),
            "failed_logins": lambda: self.inject_failed_logins(12, tenant_id),
            "latency_spike": lambda: self.inject_latency_spike(tenant_id),
            "cpu_memory_anomaly": lambda: self.inject_cpu_memory_anomaly(tenant_id),
            "correlated_burst": lambda: self.inject_correlated_incident_burst(tenant_id),
            "duplicate_and_out_of_order": lambda: self.inject_duplicate_and_out_of_order(tenant_id),
            "baseline": lambda: [self.generate_baseline_event(tenant_id)],
        }
        if key not in mapping:
            raise ValueError(f"Unknown scenario '{scenario}'. Valid: {sorted(mapping.keys())}")
        return mapping[key]()


class OrganizerStreamAdapter:
    """Consumes organizer-provided HTTP/SSE/NDJSON/file telemetry stream or demo fallback."""

    def __init__(
        self,
        stream_url: str | None = None,
        mode: str | None = None,
    ) -> None:
        self.stream_url = stream_url if stream_url is not None else settings.organizer_stream_url
        self.mode = (mode or settings.organizer_stream_mode).lower()
        self.chaos = ChaosTestGenerator()
        self.injected_queue: asyncio.Queue[RawTelemetryEvent] = asyncio.Queue()

    async def enqueue_scenario(self, scenario: str, tenant_id: str | None = None) -> int:
        events = self.chaos.get_scenario_events(scenario, tenant_id=tenant_id)
        for ev in events:
            await self.injected_queue.put(ev)
        return len(events)

    def _normalize_external_record(self, data: dict[str, Any]) -> RawTelemetryEvent:
        event_time, source_tz = normalize_to_utc(
            data.get("event_time") or data.get("timestamp"),
            data.get("source_timezone") or data.get("timezone"),
        )
        raw_metrics = data.get("metrics") or {}
        metrics = {
            "cpu_pct": float(raw_metrics.get("cpu_pct", data.get("cpu_pct", 0.0))),
            "memory_pct": float(raw_metrics.get("memory_pct", data.get("memory_pct", 0.0))),
            "disk_pct": float(raw_metrics.get("disk_pct", data.get("disk_pct", 0.0))),
            "bandwidth_mbps": float(raw_metrics.get("bandwidth_mbps", data.get("bandwidth_mbps", 0.0))),
            "latency_ms": float(raw_metrics.get("latency_ms", data.get("latency_ms", 0.0))),
            "packet_loss_pct": float(raw_metrics.get("packet_loss_pct", data.get("packet_loss_pct", 0.0))),
            "service_up": float(raw_metrics.get("service_up", 1.0)),
        }
        cat_raw = str(data.get("event_category", "INFRASTRUCTURE")).upper()
        sev_raw = str(data.get("severity", "INFO")).upper()
        category = (
            EventCategoryEnum(cat_raw)
            if cat_raw in EventCategoryEnum._value2member_map_
            else EventCategoryEnum.INFRASTRUCTURE
        )
        severity = (
            SeverityEnum(sev_raw)
            if sev_raw in SeverityEnum._value2member_map_
            else SeverityEnum.INFO
        )
        return RawTelemetryEvent(
            payload_id=data.get("payload_id"),
            tenant_id=str(data.get("tenant_id", settings.tenant_id)),
            region=str(data.get("region", settings.region)),
            collector_id=str(data.get("collector_id", settings.collector_id)),
            hostname=str(data.get("hostname") or data.get("host") or "unknown-host"),
            host_ip=str(data.get("host_ip") or data.get("ip") or "0.0.0.0"),
            auth_user=data.get("auth_user"),
            auth_failed=bool(data.get("auth_failed", False)),
            event_time=event_time,
            source_timezone=source_tz,
            event_category=category,
            severity=severity,
            raw_log=str(data.get("raw_log") or data.get("message") or ""),
            payload=data.get("payload") if isinstance(data.get("payload"), dict) else {},
            metrics=metrics,
        )

    async def _stream_from_file(self, path: Path) -> AsyncIterator[RawTelemetryEvent]:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                text = line.strip()
                if not text:
                    continue
                yield self._normalize_external_record(json.loads(text))
                await asyncio.sleep(0.1)

    async def _stream_from_http(self, url: str) -> AsyncIterator[RawTelemetryEvent]:
        timeout = httpx.Timeout(connect=5.0, read=30.0, write=5.0, pool=5.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("GET", url) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    cleaned = line.strip()
                    if not cleaned or cleaned.startswith(":"):
                        continue
                    if cleaned.startswith("data:"):
                        cleaned = cleaned[5:].strip()
                    if not cleaned:
                        continue
                    try:
                        yield self._normalize_external_record(json.loads(cleaned))
                    except Exception:
                        continue

    async def stream_events(self) -> AsyncIterator[RawTelemetryEvent]:
        """Yields injected chaos events immediately, interleaved with organizer or demo stream."""
        if self.mode == "file" and self.stream_url and Path(self.stream_url).exists():
            async for ev in self._stream_from_file(Path(self.stream_url)):
                while not self.injected_queue.empty():
                    yield await self.injected_queue.get()
                yield ev
            return

        if self.mode == "organizer" and self.stream_url.startswith(("http://", "https://")):
            try:
                async for ev in self._stream_from_http(self.stream_url):
                    while not self.injected_queue.empty():
                        yield await self.injected_queue.get()
                    yield ev
                return
            except Exception:
                # Fall back to demo generator if organizer stream is temporarily unavailable
                pass

        # Continuous demo stream + optional local host probe
        cycle = 0
        while True:
            while not self.injected_queue.empty():
                yield await self.injected_queue.get()

            cycle += 1
            if settings.enable_host_probes and cycle % 3 == 0:
                host_ev = await collect_host_probe_event()
                if host_ev is not None:
                    yield host_ev

            yield self.chaos.generate_baseline_event()

            try:
                # Wake up early if a chaos scenario is injected
                injected = await asyncio.wait_for(
                    self.injected_queue.get(),
                    timeout=settings.ingest_interval_sec,
                )
                yield injected
            except asyncio.TimeoutError:
                continue


async def _cli_main(mode: str, count: int, scenario: str | None) -> None:
    adapter = OrganizerStreamAdapter(mode=mode)
    if scenario:
        await adapter.enqueue_scenario(scenario)

    emitted = 0
    async for event in adapter.stream_events():
        print(event.model_dump_json())
        emitted += 1
        if emitted >= count:
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tier 1 Telemetry Stream Adapter CLI")
    parser.add_argument("--mode", default="demo", choices=["demo", "organizer", "file"])
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--scenario", default=None)
    args = parser.parse_args()
    asyncio.run(_cli_main(args.mode, args.count, args.scenario))