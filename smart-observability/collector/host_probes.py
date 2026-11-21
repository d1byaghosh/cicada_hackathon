from __future__ import annotations

import asyncio
import socket
import time
from datetime import datetime, timezone
from typing import Any

from collector.config import settings
from shared.contracts import EventCategoryEnum, RawTelemetryEvent, SeverityEnum

try:
    import psutil
except ImportError:  # pragma: no cover - optional dependency
    psutil = None  # type: ignore[assignment]

try:
    from icmplib import ping as icmp_ping
except ImportError:  # pragma: no cover - optional dependency
    icmp_ping = None  # type: ignore[assignment]

_last_net_io: tuple[float, int, int] | None = None


def _read_bandwidth_mbps() -> float:
    global _last_net_io
    if psutil is None:
        return 0.0

    now = time.monotonic()
    counters = psutil.net_io_counters()
    if counters is None:
        return 0.0

    if _last_net_io is None:
        _last_net_io = (now, counters.bytes_sent, counters.bytes_recv)
        return 0.0

    prev_t, prev_sent, prev_recv = _last_net_io
    elapsed = max(now - prev_t, 0.001)
    delta_bytes = max(0, (counters.bytes_sent - prev_sent) + (counters.bytes_recv - prev_recv))
    _last_net_io = (now, counters.bytes_sent, counters.bytes_recv)
    return round((delta_bytes * 8.0) / (elapsed * 1_000_000.0), 2)


def _read_ping_metrics(target: str) -> tuple[float, float]:
    if icmp_ping is None:
        return 0.0, 0.0
    try:
        # privileged=False avoids root requirement in WSL/Linux containers
        host = icmp_ping(target, count=1, timeout=1.5, privileged=False)
        return round(float(host.avg_rtt), 2), round(float(host.packet_loss * 100.0), 2)
    except Exception:
        return 0.0, 0.0


def _collect_host_metrics_sync() -> dict[str, Any]:
    cpu_pct = float(psutil.cpu_percent(interval=None)) if psutil else 0.0
    memory_pct = float(psutil.virtual_memory().percent) if psutil else 0.0
    disk_pct = float(psutil.disk_usage("/").percent) if psutil else 0.0
    bandwidth_mbps = _read_bandwidth_mbps()
    latency_ms, packet_loss_pct = _read_ping_metrics(settings.ping_target)

    hostname = socket.gethostname()
    try:
        host_ip = socket.gethostbyname(hostname)
    except OSError:
        host_ip = "127.0.0.1"

    return {
        "hostname": hostname,
        "host_ip": host_ip,
        "cpu_pct": round(cpu_pct, 2),
        "memory_pct": round(memory_pct, 2),
        "disk_pct": round(disk_pct, 2),
        "bandwidth_mbps": bandwidth_mbps,
        "latency_ms": latency_ms,
        "packet_loss_pct": packet_loss_pct,
        "service_up": True,
    }


async def collect_host_probe_event() -> RawTelemetryEvent | None:
    """Non-blocking local host metric snapshot normalized to RawTelemetryEvent."""
    if psutil is None:
        return None

    data = await asyncio.to_thread(_collect_host_metrics_sync)
    local_tz = datetime.now().astimezone().tzname() or "UTC"
    now_utc = datetime.now(timezone.utc)

    severity = SeverityEnum.INFO
    if data["cpu_pct"] >= 90 or data["memory_pct"] >= 90 or data["packet_loss_pct"] >= 10:
        severity = SeverityEnum.HIGH
    elif data["cpu_pct"] >= 75 or data["memory_pct"] >= 80:
        severity = SeverityEnum.MEDIUM

    return RawTelemetryEvent(
        tenant_id=settings.tenant_id,
        region=settings.region,
        collector_id=settings.collector_id,
        hostname=data["hostname"],
        host_ip=data["host_ip"],
        event_time=now_utc,
        source_timezone=local_tz,
        event_category=EventCategoryEnum.INFRASTRUCTURE,
        severity=severity,
        raw_log=(
            f"host_probe host={data['hostname']} ip={data['host_ip']} "
            f"cpu={data['cpu_pct']}% mem={data['memory_pct']}% "
            f"disk={data['disk_pct']}% rtt={data['latency_ms']}ms"
        ),
        payload={"probe": "local_host_psutil", "target": settings.ping_target},
        metrics={
            "cpu_pct": data["cpu_pct"],
            "memory_pct": data["memory_pct"],
            "disk_pct": data["disk_pct"],
            "bandwidth_mbps": data["bandwidth_mbps"],
            "latency_ms": data["latency_ms"],
            "packet_loss_pct": data["packet_loss_pct"],
            "service_up": 1.0,
        },
    )


def get_collector_process_usage() -> tuple[float, float]:
    """Returns (cpu_pct, mem_pct) for CollectorHeartbeat without blocking."""
    if psutil is None:
        return 0.0, 0.0
    try:
        proc = psutil.Process()
        return round(float(proc.cpu_percent(interval=None)), 2), round(
            float(proc.memory_percent()), 2
        )
    except Exception:
        return 0.0, 0.0