from __future__ import annotations

from datetime import datetime, timezone

import pytest

from collector.stream_adapter import (
    ChaosTestGenerator,
    OrganizerStreamAdapter,
    normalize_to_utc,
)
from shared.contracts import EventCategoryEnum, RawTelemetryEvent, SeverityEnum


def test_normalize_to_utc_handles_offset_and_naive_timestamps() -> None:
    # Offset-aware IST timestamp (+05:30) converts cleanly to UTC
    dt_utc, tz_name = normalize_to_utc("2026-11-21T10:30:00+05:30", "Asia/Kolkata")
    assert dt_utc.tzinfo == timezone.utc
    assert dt_utc.hour == 5
    assert dt_utc.minute == 0
    assert tz_name == "Asia/Kolkata"

    # Naive timestamp interpreted using source_timezone and converted to UTC
    naive_utc, tz_label = normalize_to_utc("2026-11-21T10:30:00", "Asia/Kolkata")
    assert naive_utc.tzinfo == timezone.utc
    assert naive_utc == dt_utc
    assert tz_label == "Asia/Kolkata"

    # Unknown timezone falls back safely to UTC without crashing
    fallback_utc, fallback_tz = normalize_to_utc("2026-11-21T05:00:00", "Invalid/Zone")
    assert fallback_utc.tzinfo == timezone.utc
    assert fallback_tz == "UTC"


@pytest.mark.parametrize(
    "scenario,expected_min_count",
    [
        ("baseline", 1),
        ("secret_log", 1),
        ("failed_logins", 12),
        ("latency_spike", 1),
        ("cpu_memory_anomaly", 1),
        ("correlated_burst", 5),
        ("duplicate_and_out_of_order", 3),
    ],
)
def test_all_chaos_scenarios_emit_valid_raw_telemetry_events(
    scenario: str,
    expected_min_count: int,
) -> None:
    gen = ChaosTestGenerator(collector_id="collector-test-01")
    events = gen.get_scenario_events(scenario, tenant_id="tenant-alpha")

    assert len(events) >= expected_min_count
    for ev in events:
        assert isinstance(ev, RawTelemetryEvent)
        assert ev.tenant_id == "tenant-alpha"
        assert ev.region == "ap-south-1"
        assert ev.event_time.tzinfo == timezone.utc
        assert ev.source_timezone == "Asia/Kolkata"


def test_duplicate_and_out_of_order_scenario_contract() -> None:
    gen = ChaosTestGenerator()
    events = gen.inject_duplicate_and_out_of_order(tenant_id="tenant-alpha")
    assert len(events) == 3

    original, duplicate, backdated = events
    # First two share the exact same payload_id for idempotency verification
    assert original.payload_id is not None
    assert original.payload_id == duplicate.payload_id

    # Third event is intentionally backdated by 90 seconds
    delta_sec = (original.event_time - backdated.event_time).total_seconds()
    assert 85.0 <= delta_sec <= 95.0


def test_unknown_scenario_raises_value_error() -> None:
    gen = ChaosTestGenerator()
    with pytest.raises(ValueError, match="Unknown scenario"):
        gen.get_scenario_events("does_not_exist")


def test_external_organizer_record_normalizes_to_utc_raw_event() -> None:
    adapter = OrganizerStreamAdapter(mode="demo")
    raw_record = {
        "tenant_id": "tenant-beta",
        "region": "eu-central-1",
        "hostname": "api-fra-01.internal",
        "host_ip": "10.40.2.15",
        "timestamp": "2026-11-21T12:00:00+01:00",
        "timezone": "Europe/Berlin",
        "event_category": "NETWORK",
        "severity": "HIGH",
        "message": "High jitter on uplink",
        "metrics": {"latency_ms": 240.5, "packet_loss_pct": 8.2},
    }

    event = adapter._normalize_external_record(raw_record)
    assert isinstance(event, RawTelemetryEvent)
    assert event.event_time == datetime(2026, 11, 21, 11, 0, 0, tzinfo=timezone.utc)
    assert event.source_timezone == "Europe/Berlin"
    assert event.event_category == EventCategoryEnum.NETWORK
    assert event.severity == SeverityEnum.HIGH
    assert event.metrics["latency_ms"] == 240.5
    assert event.metrics["packet_loss_pct"] == 8.2