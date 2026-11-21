from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _ensure_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    else:
        dt = value
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class HealthStateEnum(str, Enum):
    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    FAIR = "FAIR"
    POOR = "POOR"


class SeverityEnum(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventCategoryEnum(str, Enum):
    INFRASTRUCTURE = "INFRASTRUCTURE"
    NETWORK = "NETWORK"
    SECURITY = "SECURITY"
    COLLECTOR = "COLLECTOR"


class RawTelemetryEvent(BaseModel):
    """Tier 1 local-only event containing unredacted logs, hostnames, IPs, and payloads."""

    payload_id: str | None = None
    tenant_id: str = Field(..., min_length=1)
    region: str = Field(..., min_length=2)
    collector_id: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1)
    host_ip: str = Field(..., min_length=1)
    auth_user: str | None = None
    auth_failed: bool = False
    event_time: datetime
    source_timezone: str = "UTC"
    event_category: EventCategoryEnum
    severity: SeverityEnum
    raw_log: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, float] = Field(default_factory=dict)

    @field_validator("event_time", mode="before")
    @classmethod
    def _validate_event_time_utc(cls, v: datetime | str) -> datetime:
        return _ensure_utc(v)


class SanitizedMetadataPayload(BaseModel):
    """
    STRICT TRUST-BOUNDARY ALLOW-LIST.
    extra='forbid' guarantees raw_log, password, host_ip, or unapproved keys raise ValidationError.
    """

    model_config = ConfigDict(extra="forbid")

    payload_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    region: str = Field(..., min_length=2)
    collector_id: str = Field(..., min_length=1)
    source_id: str = Field(..., min_length=1)
    event_time: datetime
    source_timezone: str = "UTC"
    event_category: EventCategoryEnum
    severity: SeverityEnum
    health_state: HealthStateEnum
    metrics: dict[str, float] = Field(default_factory=dict)
    concise_alert_context: str = Field(..., max_length=240)
    redaction_count: int = Field(default=0, ge=0)

    @field_validator("event_time", mode="before")
    @classmethod
    def _validate_event_time_utc(cls, v: datetime | str) -> datetime:
        return _ensure_utc(v)


class EgressProofRecord(BaseModel):
    """Logged strictly before Tier 1 network egress to power the Egress Proof Panel."""

    payload_id: str
    raw_preview_redacted_markers: str
    secrets_detected: list[str] = Field(default_factory=list)
    outbound_payload: SanitizedMetadataPayload
    transmitted_at_utc: datetime
    delivery_status: Literal["SENT", "BUFFERED", "ACKNOWLEDGED"] = "SENT"

    @field_validator("transmitted_at_utc", mode="before")
    @classmethod
    def _validate_transmitted_utc(cls, v: datetime | str) -> datetime:
        return _ensure_utc(v)


class CollectorHeartbeat(BaseModel):
    """Emitted every 15s by Tier 1 so Tier 2 can detect offline collectors within <=60s."""

    model_config = ConfigDict(extra="forbid")

    collector_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    region: str = Field(..., min_length=2)
    version: str = "1.0.0"
    sent_at_utc: datetime
    collector_cpu_pct: float = Field(default=0.0, ge=0.0)
    collector_mem_pct: float = Field(default=0.0, ge=0.0)
    buffer_queue_depth: int = Field(default=0, ge=0)
    config_status: str = "HEALTHY"

    @field_validator("sent_at_utc", mode="before")
    @classmethod
    def _validate_sent_utc(cls, v: datetime | str) -> datetime:
        return _ensure_utc(v)


class HealthThresholdsConfig(BaseModel):
    """Configurable per-tenant thresholds driving the Four-State Health Engine."""

    tenant_id: str = Field(..., min_length=1)
    cpu_fair_pct: float = 75.0
    cpu_poor_pct: float = 90.0
    memory_fair_pct: float = 80.0
    memory_poor_pct: float = 90.0
    latency_fair_ms: float = 120.0
    latency_poor_ms: float = 250.0
    packet_loss_fair_pct: float = 3.0
    packet_loss_poor_pct: float = 10.0
    stale_timeout_sec: int = Field(default=60, ge=10, le=600)


class HealthStatusRecord(BaseModel):
    tenant_id: str
    region: str
    entity_id: str
    entity_type: Literal["COLLECTOR", "SOURCE"]
    health_state: HealthStateEnum
    reason: str
    last_seen_utc: datetime
    is_stale: bool = False
    version: str = "1.0.0"
    collector_cpu_pct: float = 0.0
    collector_mem_pct: float = 0.0
    buffer_queue_depth: int = 0
    latest_metrics: dict[str, float] = Field(default_factory=dict)

    @field_validator("last_seen_utc", mode="before")
    @classmethod
    def _validate_last_seen_utc(cls, v: datetime | str) -> datetime:
        return _ensure_utc(v)


class HealthStateTransition(BaseModel):
    tenant_id: str
    region: str
    entity_id: str
    entity_type: Literal["COLLECTOR", "SOURCE"]
    old_state: HealthStateEnum
    new_state: HealthStateEnum
    reason: str
    changed_at_utc: datetime

    @field_validator("changed_at_utc", mode="before")
    @classmethod
    def _validate_changed_utc(cls, v: datetime | str) -> datetime:
        return _ensure_utc(v)


class ContributingSignal(BaseModel):
    signal_name: str
    source_id: str
    baseline_value: float
    observed_value: float
    deviation_score: float
    event_time: datetime

    @field_validator("event_time", mode="before")
    @classmethod
    def _validate_signal_time_utc(cls, v: datetime | str) -> datetime:
        return _ensure_utc(v)


class ExplainableAnomaly(BaseModel):
    anomaly_id: str
    tenant_id: str
    source_id: str
    why_flagged: str
    contributing_signals: list[ContributingSignal]
    baseline_vs_actual: dict[str, dict[str, float]]
    confidence: float = Field(..., ge=0.0, le=1.0)
    detected_at_utc: datetime

    @field_validator("detected_at_utc", mode="before")
    @classmethod
    def _validate_detected_utc(cls, v: datetime | str) -> datetime:
        return _ensure_utc(v)


class CorrelatedIncident(BaseModel):
    incident_id: str
    tenant_id: str
    region: str
    affected_sources: list[str]
    raw_alert_count: int = Field(..., ge=1)
    severity: SeverityEnum
    why_flagged: str
    contributing_signals: list[ContributingSignal]
    baseline_vs_actual: dict[str, dict[str, float]]
    confidence: float = Field(..., ge=0.0, le=1.0)
    recommended_action: str
    reasoning_path: list[str]
    created_at_utc: datetime
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"] = "OPEN"

    @field_validator("created_at_utc", mode="before")
    @classmethod
    def _validate_created_utc(cls, v: datetime | str) -> datetime:
        return _ensure_utc(v)


class RemediationAuditEntry(BaseModel):
    timestamp_utc: datetime
    actor: str
    action: Literal["PROPOSED", "APPROVED", "SIMULATED", "ROLLED_BACK", "REJECTED"]
    details: str

    @field_validator("timestamp_utc", mode="before")
    @classmethod
    def _validate_audit_ts_utc(cls, v: datetime | str) -> datetime:
        return _ensure_utc(v)


class RemediationAction(BaseModel):
    remediation_id: str
    incident_id: str
    tenant_id: str
    proposed_action: str
    policy_check_passed: bool
    policy_notes: str
    approval_status: Literal["PENDING", "APPROVED", "SIMULATED", "ROLLED_BACK"] = "PENDING"
    approved_by: str | None = None
    rollback_plan: str
    audit_trail: list[RemediationAuditEntry] = Field(default_factory=list)