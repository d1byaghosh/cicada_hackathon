from __future__ import annotations

import hashlib
import hmac
import math
import re
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from collector.config import settings
from collector.local_db import LocalCollectorDB
from shared.contracts import (
    EgressProofRecord,
    EventCategoryEnum,
    HealthStateEnum,
    RawTelemetryEvent,
    SanitizedMetadataPayload,
    SeverityEnum,
)

# Compiled secret detection rules (order matters: specific patterns before generic ones)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("PRIVATE_KEY_HEADER", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("CONNECTION_STRING", re.compile(r"(?i)\b(?:postgres|mysql|mongodb|redis)://[^\s'\"`]+")),
    ("API_KEY", re.compile(r"(?i)\b(?:sk_live|pk_live|api[_-]?key|token|secret)\s*[:=]\s*[^\s,;\"']+")),
    ("PASSWORD", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;\"']+")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("IPV4_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

_HIGH_ENTROPY_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-+/=]{24,}\b")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ch in text:
        freq[ch] += 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class PrivacyEngine:
    """
    Enforces the Tier 1 trust boundary:
    Collect -> Filter/Redact -> Pseudonymize -> Aggregate Locally -> Strict Allow-List Projection.
    """

    def __init__(
        self,
        db: LocalCollectorDB,
        hmac_salt: str | None = None,
        auth_window_sec: int | None = None,
        auth_threshold: int | None = None,
    ) -> None:
        self.db = db
        self._hmac_key = (hmac_salt or settings.hmac_secret_salt).encode("utf-8")
        self.auth_window_sec = auth_window_sec or settings.auth_failure_window_sec
        self.auth_threshold = auth_threshold or settings.auth_failure_threshold
        self._failed_login_windows: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)

    def pseudonymize_source(self, tenant_id: str, hostname: str, host_ip: str) -> str:
        """Deterministically maps real host/IP to a pseudonymous source_id without leaking either."""
        raw_identity = f"{tenant_id}|{hostname.lower()}|{host_ip}".encode("utf-8")
        digest = hmac.new(self._hmac_key, raw_identity, hashlib.sha256).hexdigest()[:10]
        return f"src-{digest}"

    def scrub_text(self, text: str) -> tuple[str, list[str], list[str]]:
        """
        Scrubs secrets using regex + Shannon entropy.
        Returns: (redacted_text, secret_types_found, matched_raw_secrets)
        """
        redacted = text
        secret_types: list[str] = []
        matched_raw: list[str] = []

        for secret_type, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(redacted):
                raw_val = match.group(0)
                if secret_type not in secret_types:
                    secret_types.append(secret_type)
                # Track sensitive value part (skip harmless key labels where applicable)
                if "=" in raw_val:
                    matched_raw.append(raw_val.split("=", 1)[1].strip())
                elif ":" in raw_val and secret_type != "CONNECTION_STRING":
                    matched_raw.append(raw_val.split(":", 1)[1].strip())
                else:
                    matched_raw.append(raw_val)
            redacted = pattern.sub(f"[REDACTED:{secret_type}]", redacted)

        # Entropy pass for unlabeled secrets
        for match in list(_HIGH_ENTROPY_TOKEN_RE.finditer(redacted)):
            token = match.group(0)
            if token.startswith("REDACTED"):
                continue
            if shannon_entropy(token) >= 4.2:
                if "HIGH_ENTROPY_SECRET" not in secret_types:
                    secret_types.append("HIGH_ENTROPY_SECRET")
                matched_raw.append(token)
                redacted = redacted.replace(token, "[REDACTED:HIGH_ENTROPY_SECRET]")

        return redacted, secret_types, [s for s in matched_raw if len(s) >= 4]

    def _evaluate_local_health(self, event: RawTelemetryEvent) -> HealthStateEnum:
        m = event.metrics
        if (
            m.get("service_up", 1.0) < 1.0
            or m.get("cpu_pct", 0.0) >= 90.0
            or m.get("memory_pct", 0.0) >= 90.0
            or m.get("packet_loss_pct", 0.0) >= 10.0
            or m.get("latency_ms", 0.0) >= 250.0
            or event.severity == SeverityEnum.CRITICAL
        ):
            return HealthStateEnum.POOR
        if (
            m.get("cpu_pct", 0.0) >= 75.0
            or m.get("memory_pct", 0.0) >= 80.0
            or m.get("packet_loss_pct", 0.0) >= 3.0
            or m.get("latency_ms", 0.0) >= 120.0
            or event.severity == SeverityEnum.HIGH
        ):
            return HealthStateEnum.FAIR
        if m.get("cpu_pct", 0.0) >= 55.0 or m.get("latency_ms", 0.0) >= 60.0:
            return HealthStateEnum.GOOD
        return HealthStateEnum.EXCELLENT

    def _is_failed_login(self, event: RawTelemetryEvent) -> bool:
        if getattr(event, "auth_failed", False):
            return True
        lowered = event.raw_log.lower()
        return event.event_category == EventCategoryEnum.SECURITY and (
            "failed password" in lowered
            or "authentication failure" in lowered
            or "failed login" in lowered
        )

    def _record_and_check_auth_burst(
        self,
        tenant_id: str,
        source_id: str,
        event_time: datetime,
    ) -> int | None:
        """
        Maintains a local rolling window of failed logins.
        Returns the aggregated count when threshold is hit (emitting 1 concise signal per burst).
        """
        key = (tenant_id, source_id)
        window = self._failed_login_windows[key]
        cutoff = event_time - timedelta(seconds=self.auth_window_sec)
        while window and window[0] < cutoff:
            window.popleft()
        window.append(event_time)

        if len(window) >= self.auth_threshold and len(window) % self.auth_threshold == 0:
            return len(window)
        return None

    def process_event(
        self,
        raw_event: RawTelemetryEvent,
    ) -> tuple[SanitizedMetadataPayload, EgressProofRecord] | None:
        """
        Processes one RawTelemetryEvent:
        1. Scrubs secrets from raw log & payload for local audit tracking.
        2. Stores raw event strictly in collector_local.db.
        3. Aggregates repeated failed logins locally (returns None for individual raw auth lines).
        4. Projects ONLY allow-listed fields into SanitizedMetadataPayload.
        5. Verifies zero raw secrets exist in outbound JSON and writes EgressProofRecord.
        """
        payload_id = getattr(raw_event, "payload_id", None) or str(uuid.uuid4())
        source_id = self.pseudonymize_source(
            raw_event.tenant_id,
            raw_event.hostname,
            raw_event.host_ip,
        )

        # Scrub raw log and any raw payload strings to catalog all caught secrets
        redacted_preview, secrets_found, matched_raw = self.scrub_text(raw_event.raw_log)
        if raw_event.payload:
            _, payload_secrets, payload_raw = self.scrub_text(str(raw_event.payload))
            for st in payload_secrets:
                if st not in secrets_found:
                    secrets_found.append(st)
            matched_raw.extend(payload_raw)

        # Always keep the raw unredacted telemetry strictly inside Tier 1 local SQLite
        self.db.insert_raw_event(payload_id, raw_event, secrets_found)

        # Local security aggregation for repeated failed logins (Scenario 3)
        concise_context = f"{raw_event.event_category.value.lower()} telemetry normal"
        severity = raw_event.severity
        health_state = self._evaluate_local_health(raw_event)

        if self._is_failed_login(raw_event):
            burst_count = self._record_and_check_auth_burst(
                raw_event.tenant_id,
                source_id,
                raw_event.event_time.astimezone(timezone.utc),
            )
            if burst_count is None:
                # Raw failed login stays strictly local; do not spam Tier 2
                return None
            severity = SeverityEnum.CRITICAL if burst_count >= 10 else SeverityEnum.HIGH
            health_state = HealthStateEnum.POOR if burst_count >= 10 else HealthStateEnum.FAIR
            concise_context = (
                f"Repeated authentication failures detected locally "
                f"(count={burst_count} within {self.auth_window_sec}s)"
            )
        elif secrets_found:
            concise_context = (
                f"Sensitive patterns scrubbed locally ({len(secrets_found)} type(s)); "
                f"category={raw_event.event_category.value.lower()}"
            )
        elif health_state in (HealthStateEnum.FAIR, HealthStateEnum.POOR):
            m = raw_event.metrics
            concise_context = (
                f"Degraded {raw_event.event_category.value.lower()} telemetry "
                f"(cpu={m.get('cpu_pct', 0):.1f}%, mem={m.get('memory_pct', 0):.1f}%, "
                f"lat={m.get('latency_ms', 0):.1f}ms, loss={m.get('packet_loss_pct', 0):.1f}%)"
            )

        # Strict allow-list projection (SanitizedMetadataPayload uses extra="forbid")
        safe_metrics = {
            k: round(float(v), 3)
            for k, v in raw_event.metrics.items()
            if k
            in {
                "cpu_pct",
                "memory_pct",
                "disk_pct",
                "bandwidth_mbps",
                "latency_ms",
                "packet_loss_pct",
                "service_up",
            }
        }

        outbound = SanitizedMetadataPayload(
            payload_id=payload_id,
            tenant_id=raw_event.tenant_id,
            region=raw_event.region,
            collector_id=raw_event.collector_id,
            source_id=source_id,
            event_time=raw_event.event_time.astimezone(timezone.utc),
            source_timezone=raw_event.source_timezone,
            event_category=raw_event.event_category,
            severity=severity,
            health_state=health_state,
            metrics=safe_metrics,
            concise_alert_context=concise_context[:240],
            redaction_count=len(secrets_found),
        )

        # Defense-in-depth egress assertion: ensure zero matched secrets or raw IP leaked
        serialized = outbound.model_dump_json()
        for raw_secret in matched_raw:
            if raw_secret and raw_secret in serialized:
                raise RuntimeError(f"Privacy boundary violation prevented for payload {payload_id}")
        if raw_event.host_ip and raw_event.host_ip not in {"0.0.0.0", "127.0.0.1"} and raw_event.host_ip in serialized:
            raise RuntimeError(f"Host IP leak prevented for payload {payload_id}")

        egress_record = EgressProofRecord(
            payload_id=payload_id,
            raw_preview_redacted_markers=redacted_preview[:300],
            secrets_detected=secrets_found,
            outbound_payload=outbound,
            transmitted_at_utc=datetime.now(timezone.utc),
            delivery_status="SENT",
        )
        # Log exact outbound payload BEFORE network transmission
        self.db.insert_egress_proof(egress_record)
        return outbound, egress_record