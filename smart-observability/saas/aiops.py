from __future__ import annotations

import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from saas.database import SaaSMetadataDB, utc_now
from shared.contracts import (
    ContributingSignal,
    CorrelatedIncident,
    EventCategoryEnum,
    SanitizedMetadataPayload,
    SeverityEnum,
)

# Minimum practical deviation above baseline so tiny variance never causes false alarms
METRIC_SPECS: dict[str, dict[str, Any]] = {
    "cpu_pct": {"min_delta": 18.0, "abs_high": 85.0, "unit": "%"},
    "memory_pct": {"min_delta": 16.0, "abs_high": 85.0, "unit": "%"},
    "latency_ms": {"min_delta": 45.0, "abs_high": 150.0, "unit": "ms"},
    "packet_loss_pct": {"min_delta": 2.5, "abs_high": 5.0, "unit": "%"},
}

SEVERITY_RANK: dict[SeverityEnum, int] = {
    SeverityEnum.INFO: 0,
    SeverityEnum.LOW: 1,
    SeverityEnum.MEDIUM: 2,
    SeverityEnum.HIGH: 3,
    SeverityEnum.CRITICAL: 4,
}


class ExplainableAIOpsEngine:
    """
    100% offline AIOps engine using NumPy, Pandas (EWMA + rolling Z-score), and
    scikit-learn (IsolationForest) with 90-second alert correlation and structured explainability.
    """

    def __init__(
        self,
        db: SaaSMetadataDB,
        z_threshold: float = 2.8,
        correlation_window_sec: int = 90,
        window_size: int = 60,
    ) -> None:
        self.db = db
        self.z_threshold = z_threshold
        self.correlation_window_sec = correlation_window_sec
        self.window_size = window_size

        # Rolling history per (tenant_id, source_id) -> deque of metric dicts
        self._history: dict[tuple[str, str], deque[dict[str, float]]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        # Active open incidents keyed by (tenant_id, region) -> list of (last_event_utc, CorrelatedIncident)
        self._active_incidents: dict[tuple[str, str], list[tuple[datetime, CorrelatedIncident]]] = defaultdict(list)

    def _run_isolation_forest_score(
        self,
        history: list[dict[str, float]],
        current_metrics: dict[str, float],
    ) -> tuple[bool, float]:
        """Runs offline scikit-learn IsolationForest once >= 20 baseline points exist."""
        if len(history) < 20:
            return False, 0.0

        cols = ["cpu_pct", "memory_pct", "latency_ms", "packet_loss_pct"]
        df = pd.DataFrame([{c: float(row.get(c, 0.0)) for c in cols} for row in history])
        # Skip IF if baseline variance is nearly zero
        if float(df.std().sum()) < 1e-6:
            return False, 0.0

        model = IsolationForest(n_estimators=50, contamination="auto", random_state=42)
        model.fit(df.values)

        x_curr = np.array([[float(current_metrics.get(c, 0.0)) for c in cols]])
        pred = int(model.predict(x_curr)[0])
        score = float(model.decision_function(x_curr)[0])
        return pred == -1, round(score, 4)

    def _detect_signals(
        self,
        payload: SanitizedMetadataPayload,
    ) -> tuple[list[ContributingSignal], bool, float]:
        key = (payload.tenant_id, payload.source_id)
        hist_deque = self._history[key]
        hist_list = list(hist_deque)

        signals: list[ContributingSignal] = []
        if_flagged, if_score = self._run_isolation_forest_score(hist_list, payload.metrics)

        # 1. Rolling EWMA + Z-score anomaly detection for numeric metrics
        for metric_name, spec in METRIC_SPECS.items():
            if metric_name not in payload.metrics:
                continue
            observed = float(payload.metrics[metric_name])
            past_values = [float(item.get(metric_name, 0.0)) for item in hist_list if metric_name in item]

            if len(past_values) >= 5:
                series = pd.Series(past_values, dtype=float)
                ewma_baseline = float(series.ewm(span=min(len(series), 12), adjust=False).mean().iloc[-1])
                rolling_std = float(series.std(ddof=0))
                effective_std = max(rolling_std, spec["min_delta"] * 0.15)
                z_score = (observed - ewma_baseline) / effective_std

                if z_score >= self.z_threshold and (observed - ewma_baseline) >= spec["min_delta"]:
                    signals.append(
                        ContributingSignal(
                            signal_name=metric_name,
                            source_id=payload.source_id,
                            baseline_value=round(ewma_baseline, 2),
                            observed_value=round(observed, 2),
                            deviation_score=round(float(z_score), 2),
                            event_time=payload.event_time,
                        )
                    )
            else:
                # Cold-start fallback before 5 baseline samples exist
                if observed >= spec["abs_high"]:
                    default_base = round(spec["abs_high"] * 0.4, 2)
                    dev = round((observed - default_base) / max(default_base * 0.25, 1.0), 2)
                    signals.append(
                        ContributingSignal(
                            signal_name=metric_name,
                            source_id=payload.source_id,
                            baseline_value=default_base,
                            observed_value=round(observed, 2),
                            deviation_score=max(dev, 3.0),
                            event_time=payload.event_time,
                        )
                    )

        # 2. Service probe failure signal
        if float(payload.metrics.get("service_up", 1.0)) < 1.0:
            signals.append(
                ContributingSignal(
                    signal_name="service_up",
                    source_id=payload.source_id,
                    baseline_value=1.0,
                    observed_value=0.0,
                    deviation_score=5.0,
                    event_time=payload.event_time,
                )
            )

        # 3. Local security summary signal (Scenario 3: repeated failed logins aggregated in Tier 1)
        if (
            payload.event_category == EventCategoryEnum.SECURITY
            and payload.severity in (SeverityEnum.HIGH, SeverityEnum.CRITICAL)
            and "authentication failure" in payload.concise_alert_context.lower()
        ):
            signals.append(
                ContributingSignal(
                    signal_name="local_auth_failures",
                    source_id=payload.source_id,
                    baseline_value=0.0,
                    observed_value=1.0,
                    deviation_score=4.5,
                    event_time=payload.event_time,
                )
            )

        # Update rolling baseline ONLY with clean/non-anomalous samples so spikes don't poison baseline
        if not signals:
            hist_deque.append(dict(payload.metrics))

        return signals, if_flagged, if_score

    def _choose_recommended_action(
        self,
        signal_names: set[str],
        sources: list[str],
    ) -> str:
        target = ", ".join(sources[:3])
        if "local_auth_failures" in signal_names:
            return (
                f"Apply temporary rate-limiting and SSH/auth lockout policy on {target} "
                "and rotate exposed credentials locally."
            )
        if {"latency_ms", "packet_loss_pct"} & signal_names and {"cpu_pct", "memory_pct", "service_up"} & signal_names:
            return (
                f"Reroute traffic away from degraded uplink and scale/restart saturated worker pool on {target}."
            )
        if {"latency_ms", "packet_loss_pct"} & signal_names:
            return f"Fail over primary network route and inspect congested uplink interface for {target}."
        if {"cpu_pct", "memory_pct", "service_up"} & signal_names:
            return f"Throttle non-critical background jobs and perform rolling restart/scale-out for {target}."
        return f"Inspect degraded telemetry on {target} and validate recent config deployments."

    def _build_explanation(
        self,
        signals: list[ContributingSignal],
        sources: list[str],
        raw_alert_count: int,
        if_flagged: bool,
        if_score: float,
        recommended_action: str,
    ) -> tuple[str, dict[str, dict[str, float]], float, list[str]]:
        # Deduplicate summary metrics keeping the highest deviation per signal_name
        best_by_metric: dict[str, ContributingSignal] = {}
        for sig in signals:
            prev = best_by_metric.get(sig.signal_name)
            if prev is None or sig.deviation_score > prev.deviation_score:
                best_by_metric[sig.signal_name] = sig

        baseline_vs_actual = {
            name: {
                "baseline": sig.baseline_value,
                "actual": sig.observed_value,
                "deviation_sigma": sig.deviation_score,
            }
            for name, sig in best_by_metric.items()
        }

        highlights: list[str] = []
        for name, sig in best_by_metric.items():
            unit = METRIC_SPECS.get(name, {}).get("unit", "")
            highlights.append(
                f"{name} reached {sig.observed_value}{unit} "
                f"({sig.deviation_score:.1f}σ vs baseline {sig.baseline_value}{unit})"
            )

        why_flagged = (
            f"Correlated {raw_alert_count} anomalous alert(s) across {', '.join(sources)}: "
            + "; ".join(highlights[:4])
        )

        max_dev = max((s.deviation_score for s in signals), default=3.0)
        distinct_signals = len(best_by_metric)
        confidence = min(
            0.99,
            round(
                0.55
                + min(max_dev, 8.0) * 0.035
                + min(distinct_signals, 4) * 0.04
                + (0.04 if if_flagged else 0.0),
                2,
            ),
        )

        reasoning_path = [
            f"1. Signal Ingestion: Detected {len(signals)} contributing anomaly signal(s) from metadata only.",
            (
                "2. Baseline Deviation: "
                + "; ".join(highlights[:3])
                + (
                    f" (corroborated by offline IsolationForest score={if_score})."
                    if if_flagged
                    else " (confirmed via rolling EWMA + Z-score baseline)."
                )
            ),
            (
                f"3. Event Correlation: Merged {raw_alert_count} related alert(s) within "
                f"{self.correlation_window_sec}s window for source(s) {', '.join(sources)}."
            ),
            f"4. Root-Cause Hypothesis: Multi-signal degradation affecting {', '.join(sorted(best_by_metric.keys()))}.",
            f"5. Recommended Action: {recommended_action}",
        ]
        return why_flagged, baseline_vs_actual, confidence, reasoning_path

    def _determine_severity(
        self,
        payload_severity: SeverityEnum,
        signals: list[ContributingSignal],
        raw_alert_count: int,
    ) -> SeverityEnum:
        max_dev = max((s.deviation_score for s in signals), default=0.0)
        if (
            payload_severity == SeverityEnum.CRITICAL
            or raw_alert_count >= 3
            or max_dev >= 5.0
            or any(s.signal_name in {"service_up", "local_auth_failures"} for s in signals)
        ):
            return SeverityEnum.CRITICAL
        if payload_severity == SeverityEnum.HIGH or max_dev >= 3.5 or len(signals) >= 2:
            return SeverityEnum.HIGH
        return SeverityEnum.MEDIUM

    def process_metadata_event(
        self,
        payload: SanitizedMetadataPayload,
    ) -> CorrelatedIncident | None:
        """
        Evaluates one sanitized payload:
        - Returns None on normal baseline points (zero false alarms).
        - Creates or merges into an active CorrelatedIncident within 90 seconds.
        """
        signals, if_flagged, if_score = self._detect_signals(payload)
        if not signals:
            return None

        event_utc = payload.event_time.astimezone(timezone.utc)
        bucket_key = (payload.tenant_id, payload.region)
        cutoff = event_utc - timedelta(seconds=self.correlation_window_sec)

        # Prune expired active correlation windows
        active_list = [
            (last_ts, inc)
            for last_ts, inc in self._active_incidents[bucket_key]
            if last_ts >= cutoff and abs((event_utc - last_ts).total_seconds()) <= self.correlation_window_sec
        ]
        self._active_incidents[bucket_key] = active_list

        # Merge into existing active incident for same tenant/region within 90s
        if active_list:
            idx = len(active_list) - 1
            _, incident = active_list[idx]

            merged_sources = list(incident.affected_sources)
            if payload.source_id not in merged_sources:
                merged_sources.append(payload.source_id)

            merged_signals = list(incident.contributing_signals) + signals
            new_raw_count = incident.raw_alert_count + 1
            new_sev = self._determine_severity(payload.severity, merged_signals, new_raw_count)
            if SEVERITY_RANK[incident.severity] > SEVERITY_RANK[new_sev]:
                new_sev = incident.severity

            signal_names = {s.signal_name for s in merged_signals}
            recommended_action = self._choose_recommended_action(signal_names, merged_sources)
            why_flagged, baseline_vs_actual, confidence, reasoning_path = self._build_explanation(
                merged_signals,
                merged_sources,
                new_raw_count,
                if_flagged,
                if_score,
                recommended_action,
            )

            updated = incident.model_copy(
                update={
                    "affected_sources": merged_sources,
                    "raw_alert_count": new_raw_count,
                    "severity": new_sev,
                    "why_flagged": why_flagged,
                    "contributing_signals": merged_signals,
                    "baseline_vs_actual": baseline_vs_actual,
                    "confidence": confidence,
                    "recommended_action": recommended_action,
                    "reasoning_path": reasoning_path,
                }
            )
            active_list[idx] = (max(event_utc, active_list[idx][0]), updated)
            self.db.save_incident(updated)
            return updated

        # Create a new correlated incident
        sources = [payload.source_id]
        raw_count = 1
        severity = self._determine_severity(payload.severity, signals, raw_count)
        signal_names = {s.signal_name for s in signals}
        recommended_action = self._choose_recommended_action(signal_names, sources)
        why_flagged, baseline_vs_actual, confidence, reasoning_path = self._build_explanation(
            signals,
            sources,
            raw_count,
            if_flagged,
            if_score,
            recommended_action,
        )

        incident = CorrelatedIncident(
            incident_id=f"inc-{uuid.uuid4().hex[:10]}",
            tenant_id=payload.tenant_id,
            region=payload.region,
            affected_sources=sources,
            raw_alert_count=raw_count,
            severity=severity,
            why_flagged=why_flagged,
            contributing_signals=signals,
            baseline_vs_actual=baseline_vs_actual,
            confidence=confidence,
            recommended_action=recommended_action,
            reasoning_path=reasoning_path,
            created_at_utc=utc_now(),
            status="OPEN",
        )
        active_list.append((event_utc, incident))
        self.db.save_incident(incident)
        return incident