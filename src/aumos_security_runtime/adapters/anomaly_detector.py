"""Statistical anomaly detection adapter for security scan patterns.

Computes rolling baseline statistics per tenant and detects anomalous
spikes in injection attempts, PII exposure rates, and overall scan volumes.
Uses z-score analysis against stored SecAnomalyBaseline records.

Gap Coverage: GAP-228 (Runtime Anomaly Detection)
"""

import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Metrics tracked per tenant
_TRACKED_METRICS = [
    "scans_per_minute",
    "injection_rate",
    "pii_rate",
    "block_rate",
]


@dataclass
class AnomalySignal:
    """Result of an anomaly detection check for a single metric.

    Attributes:
        metric_name: Name of the evaluated metric.
        current_value: The observed value for this check window.
        baseline_mean: Rolling mean from the stored baseline.
        baseline_stddev: Rolling standard deviation from the baseline.
        z_score: How many standard deviations above mean the current value is.
        is_anomaly: True if z_score exceeds the configured threshold.
        severity: Severity level if anomaly detected (warning/critical).
    """

    metric_name: str
    current_value: float
    baseline_mean: float
    baseline_stddev: float
    z_score: float
    is_anomaly: bool
    severity: str


@dataclass
class AnomalyReport:
    """Aggregated anomaly detection report for a tenant check run.

    Attributes:
        tenant_id: The tenant evaluated.
        has_anomalies: True if any metric triggered an anomaly signal.
        signals: Individual AnomalySignal per metric checked.
        check_latency_ms: Time taken to run the detection check.
    """

    tenant_id: uuid.UUID
    has_anomalies: bool
    signals: list[AnomalySignal]
    check_latency_ms: float


class SecurityAnomalyDetector:
    """Statistical anomaly detector for per-tenant security scan behaviour.

    Compares current scan metric rates against stored rolling baselines.
    Uses z-score analysis: current_value > mean + (stddev * threshold_multiplier)
    triggers an anomaly signal.

    Designed to run on a background schedule (e.g., every 60 seconds) rather
    than on the hot-path scan requests.

    Args:
        baseline_repository: Repository for reading/writing SecAnomalyBaseline records.
        warn_z_score: Z-score above which a warning is issued (default: 2.5).
        critical_z_score: Z-score above which a critical alert is issued (default: 4.0).
        min_sample_count: Minimum samples before baselines are trusted (default: 100).
    """

    def __init__(
        self,
        baseline_repository: Any,
        warn_z_score: float = 2.5,
        critical_z_score: float = 4.0,
        min_sample_count: int = 100,
    ) -> None:
        """Initialize the anomaly detector.

        Args:
            baseline_repository: Repository implementing read/write for baselines.
            warn_z_score: Warning threshold as z-score.
            critical_z_score: Critical threshold as z-score.
            min_sample_count: Baseline is unreliable below this sample count.
        """
        self._baseline_repo = baseline_repository
        self._warn_z_score = warn_z_score
        self._critical_z_score = critical_z_score
        self._min_sample_count = min_sample_count

    async def check_tenant(
        self,
        tenant_id: uuid.UUID,
        current_metrics: dict[str, float],
    ) -> AnomalyReport:
        """Evaluate current metrics against stored baselines for a tenant.

        Args:
            tenant_id: The tenant to evaluate.
            current_metrics: Dict mapping metric_name to current observed value.
                Expected keys: scans_per_minute, injection_rate, pii_rate, block_rate.

        Returns:
            AnomalyReport with signals for each evaluated metric.
        """
        start_time = time.perf_counter()
        signals: list[AnomalySignal] = []

        for metric_name, current_value in current_metrics.items():
            baseline = await self._get_baseline(tenant_id, metric_name)

            if baseline is None or baseline.get("sample_count", 0) < self._min_sample_count:
                logger.debug(
                    "Skipping anomaly check — insufficient baseline samples",
                    tenant_id=str(tenant_id),
                    metric_name=metric_name,
                    sample_count=baseline.get("sample_count", 0) if baseline else 0,
                )
                continue

            mean = baseline["mean_value"]
            stddev = baseline["stddev_value"]

            if stddev == 0.0:
                # No variance in baseline — any non-zero deviation is suspicious
                z_score = float("inf") if current_value > mean else 0.0
            else:
                z_score = (current_value - mean) / stddev

            threshold_multiplier = baseline.get("anomaly_threshold_multiplier", 3.0)

            is_anomaly = z_score > threshold_multiplier
            severity = "none"
            if z_score >= self._critical_z_score:
                severity = "critical"
                is_anomaly = True
            elif z_score >= self._warn_z_score:
                severity = "warning"
                is_anomaly = True

            signal = AnomalySignal(
                metric_name=metric_name,
                current_value=current_value,
                baseline_mean=mean,
                baseline_stddev=stddev,
                z_score=round(z_score, 3),
                is_anomaly=is_anomaly,
                severity=severity,
            )
            signals.append(signal)

            if is_anomaly:
                logger.warning(
                    "Security anomaly detected",
                    tenant_id=str(tenant_id),
                    metric_name=metric_name,
                    current_value=current_value,
                    baseline_mean=mean,
                    z_score=round(z_score, 3),
                    severity=severity,
                )

        check_latency_ms = (time.perf_counter() - start_time) * 1000
        has_anomalies = any(s.is_anomaly for s in signals)

        logger.info(
            "Anomaly detection check complete",
            tenant_id=str(tenant_id),
            metrics_checked=len(signals),
            anomalies_detected=sum(1 for s in signals if s.is_anomaly),
            check_latency_ms=round(check_latency_ms, 2),
        )

        return AnomalyReport(
            tenant_id=tenant_id,
            has_anomalies=has_anomalies,
            signals=signals,
            check_latency_ms=check_latency_ms,
        )

    async def update_baseline(
        self,
        tenant_id: uuid.UUID,
        metric_name: str,
        new_value: float,
    ) -> None:
        """Incrementally update a baseline with a new observation.

        Uses Welford's online algorithm for numerically stable mean/variance
        computation without storing all historical values.

        Args:
            tenant_id: The tenant whose baseline to update.
            metric_name: The metric being updated.
            new_value: The new observed value to incorporate.
        """
        baseline = await self._get_baseline(tenant_id, metric_name)

        if baseline is None:
            # First observation — initialise baseline
            await self._create_baseline(
                tenant_id=tenant_id,
                metric_name=metric_name,
                mean=new_value,
                stddev=0.0,
                sample_count=1,
            )
            return

        n = baseline.get("sample_count", 0) + 1
        old_mean = baseline["mean_value"]
        old_m2 = (baseline["stddev_value"] ** 2) * max(baseline.get("sample_count", 1) - 1, 1)

        # Welford's online update
        delta = new_value - old_mean
        new_mean = old_mean + delta / n
        delta2 = new_value - new_mean
        new_m2 = old_m2 + delta * delta2
        new_variance = new_m2 / max(n - 1, 1)
        new_stddev = new_variance ** 0.5

        await self._update_baseline(
            tenant_id=tenant_id,
            metric_name=metric_name,
            mean=new_mean,
            stddev=new_stddev,
            sample_count=n,
        )

    async def _get_baseline(
        self,
        tenant_id: uuid.UUID,
        metric_name: str,
    ) -> dict[str, Any] | None:
        """Retrieve baseline record from repository.

        Args:
            tenant_id: The tenant to look up.
            metric_name: The metric identifier.

        Returns:
            Baseline dict or None if not found.
        """
        try:
            return await self._baseline_repo.get_baseline(
                tenant_id=tenant_id,
                metric_name=metric_name,
            )
        except Exception as exc:
            logger.error(
                "Failed to retrieve anomaly baseline",
                tenant_id=str(tenant_id),
                metric_name=metric_name,
                error=str(exc),
            )
            return None

    async def _create_baseline(
        self,
        tenant_id: uuid.UUID,
        metric_name: str,
        mean: float,
        stddev: float,
        sample_count: int,
    ) -> None:
        """Create a new baseline record in the repository.

        Args:
            tenant_id: The owning tenant.
            metric_name: The metric identifier.
            mean: Initial mean value.
            stddev: Initial standard deviation.
            sample_count: Initial sample count.
        """
        try:
            await self._baseline_repo.create_baseline(
                tenant_id=tenant_id,
                metric_name=metric_name,
                mean_value=mean,
                stddev_value=stddev,
                sample_count=sample_count,
            )
        except Exception as exc:
            logger.error(
                "Failed to create anomaly baseline",
                tenant_id=str(tenant_id),
                metric_name=metric_name,
                error=str(exc),
            )

    async def _update_baseline(
        self,
        tenant_id: uuid.UUID,
        metric_name: str,
        mean: float,
        stddev: float,
        sample_count: int,
    ) -> None:
        """Update an existing baseline record in the repository.

        Args:
            tenant_id: The owning tenant.
            metric_name: The metric identifier.
            mean: New rolling mean.
            stddev: New rolling standard deviation.
            sample_count: Updated total sample count.
        """
        try:
            await self._baseline_repo.update_baseline(
                tenant_id=tenant_id,
                metric_name=metric_name,
                mean_value=mean,
                stddev_value=stddev,
                sample_count=sample_count,
            )
        except Exception as exc:
            logger.error(
                "Failed to update anomaly baseline",
                tenant_id=str(tenant_id),
                metric_name=metric_name,
                error=str(exc),
            )


__all__ = [
    "AnomalySignal",
    "AnomalyReport",
    "SecurityAnomalyDetector",
]
