"""Kafka event publishing for aumos-security-runtime.

Publishes security events to Kafka topics for:
  - Real-time SIEM integration
  - Security dashboards
  - Downstream alerting and incident response

Events must include tenant_id and correlation_id for traceability.
Topic: security.threats.detected

IMPORTANT: The Kafka publish is fire-and-forget relative to the scan response.
The scan result is returned to the caller immediately; event publishing
happens asynchronously to avoid adding to the <50ms latency budget.
"""

import uuid

from aumos_common.events import EventPublisher, Topics
from aumos_common.observability import get_logger

logger = get_logger(__name__)


class SecurityEventPublisher:
    """Publisher for aumos-security-runtime domain events.

    Wraps EventPublisher with typed methods for each security event type.
    All events are published asynchronously — never block the scan response.

    Args:
        publisher: The underlying EventPublisher from aumos-common.
    """

    def __init__(self, publisher: EventPublisher) -> None:
        """Initialize with the shared event publisher.

        Args:
            publisher: Configured EventPublisher instance.
        """
        self._publisher = publisher

    async def publish_threat_detected(
        self,
        tenant_id: uuid.UUID,
        scan_id: uuid.UUID,
        threat_type: str,
        severity: str,
        confidence: float,
        action_taken: str,
        correlation_id: str,
    ) -> None:
        """Publish a ThreatDetected event to Kafka.

        Called after any scan that detects a threat. Published
        asynchronously to avoid impacting scan latency.

        Args:
            tenant_id: The tenant whose content was scanned.
            scan_id: The scan record UUID.
            threat_type: Category of threat detected.
            severity: Severity level (critical/high/medium/low).
            confidence: Detection confidence score.
            action_taken: Enforcement action applied.
            correlation_id: Request correlation ID for tracing.
        """
        try:
            await self._publisher.publish(
                Topics.SECURITY_THREAT_DETECTED,
                {
                    "tenant_id": str(tenant_id),
                    "scan_id": str(scan_id),
                    "threat_type": threat_type,
                    "severity": severity,
                    "confidence": confidence,
                    "action_taken": action_taken,
                    "correlation_id": correlation_id,
                },
            )
            logger.info(
                "Published ThreatDetected event",
                tenant_id=str(tenant_id),
                scan_id=str(scan_id),
                threat_type=threat_type,
                severity=severity,
            )
        except Exception as exc:
            # Publishing failures must not propagate to the scan response
            logger.error(
                "Failed to publish ThreatDetected event",
                error=str(exc),
                tenant_id=str(tenant_id),
                scan_id=str(scan_id),
            )

    async def publish_scan_complete(
        self,
        tenant_id: uuid.UUID,
        scan_id: uuid.UUID,
        scan_type: str,
        threats_detected: int,
        action_taken: str,
        latency_ms: float,
        correlation_id: str,
    ) -> None:
        """Publish a SecurityScanComplete event to Kafka.

        Published after every scan regardless of whether threats were found.
        Used for metrics aggregation and audit trail.

        Args:
            tenant_id: The tenant whose content was scanned.
            scan_id: The scan record UUID.
            scan_type: Type of scan (input/output/container).
            threats_detected: Number of threats found.
            action_taken: Final enforcement action.
            latency_ms: Total scan latency.
            correlation_id: Request correlation ID for tracing.
        """
        try:
            await self._publisher.publish(
                Topics.SECURITY_SCAN_COMPLETE,
                {
                    "tenant_id": str(tenant_id),
                    "scan_id": str(scan_id),
                    "scan_type": scan_type,
                    "threats_detected": threats_detected,
                    "action_taken": action_taken,
                    "latency_ms": latency_ms,
                    "correlation_id": correlation_id,
                },
            )
            logger.info(
                "Published SecurityScanComplete event",
                tenant_id=str(tenant_id),
                scan_id=str(scan_id),
                scan_type=scan_type,
                latency_ms=round(latency_ms, 2),
            )
        except Exception as exc:
            logger.error(
                "Failed to publish SecurityScanComplete event",
                error=str(exc),
                tenant_id=str(tenant_id),
                scan_id=str(scan_id),
            )
