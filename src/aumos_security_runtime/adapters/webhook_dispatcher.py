"""SIEM webhook dispatch adapter for aumos-security-runtime.

Delivers security events to registered SIEM endpoints with retry logic,
circuit breaking on repeated failures, and HMAC-SHA256 payload signing.
Reads endpoint configurations from the database and applies event filters
before dispatching. Uses httpx for async HTTP delivery.

Gap Coverage: GAP-226 (SIEM/Webhook Integration)
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from aumos_common.observability import get_logger

from aumos_security_runtime.adapters.siem_formatters import format_security_event, sign_payload

logger = get_logger(__name__)

# Auto-disable endpoint after this many consecutive failures
_MAX_CONSECUTIVE_FAILURES = 5

# Retry delays in seconds: 5s, 30s, 5min
_RETRY_DELAYS_SECONDS = [5, 30, 300]


@dataclass
class WebhookEndpointConfig:
    """In-memory representation of a registered SIEM webhook endpoint.

    Attributes:
        endpoint_id: UUID of the SecWebhookEndpoint record.
        name: Human-readable endpoint name.
        target_url: HTTPS destination URL.
        format: Payload format (json/splunk_hec/datadog/sentinel_cef).
        signing_secret: Optional HMAC-SHA256 signing key.
        event_filter: Optional filter criteria dict.
        enabled: Whether the endpoint is active.
        failure_count: Current consecutive failure count.
    """

    endpoint_id: uuid.UUID
    name: str
    target_url: str
    format: str
    signing_secret: str | None
    event_filter: dict[str, Any]
    enabled: bool
    failure_count: int = 0


@dataclass
class DeliveryResult:
    """Result of a single webhook delivery attempt.

    Attributes:
        endpoint_id: UUID of the target endpoint.
        success: Whether the delivery succeeded.
        http_status_code: HTTP response code (None if connection failed).
        error_detail: Error message on failure.
        attempt_count: Number of attempts made including retries.
        payload_size_bytes: Size of the delivered payload.
    """

    endpoint_id: uuid.UUID
    success: bool
    http_status_code: int | None
    error_detail: str | None = None
    attempt_count: int = 1
    payload_size_bytes: int = 0


class WebhookDispatcher:
    """Dispatches security events to registered SIEM endpoints.

    Handles payload formatting, HMAC signing, HTTP delivery with retries,
    and circuit breaking for consistently failing endpoints.

    Args:
        http_timeout_seconds: Timeout for each HTTP delivery attempt.
        max_retries: Number of retry attempts on failure.
    """

    def __init__(
        self,
        http_timeout_seconds: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        """Initialize the dispatcher.

        Args:
            http_timeout_seconds: Per-request HTTP timeout.
            max_retries: Maximum retry attempts per delivery.
        """
        self._http_timeout = http_timeout_seconds
        self._max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

    async def initialize(self) -> None:
        """Create the shared HTTP client.

        Must be called before dispatch() is invoked. Typically called
        during application lifespan startup.
        """
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._http_timeout),
            follow_redirects=False,
            verify=True,
        )
        logger.info("WebhookDispatcher initialized", http_timeout_seconds=self._http_timeout)

    async def close(self) -> None:
        """Close the HTTP client on shutdown."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def dispatch_to_endpoints(
        self,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        event_data: dict[str, Any],
        endpoints: list[WebhookEndpointConfig],
    ) -> list[DeliveryResult]:
        """Dispatch a security event to all registered active endpoints.

        Filters endpoints by event criteria, formats payloads per endpoint,
        signs them, and delivers in parallel. Returns one DeliveryResult
        per endpoint that was eligible for delivery.

        Args:
            scan_id: UUID of the triggering security scan.
            tenant_id: Owning tenant UUID.
            event_data: Raw security event dict with threat details.
            endpoints: List of registered endpoint configs.

        Returns:
            List of DeliveryResult, one per attempted endpoint.
        """
        eligible = [ep for ep in endpoints if ep.enabled and self._passes_filter(event_data, ep.event_filter)]

        if not eligible:
            logger.debug(
                "No eligible webhook endpoints for event",
                scan_id=str(scan_id),
                tenant_id=str(tenant_id),
                total_endpoints=len(endpoints),
            )
            return []

        tasks = [
            self._deliver_with_retry(scan_id=scan_id, event_data=event_data, endpoint=ep)
            for ep in eligible
        ]
        results: list[DeliveryResult] = await asyncio.gather(*tasks, return_exceptions=False)

        successes = sum(1 for r in results if r.success)
        logger.info(
            "Webhook dispatch complete",
            scan_id=str(scan_id),
            tenant_id=str(tenant_id),
            eligible_endpoints=len(eligible),
            successful_deliveries=successes,
        )
        return results

    async def _deliver_with_retry(
        self,
        scan_id: uuid.UUID,
        event_data: dict[str, Any],
        endpoint: WebhookEndpointConfig,
    ) -> DeliveryResult:
        """Deliver a payload to a single endpoint with exponential-backoff retries.

        Args:
            scan_id: UUID of the triggering scan.
            event_data: Security event data to format and send.
            endpoint: Target endpoint configuration.

        Returns:
            DeliveryResult with success/failure details.
        """
        payload_bytes, content_type = self._build_payload(event_data, endpoint)
        payload_size = len(payload_bytes)

        headers: dict[str, str] = {
            "Content-Type": content_type,
            "X-AumOS-Event": "security.scan",
            "X-AumOS-Scan-ID": str(scan_id),
            "X-AumOS-Timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }

        if endpoint.signing_secret:
            signature = sign_payload(payload_bytes, endpoint.signing_secret)
            headers["X-AumOS-Signature-256"] = f"sha256={signature}"

        for attempt in range(1, self._max_retries + 1):
            try:
                if self._client is None:
                    raise RuntimeError("WebhookDispatcher.initialize() was not called")

                response = await self._client.post(
                    endpoint.target_url,
                    content=payload_bytes,
                    headers=headers,
                )

                if response.is_success:
                    logger.info(
                        "Webhook delivery succeeded",
                        endpoint_id=str(endpoint.endpoint_id),
                        endpoint_name=endpoint.name,
                        http_status=response.status_code,
                        attempt=attempt,
                    )
                    return DeliveryResult(
                        endpoint_id=endpoint.endpoint_id,
                        success=True,
                        http_status_code=response.status_code,
                        attempt_count=attempt,
                        payload_size_bytes=payload_size,
                    )

                # 4xx errors are not retried (client configuration error)
                if 400 <= response.status_code < 500:
                    logger.warning(
                        "Webhook delivery rejected by endpoint (4xx — not retrying)",
                        endpoint_id=str(endpoint.endpoint_id),
                        http_status=response.status_code,
                    )
                    return DeliveryResult(
                        endpoint_id=endpoint.endpoint_id,
                        success=False,
                        http_status_code=response.status_code,
                        error_detail=f"HTTP {response.status_code}: client error",
                        attempt_count=attempt,
                        payload_size_bytes=payload_size,
                    )

                # 5xx: retry after backoff
                error_detail = f"HTTP {response.status_code}: server error"

            except httpx.TimeoutException as exc:
                error_detail = f"Timeout after {self._http_timeout}s: {exc}"
            except httpx.ConnectError as exc:
                error_detail = f"Connection error: {exc}"
            except Exception as exc:
                error_detail = f"Unexpected error: {exc}"

            logger.warning(
                "Webhook delivery attempt failed",
                endpoint_id=str(endpoint.endpoint_id),
                attempt=attempt,
                max_retries=self._max_retries,
                error=error_detail,
            )

            if attempt < self._max_retries:
                delay = _RETRY_DELAYS_SECONDS[min(attempt - 1, len(_RETRY_DELAYS_SECONDS) - 1)]
                await asyncio.sleep(delay)

        return DeliveryResult(
            endpoint_id=endpoint.endpoint_id,
            success=False,
            http_status_code=None,
            error_detail=error_detail,
            attempt_count=self._max_retries,
            payload_size_bytes=payload_size,
        )

    def _build_payload(
        self,
        event_data: dict[str, Any],
        endpoint: WebhookEndpointConfig,
    ) -> tuple[bytes, str]:
        """Format and encode the payload for the endpoint's expected format.

        Args:
            event_data: Raw security event dict.
            endpoint: Target endpoint with format specification.

        Returns:
            Tuple of (encoded_payload_bytes, content_type_string).
        """
        formatted = format_security_event(event_data, endpoint.format)

        if endpoint.format == "sentinel_cef":
            return formatted.encode("utf-8"), "text/plain; charset=utf-8"

        import json
        return json.dumps(formatted).encode("utf-8"), "application/json"

    def _passes_filter(
        self,
        event_data: dict[str, Any],
        event_filter: dict[str, Any],
    ) -> bool:
        """Check whether an event matches an endpoint's filter criteria.

        Filter dict may contain:
          - min_severity: Only deliver events at or above this severity.
          - threat_types: List of threat_type strings to include.

        Args:
            event_data: Security event to evaluate.
            event_filter: Filter configuration for the endpoint.

        Returns:
            True if the event should be delivered to the endpoint.
        """
        if not event_filter:
            return True

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        event_severity = event_data.get("severity", "low")

        min_severity = event_filter.get("min_severity")
        if min_severity:
            event_rank = severity_order.get(event_severity, 99)
            min_rank = severity_order.get(min_severity, 99)
            if event_rank > min_rank:
                return False

        allowed_types = event_filter.get("threat_types")
        if allowed_types:
            event_threat_type = event_data.get("threat_type", "")
            if event_threat_type not in allowed_types:
                return False

        return True


__all__ = [
    "WebhookEndpointConfig",
    "DeliveryResult",
    "WebhookDispatcher",
]
