"""Additional SQLAlchemy ORM models for security runtime gap features.

New models (Gaps #224-233):
    SecJailbreakPattern    — stored jailbreak pattern definitions (GAP-225)
    SecWebhookEndpoint     — SIEM/webhook endpoint registrations (GAP-226)
    SecWebhookDelivery     — delivery attempt records for webhook events (GAP-226)
    SecRateLimitConfig     — per-tenant rate limit configuration (GAP-227)
    SecAnomalyBaseline     — baseline statistics for anomaly detection (GAP-228)
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from aumos_common.database import AumOSModel


class SecJailbreakPattern(AumOSModel):
    """Stored jailbreak and adversarial injection pattern definition.

    Platform-level and tenant-specific patterns that feed the two-stage
    (regex + semantic) jailbreak detection pipeline. Platform patterns
    have tenant_id set to the system sentinel UUID; tenant patterns are
    scoped to the owning tenant.

    Table: sec_jailbreak_patterns
    """

    __tablename__ = "sec_jailbreak_patterns"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "pattern_name",
            name="uq_sec_jailbreak_patterns_tenant_name",
        ),
    )

    pattern_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Unique identifier for the pattern (e.g., ignore_previous_instructions)",
    )
    pattern_scope: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="tenant",
        comment="platform | tenant — platform patterns apply to all tenants",
    )
    detection_method: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="regex",
        comment="regex | semantic | hybrid — detection strategy for this pattern",
    )
    regex_pattern: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Compiled regex pattern string (used when detection_method is regex or hybrid)",
    )
    semantic_exemplar: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Representative text for semantic similarity matching (hybrid/semantic only)",
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="high",
        comment="Severity assigned on match: critical | high | medium | low",
    )
    confidence_override: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Fixed confidence score for regex matches (None = use ML confidence)",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Soft-delete — inactive patterns are excluded from the detection pipeline",
    )
    match_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Lifetime count of times this pattern has matched (updated periodically)",
    )
    last_matched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the most recent match event",
    )
    pattern_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Additional metadata: source, CVE reference, test cases, etc.",
    )


class SecWebhookEndpoint(AumOSModel):
    """SIEM or security webhook endpoint registration.

    Tenants register SIEM destinations to receive real-time security events.
    Each endpoint specifies the format, target URL, and HMAC signing secret.
    Deliveries are tracked in SecWebhookDelivery records.

    Table: sec_webhook_endpoints
    """

    __tablename__ = "sec_webhook_endpoints"

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Human-readable endpoint name (e.g., splunk-prod, sentinel-security)",
    )
    target_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        comment="HTTPS destination URL for security event payloads",
    )
    format: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="json",
        comment="Payload format: json | splunk_hec | datadog | sentinel_cef",
    )
    signing_secret: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        comment="HMAC-SHA256 signing secret (stored encrypted at rest)",
    )
    event_filter: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Optional event filter: {min_severity: high, threat_types: [prompt_injection]}",
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether this endpoint is active and receives deliveries",
    )
    failure_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Consecutive delivery failures (auto-disables after threshold)",
    )
    last_delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the most recent successful delivery",
    )
    total_deliveries: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Lifetime count of successful deliveries to this endpoint",
    )


class SecWebhookDelivery(AumOSModel):
    """Record of a single webhook delivery attempt.

    Each security event that passes endpoint filters creates one delivery
    record per registered endpoint. Records are retained for 30 days for
    debugging and compliance audit purposes.

    Table: sec_webhook_deliveries
    """

    __tablename__ = "sec_webhook_deliveries"

    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="FK to sec_webhook_endpoints (no DB constraint — same-service UUID)",
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="FK to sec_security_scans that triggered this delivery",
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="pending",
        comment="Delivery status: pending | success | failed | retrying",
    )
    http_status_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="HTTP response status from the target endpoint (None if no response)",
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        comment="Number of delivery attempts (includes retries)",
    )
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Scheduled timestamp for next retry (None if not retrying)",
    )
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when delivery succeeded",
    )
    error_detail: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Error message on delivery failure (connection error, HTTP 4xx/5xx, etc.)",
    )
    payload_size_bytes: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Size of the delivered payload in bytes",
    )


class SecRateLimitConfig(AumOSModel):
    """Per-tenant scan rate limit configuration.

    Defines the request-per-second ceiling for a tenant's security scan
    calls. The TenantRateLimiter adapter reads these configs (cached in
    Redis) to enforce limits without hitting the DB on every request.

    Table: sec_rate_limit_configs
    """

    __tablename__ = "sec_rate_limit_configs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "scope",
            name="uq_sec_rate_limit_configs_tenant_scope",
        ),
    )

    scope: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="global",
        comment="Limit scope: global | input_scan | output_scan | container_scan",
    )
    requests_per_second: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=100,
        comment="Maximum allowed scan requests per second for this tenant",
    )
    burst_multiplier: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=2.0,
        comment="Allowed burst = requests_per_second * burst_multiplier",
    )
    action_on_limit: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="reject",
        comment="Action when limit exceeded: reject | queue | throttle",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether this rate limit configuration is enforced",
    )
    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Admin notes explaining the limit (e.g., Enterprise tier, SLA exception)",
    )


class SecAnomalyBaseline(AumOSModel):
    """Rolling baseline statistics for per-tenant anomaly detection.

    Stores the statistical profile (mean, stddev, percentiles) of normal
    scan behaviour per tenant. The anomaly detection service compares
    current request patterns against this baseline to identify suspicious
    spikes in injection attempts, PII exposure events, or scan volumes.

    Table: sec_anomaly_baselines
    """

    __tablename__ = "sec_anomaly_baselines"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "metric_name",
            name="uq_sec_anomaly_baselines_tenant_metric",
        ),
    )

    metric_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Metric identifier: scans_per_minute | injection_rate | pii_rate | block_rate",
    )
    window_hours: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=168,
        comment="Rolling window in hours used to compute the baseline (default: 7 days)",
    )
    mean_value: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="Rolling mean of the metric over the window",
    )
    stddev_value: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="Rolling standard deviation of the metric",
    )
    p95_value: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="95th percentile of the metric over the window",
    )
    p99_value: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="99th percentile of the metric over the window",
    )
    anomaly_threshold_multiplier: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=3.0,
        comment="Alert when value exceeds mean + (stddev * multiplier)",
    )
    last_computed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the last baseline recomputation",
    )
    sample_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of data points used in the current baseline computation",
    )


__all__ = [
    "SecJailbreakPattern",
    "SecWebhookEndpoint",
    "SecWebhookDelivery",
    "SecRateLimitConfig",
    "SecAnomalyBaseline",
]
