"""SQLAlchemy ORM models for aumos-security-runtime.

All tables use the sec_ prefix and extend AumOSModel which provides:
  - id: UUID primary key
  - tenant_id: UUID (RLS-enforced)
  - created_at: datetime
  - updated_at: datetime

Tables:
  - sec_security_scans: Records of every content scan (input/output/container)
  - sec_threat_detections: Individual threats found within a scan
  - sec_guardrail_rules: Tenant-configurable rules (block/warn/redact)
  - sec_security_policies: Tenant security policy configurations
"""

import uuid
from enum import Enum

from sqlalchemy import Boolean, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from aumos_common.database import AumOSModel


class ScanType(str, Enum):
    """The type of content that was scanned."""

    INPUT = "input"
    OUTPUT = "output"
    CONTAINER = "container"


class ThreatType(str, Enum):
    """The category of threat that was detected."""

    PROMPT_INJECTION = "prompt_injection"
    PII_LEAK = "pii_leak"
    DATA_EXTRACTION = "data_extraction"
    TOXICITY = "toxicity"


class ThreatSeverity(str, Enum):
    """Severity level of a detected threat."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleType(str, Enum):
    """Whether a guardrail rule applies to input or output scanning."""

    INPUT = "input"
    OUTPUT = "output"


class RuleAction(str, Enum):
    """The enforcement action taken when a rule matches."""

    BLOCK = "block"
    WARN = "warn"
    REDACT = "redact"


class SecurityScan(AumOSModel):
    """Record of a security scan operation.

    Each call to /scan/input or /scan/output creates one SecurityScan record.
    Multiple ThreatDetection records may be associated with a single scan.

    Table: sec_security_scans
    """

    __tablename__ = "sec_security_scans"

    scan_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Type of scan: input, output, or container",
    )
    content_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of scanned content (never store raw content)",
    )
    threats_detected: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of threats found in this scan",
    )
    latency_ms: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Total scan latency in milliseconds",
    )
    action_taken: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="allow",
        comment="Final enforcement action: allow, block, warn, or redact",
    )
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="Security policy that governed this scan",
    )


class ThreatDetection(AumOSModel):
    """Record of an individual threat found during a scan.

    One SecurityScan may have multiple ThreatDetection records.
    Details are stored as JSONB for flexible schema.

    Table: sec_threat_detections
    """

    __tablename__ = "sec_threat_detections"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="Foreign key to sec_security_scans (no FK constraint — cross-service UUID)",
    )
    threat_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Category of threat: prompt_injection, pii_leak, data_extraction, toxicity",
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Severity level: critical, high, medium, low",
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Detection confidence score (0.0–1.0)",
    )
    details: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Structured details about the threat (pattern matched, entity types, etc.)",
    )


class GuardrailRule(AumOSModel):
    """Tenant-configurable guardrail rule.

    Tenants can define custom rules to supplement platform defaults.
    Rules are cached per-tenant and reloaded when modified.

    Table: sec_guardrail_rules
    """

    __tablename__ = "sec_guardrail_rules"

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Human-readable rule name",
    )
    rule_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Whether to apply at input or output scanning stage",
    )
    pattern: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Regex pattern to match against content",
    )
    action: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=RuleAction.WARN,
        comment="Enforcement action: block, warn, or redact",
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether this rule is currently active",
    )


class SecurityPolicy(AumOSModel):
    """Tenant-level security policy configuration.

    Policies define which checks to enable, severity thresholds,
    and the maximum allowed latency for this tenant's scans.
    Config is stored as JSONB for flexible schema evolution.

    Table: sec_security_policies
    """

    __tablename__ = "sec_security_policies"

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Human-readable policy name",
    )
    config: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Policy configuration: enabled checks, thresholds, etc.",
    )
    max_latency_ms: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=50,
        comment="Maximum allowed scan latency in milliseconds for this policy",
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether this policy is currently active",
    )


__all__ = [
    "ScanType",
    "ThreatType",
    "ThreatSeverity",
    "RuleType",
    "RuleAction",
    "SecurityScan",
    "ThreatDetection",
    "GuardrailRule",
    "SecurityPolicy",
]
