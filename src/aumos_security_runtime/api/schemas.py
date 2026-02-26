"""Pydantic request and response schemas for aumos-security-runtime API.

All API inputs and outputs use Pydantic models — never raw dicts.
Schema groups:
  - ScanInput* — POST /scan/input
  - ScanOutput* — POST /scan/output
  - SecurityScan* — GET /scans
  - Guardrail* — POST/GET /guardrails
  - ThreatDetection* — GET /threats
  - SecurityPolicy* — POST /policies
  - SecurityMetrics* — GET /metrics
  - ContainerScan* — POST /container-scan
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ============================================================================
# Input Scan Schemas
# ============================================================================


class ScanInputRequest(BaseModel):
    """Request body for POST /api/v1/scan/input.

    Attributes:
        content: The LLM input text to scan.
        context: Optional metadata about the LLM call (model, purpose, etc.).
        policy_id: Optional security policy UUID to apply.
    """

    content: str = Field(description="The LLM input text to scan", min_length=1, max_length=100_000)
    context: dict[str, Any] | None = Field(default=None, description="Optional LLM call metadata")
    policy_id: uuid.UUID | None = Field(default=None, description="Security policy UUID to apply")


class ThreatResult(BaseModel):
    """A single detected threat within a scan result.

    Attributes:
        threat_type: Category of threat detected.
        severity: Severity level (critical/high/medium/low).
        confidence: Detection confidence score (0.0–1.0).
        details: Structured details about the threat.
    """

    threat_type: str = Field(description="Threat category (e.g., prompt_injection, pii_leak)")
    severity: str = Field(description="Severity level: critical, high, medium, or low")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence (0.0–1.0)")
    details: dict[str, Any] = Field(default_factory=dict, description="Threat detection details")


class ScanInputResponse(BaseModel):
    """Response body for POST /api/v1/scan/input.

    Attributes:
        scan_id: UUID of the created scan record.
        allowed: Whether the content passed all security checks.
        action: Enforcement action (allow/block/warn/redact).
        threats: List of detected threats.
        redacted_content: PII-redacted content if action is redact.
        latency_ms: Total scan latency in milliseconds.
        scan_type: Always "input" for this endpoint.
    """

    scan_id: uuid.UUID = Field(description="UUID of the created security scan record")
    allowed: bool = Field(description="Whether the content passed all security checks")
    action: str = Field(description="Enforcement action: allow, block, warn, or redact")
    threats: list[ThreatResult] = Field(default_factory=list, description="Detected threats")
    redacted_content: str | None = Field(default=None, description="Content with PII redacted")
    latency_ms: float = Field(description="Total scan latency in milliseconds")
    scan_type: str = Field(default="input", description="Type of scan")


# ============================================================================
# Output Scan Schemas
# ============================================================================


class ScanOutputRequest(BaseModel):
    """Request body for POST /api/v1/scan/output.

    Attributes:
        content: The LLM output text to scan.
        context: Optional metadata about the LLM response.
        policy_id: Optional security policy UUID to apply.
    """

    content: str = Field(description="The LLM output text to scan", min_length=1, max_length=500_000)
    context: dict[str, Any] | None = Field(default=None, description="Optional LLM response metadata")
    policy_id: uuid.UUID | None = Field(default=None, description="Security policy UUID to apply")


class ScanOutputResponse(BaseModel):
    """Response body for POST /api/v1/scan/output."""

    scan_id: uuid.UUID = Field(description="UUID of the created security scan record")
    allowed: bool = Field(description="Whether the content passed all security checks")
    action: str = Field(description="Enforcement action: allow, block, warn, or redact")
    threats: list[ThreatResult] = Field(default_factory=list, description="Detected threats")
    redacted_content: str | None = Field(default=None, description="Content with PII redacted")
    latency_ms: float = Field(description="Total scan latency in milliseconds")
    scan_type: str = Field(default="output", description="Type of scan")


# ============================================================================
# Security Scan List Schemas
# ============================================================================


class SecurityScanResponse(BaseModel):
    """Response schema for a single security scan record.

    Attributes:
        id: Scan UUID.
        tenant_id: Owning tenant UUID.
        scan_type: Type of scan (input/output/container).
        content_hash: SHA-256 hash of scanned content.
        threats_detected: Number of threats found.
        latency_ms: Total scan latency.
        action_taken: Enforcement action applied.
        policy_id: Security policy that governed the scan.
        created_at: When the scan was created.
    """

    id: uuid.UUID = Field(description="Scan UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    scan_type: str = Field(description="Type of scan: input, output, or container")
    content_hash: str = Field(description="SHA-256 hash of scanned content")
    threats_detected: int = Field(description="Number of threats found")
    latency_ms: float = Field(description="Total scan latency in milliseconds")
    action_taken: str = Field(description="Enforcement action applied")
    policy_id: uuid.UUID | None = Field(default=None, description="Applied security policy")
    created_at: datetime = Field(description="When the scan was created")


class SecurityScanListResponse(BaseModel):
    """Paginated list of security scans.

    Attributes:
        items: List of security scan records.
        total: Total number of records matching the filter.
        page: Current page number.
        page_size: Records per page.
    """

    items: list[SecurityScanResponse] = Field(description="Security scan records")
    total: int = Field(description="Total records matching filter")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Records per page")


# ============================================================================
# Guardrail Schemas
# ============================================================================


class GuardrailCreateRequest(BaseModel):
    """Request body for POST /api/v1/guardrails.

    Attributes:
        name: Human-readable rule name.
        rule_type: Whether to apply at input or output stage.
        pattern: Regex pattern string.
        action: Enforcement action (block/warn/redact).
        enabled: Whether the rule is immediately active.
    """

    name: str = Field(description="Human-readable rule name", min_length=1, max_length=255)
    rule_type: str = Field(description="Apply at: input or output")
    pattern: str = Field(description="Regex pattern to match", min_length=1)
    action: str = Field(description="Enforcement action: block, warn, or redact")
    enabled: bool = Field(default=True, description="Whether the rule is active")


class GuardrailResponse(BaseModel):
    """Response schema for a guardrail rule.

    Attributes:
        id: Rule UUID.
        tenant_id: Owning tenant UUID.
        name: Rule name.
        rule_type: Input or output stage.
        pattern: Regex pattern.
        action: Enforcement action.
        enabled: Whether the rule is active.
        created_at: Creation timestamp.
    """

    id: uuid.UUID = Field(description="Rule UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    name: str = Field(description="Rule name")
    rule_type: str = Field(description="Input or output stage")
    pattern: str = Field(description="Regex pattern")
    action: str = Field(description="Enforcement action")
    enabled: bool = Field(description="Whether the rule is active")
    created_at: datetime = Field(description="Creation timestamp")


class GuardrailListResponse(BaseModel):
    """List of guardrail rules for a tenant."""

    items: list[GuardrailResponse] = Field(description="Guardrail rules")
    total: int = Field(description="Total number of rules")


# ============================================================================
# Threat Detection Schemas
# ============================================================================


class ThreatDetectionResponse(BaseModel):
    """Response schema for a threat detection record.

    Attributes:
        id: Threat UUID.
        tenant_id: Owning tenant UUID.
        scan_id: Associated scan UUID.
        threat_type: Category of threat.
        severity: Severity level.
        confidence: Detection confidence.
        details: Structured threat details.
        created_at: Detection timestamp.
    """

    id: uuid.UUID = Field(description="Threat detection UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    scan_id: uuid.UUID = Field(description="Associated scan UUID")
    threat_type: str = Field(description="Threat category")
    severity: str = Field(description="Severity level")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence")
    details: dict[str, Any] = Field(default_factory=dict, description="Threat details")
    created_at: datetime = Field(description="Detection timestamp")


class ThreatDetectionListResponse(BaseModel):
    """Paginated list of threat detections."""

    items: list[ThreatDetectionResponse] = Field(description="Threat detection records")
    total: int = Field(description="Total records matching filter")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Records per page")


# ============================================================================
# Security Policy Schemas
# ============================================================================


class SecurityPolicyCreateRequest(BaseModel):
    """Request body for POST /api/v1/policies.

    Attributes:
        name: Policy name.
        config: JSONB policy configuration.
        max_latency_ms: Maximum allowed scan latency.
        enabled: Whether the policy is active.
    """

    name: str = Field(description="Policy name", min_length=1, max_length=255)
    config: dict[str, Any] = Field(default_factory=dict, description="Policy configuration")
    max_latency_ms: int = Field(default=50, ge=10, le=5000, description="Maximum scan latency in ms")
    enabled: bool = Field(default=True, description="Whether the policy is active")


class SecurityPolicyResponse(BaseModel):
    """Response schema for a security policy."""

    id: uuid.UUID = Field(description="Policy UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    name: str = Field(description="Policy name")
    config: dict[str, Any] = Field(description="Policy configuration")
    max_latency_ms: int = Field(description="Maximum scan latency in ms")
    enabled: bool = Field(description="Whether the policy is active")
    created_at: datetime = Field(description="Creation timestamp")


# ============================================================================
# Metrics Schemas
# ============================================================================


class LatencyPercentiles(BaseModel):
    """Latency percentile distribution for scan operations.

    Attributes:
        p50: Median latency in milliseconds.
        p95: 95th percentile latency in milliseconds.
        p99: 99th percentile latency in milliseconds.
    """

    p50: float = Field(description="Median scan latency (ms)")
    p95: float = Field(description="P95 scan latency (ms)")
    p99: float = Field(description="P99 scan latency (ms)")


class SecurityMetricsResponse(BaseModel):
    """Security metrics response for GET /api/v1/metrics.

    Attributes:
        total_scans: Total number of scans in the time window.
        total_threats: Total number of threats detected.
        detection_rate: Fraction of scans with at least one threat.
        block_rate: Fraction of scans that resulted in a block action.
        latency: Latency percentile statistics.
        scans_by_type: Breakdown of scans by type (input/output/container).
        threats_by_type: Breakdown of threats by category.
    """

    total_scans: int = Field(description="Total scans in time window")
    total_threats: int = Field(description="Total threats detected")
    detection_rate: float = Field(ge=0.0, le=1.0, description="Fraction of scans with threats")
    block_rate: float = Field(ge=0.0, le=1.0, description="Fraction of scans resulting in block")
    latency: LatencyPercentiles = Field(description="Latency percentile statistics")
    scans_by_type: dict[str, int] = Field(description="Scan counts by type")
    threats_by_type: dict[str, int] = Field(description="Threat counts by category")


# ============================================================================
# Container Scan Schemas
# ============================================================================


class ContainerScanRequest(BaseModel):
    """Request body for POST /api/v1/container-scan.

    Attributes:
        image_ref: Container image reference (e.g., myrepo/myimage:latest).
        registry: Optional registry URL if not Docker Hub.
        severity_threshold: Minimum vulnerability severity to report.
    """

    image_ref: str = Field(description="Container image reference (e.g., myrepo/myimage:latest)")
    registry: str | None = Field(default=None, description="Optional registry URL")
    severity_threshold: str = Field(
        default="HIGH",
        description="Minimum severity to report: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL",
    )


class VulnerabilityResult(BaseModel):
    """A single vulnerability found in a container scan.

    Attributes:
        vulnerability_id: CVE or other vulnerability identifier.
        severity: Severity level (CRITICAL/HIGH/MEDIUM/LOW).
        package_name: Affected package name.
        installed_version: Currently installed version.
        fixed_version: Version that fixes the vulnerability.
        description: Human-readable description.
    """

    vulnerability_id: str = Field(description="CVE or other vulnerability ID")
    severity: str = Field(description="Severity level")
    package_name: str = Field(description="Affected package")
    installed_version: str = Field(description="Currently installed version")
    fixed_version: str | None = Field(default=None, description="Version with fix (if available)")
    description: str = Field(description="Vulnerability description")


class ContainerScanResponse(BaseModel):
    """Response body for POST /api/v1/container-scan.

    Attributes:
        scan_id: UUID of the created scan record.
        image_ref: The image that was scanned.
        vulnerabilities: List of found vulnerabilities.
        total_vulnerabilities: Total number of vulnerabilities found.
        critical_count: Number of CRITICAL severity vulnerabilities.
        high_count: Number of HIGH severity vulnerabilities.
        status: Scan outcome (passed/failed).
    """

    scan_id: uuid.UUID = Field(description="UUID of the scan record")
    image_ref: str = Field(description="Container image that was scanned")
    vulnerabilities: list[VulnerabilityResult] = Field(
        default_factory=list, description="Found vulnerabilities"
    )
    total_vulnerabilities: int = Field(description="Total number of vulnerabilities")
    critical_count: int = Field(description="Number of CRITICAL severity vulnerabilities")
    high_count: int = Field(description="Number of HIGH severity vulnerabilities")
    status: str = Field(description="Scan result: passed or failed")


__all__ = [
    "ScanInputRequest",
    "ScanInputResponse",
    "ThreatResult",
    "ScanOutputRequest",
    "ScanOutputResponse",
    "SecurityScanResponse",
    "SecurityScanListResponse",
    "GuardrailCreateRequest",
    "GuardrailResponse",
    "GuardrailListResponse",
    "ThreatDetectionResponse",
    "ThreatDetectionListResponse",
    "SecurityPolicyCreateRequest",
    "SecurityPolicyResponse",
    "LatencyPercentiles",
    "SecurityMetricsResponse",
    "ContainerScanRequest",
    "ContainerScanResponse",
    "VulnerabilityResult",
]
