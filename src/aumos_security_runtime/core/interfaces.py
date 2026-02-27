"""Abstract interfaces (Protocol classes) for aumos-security-runtime.

Defining interfaces as Protocol classes enables:
  - Dependency injection in services
  - Easy mocking in tests
  - Clear contracts between scanner adapters and the pipeline service

Services depend on interfaces, not concrete implementations.

Protocols defined:
- IScannerResult
- IPatternScanner
- IMLScanner
- IPIIScanner
- ISecurityScanRepository
- IThreatDetectionRepository
- IGuardrailRepository
- ISecurityPolicyRepository
- ISecretScanner
- IVulnerabilityScanner
"""

import uuid
from typing import Any, Protocol, runtime_checkable

from aumos_security_runtime.core.models import (
    GuardrailRule,
    SecurityPolicy,
    SecurityScan,
    ThreatDetection,
)


@runtime_checkable
class IScannerResult(Protocol):
    """Result returned by any scanner adapter."""

    threat_type: str
    severity: str
    confidence: float
    details: dict[str, Any]
    is_threat: bool


@runtime_checkable
class IPatternScanner(Protocol):
    """Interface for regex/pattern-based prompt injection detection."""

    async def scan(self, content: str) -> list[IScannerResult]:
        """Scan content for injection patterns.

        Args:
            content: The text content to scan.

        Returns:
            List of scanner results, one per matched pattern.
        """
        ...

    async def initialize(self) -> None:
        """Pre-compile and cache all regex patterns.

        Called once at startup to avoid compilation latency on hot path.
        """
        ...


@runtime_checkable
class IMLScanner(Protocol):
    """Interface for ML-based prompt injection classification."""

    async def scan(self, content: str) -> IScannerResult:
        """Classify content using the ML model.

        Args:
            content: The text content to classify.

        Returns:
            Scanner result with confidence score.
        """
        ...

    async def initialize(self) -> None:
        """Load ML model into memory.

        Called once at startup. Must not be called on the request hot path.
        """
        ...


@runtime_checkable
class IPIIScanner(Protocol):
    """Interface for PII detection and redaction."""

    async def scan(self, content: str) -> list[IScannerResult]:
        """Detect PII entities in content.

        Args:
            content: The text content to analyze.

        Returns:
            List of scanner results, one per PII entity type found.
        """
        ...

    async def redact(self, content: str) -> str:
        """Redact PII from content, replacing with [REDACTED].

        Args:
            content: The text content to redact.

        Returns:
            Content with PII replaced by [REDACTED] markers.
        """
        ...

    async def initialize(self) -> None:
        """Load Presidio analyzer models into memory."""
        ...


@runtime_checkable
class ISecurityScanRepository(Protocol):
    """Repository interface for SecurityScan records."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        scan_type: str,
        content_hash: str,
        threats_detected: int,
        latency_ms: float,
        action_taken: str,
        policy_id: uuid.UUID | None,
    ) -> SecurityScan:
        """Create a new security scan record.

        Args:
            tenant_id: The tenant that triggered the scan.
            scan_type: Type of scan (input/output/container).
            content_hash: SHA-256 hash of scanned content.
            threats_detected: Number of threats found.
            latency_ms: Total scan latency.
            action_taken: Enforcement action applied.
            policy_id: Optional security policy that governed the scan.

        Returns:
            The created SecurityScan record.
        """
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> list[SecurityScan]:
        """List security scans for a tenant with pagination.

        Args:
            tenant_id: The tenant to filter by.
            page: Page number (1-indexed).
            page_size: Number of records per page.

        Returns:
            List of SecurityScan records for the tenant.
        """
        ...


@runtime_checkable
class IThreatDetectionRepository(Protocol):
    """Repository interface for ThreatDetection records."""

    async def create_many(
        self,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        threats: list[dict[str, Any]],
    ) -> list[ThreatDetection]:
        """Bulk-create threat detection records for a scan.

        Args:
            scan_id: The scan these threats belong to.
            tenant_id: The owning tenant.
            threats: List of threat data dicts.

        Returns:
            List of created ThreatDetection records.
        """
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> list[ThreatDetection]:
        """List threat detections for a tenant with pagination.

        Args:
            tenant_id: The tenant to filter by.
            page: Page number (1-indexed).
            page_size: Number of records per page.

        Returns:
            List of ThreatDetection records for the tenant.
        """
        ...


@runtime_checkable
class IGuardrailRepository(Protocol):
    """Repository interface for GuardrailRule records."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        name: str,
        rule_type: str,
        pattern: str,
        action: str,
        enabled: bool,
    ) -> GuardrailRule:
        """Create a new guardrail rule.

        Args:
            tenant_id: The owning tenant.
            name: Human-readable rule name.
            rule_type: Whether to apply at input or output stage.
            pattern: Regex pattern.
            action: Enforcement action (block/warn/redact).
            enabled: Whether the rule is active.

        Returns:
            The created GuardrailRule record.
        """
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        rule_type: str | None,
    ) -> list[GuardrailRule]:
        """List guardrail rules for a tenant.

        Args:
            tenant_id: The owning tenant.
            rule_type: Optional filter by input/output type.

        Returns:
            List of GuardrailRule records.
        """
        ...


@runtime_checkable
class ISecurityPolicyRepository(Protocol):
    """Repository interface for SecurityPolicy records."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        name: str,
        config: dict[str, Any],
        max_latency_ms: int,
        enabled: bool,
    ) -> SecurityPolicy:
        """Create a new security policy.

        Args:
            tenant_id: The owning tenant.
            name: Policy name.
            config: JSONB policy configuration.
            max_latency_ms: Maximum allowed scan latency.
            enabled: Whether the policy is active.

        Returns:
            The created SecurityPolicy record.
        """
        ...

    async def get_by_id(
        self,
        policy_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> SecurityPolicy | None:
        """Retrieve a policy by ID within a tenant scope.

        Args:
            policy_id: The policy UUID.
            tenant_id: The owning tenant.

        Returns:
            The SecurityPolicy or None if not found.
        """
        ...


@runtime_checkable
class ISecretScanner(Protocol):
    """Interface for exposed secret and credential detection.

    Scans LLM inputs and outputs for accidentally exposed API keys, tokens,
    database connection strings, private keys, and high-entropy strings.
    Designed for the security pipeline hot path (<5ms target latency).
    """

    async def scan(self, content: str) -> list[dict[str, Any]]:
        """Scan content for exposed secrets.

        Returns results in IScannerResult-compatible dict format.

        Args:
            content: Text content to scan for secrets.

        Returns:
            List of IScannerResult-compatible dicts, one per finding.
            Empty list if no secrets are detected.
        """
        ...

    async def initialize(self) -> None:
        """Pre-compile and cache all regex patterns.

        Called once at startup to avoid compilation latency on the hot path.
        Must be called before scan() is invoked.
        """
        ...

    def sanitize_for_logging(self, content: str) -> str:
        """Sanitize content before logging to prevent secret exposure.

        Args:
            content: Text content to sanitize.

        Returns:
            Sanitized content safe for logging.
        """
        ...


@runtime_checkable
class IVulnerabilityScanner(Protocol):
    """Interface for CVE and dependency vulnerability scanning.

    Scans Python package dependencies and container images for known
    vulnerabilities using pip-audit and Trivy integrations. Not intended
    for the <50ms request hot path — use for background security jobs.
    """

    async def scan(self, content: str) -> list[dict[str, Any]]:
        """Scan for vulnerabilities from a requirements or image reference.

        Content is expected to be a JSON requirements payload or image
        reference string. Parses the content type and delegates to the
        appropriate scanner backend.

        Args:
            content: Requirements JSON or image reference string.

        Returns:
            List of IScannerResult-compatible dicts, one per CVE finding.
            Empty list if no vulnerabilities are detected.
        """
        ...

    async def scan_python_dependencies(self) -> dict[str, Any]:
        """Scan installed Python dependencies for known CVEs.

        Uses pip-audit against OSV/PyPA advisory databases.

        Returns:
            VulnerabilityScanResult-compatible dict with findings.
        """
        ...

    async def scan_container_image(self, image_reference: str) -> dict[str, Any]:
        """Scan a container image for OS and library vulnerabilities.

        Uses Trivy as a subprocess. Not suitable for the request hot path.

        Args:
            image_reference: Docker image reference (e.g., 'myapp:latest').

        Returns:
            VulnerabilityScanResult-compatible dict with findings.
        """
        ...

    def is_available(self) -> bool:
        """Return True if at least one scanning backend is available.

        Returns:
            True if pip-audit or Trivy is installed on the system.
        """
        ...


__all__ = [
    "IScannerResult",
    "IPatternScanner",
    "IMLScanner",
    "IPIIScanner",
    "ISecurityScanRepository",
    "IThreatDetectionRepository",
    "IGuardrailRepository",
    "ISecurityPolicyRepository",
    "ISecretScanner",
    "IVulnerabilityScanner",
]
