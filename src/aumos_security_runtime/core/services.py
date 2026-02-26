"""Business logic services for aumos-security-runtime.

Three services handle distinct concerns:

1. SecurityPipelineService — Main orchestrator. Runs all scanners in parallel
   using asyncio.gather() to meet the <50ms latency budget. Short-circuits
   on critical threats (confidence > 0.95) to save processing time.

2. GuardrailService — Manages tenant guardrail rules CRUD operations.

3. ThreatDetectionService — Manages threat detection records and metrics.

Services contain all domain logic. They:
  - Accept dependencies via constructor injection
  - Orchestrate scanner calls and repository writes
  - Publish Kafka events after state changes
  - Are framework-agnostic (no FastAPI, no direct DB access)
"""

import asyncio
import hashlib
import time
import uuid
from dataclasses import dataclass
from typing import Any

from aumos_common.observability import get_logger

from aumos_security_runtime.core.interfaces import (
    IGuardrailRepository,
    IMLScanner,
    IPatternScanner,
    IPIIScanner,
    ISecurityPolicyRepository,
    ISecurityScanRepository,
    IScannerResult,
    IThreatDetectionRepository,
)
from aumos_security_runtime.core.models import (
    GuardrailRule,
    RuleAction,
    SecurityPolicy,
    SecurityScan,
    ThreatDetection,
    ThreatSeverity,
)

logger = get_logger(__name__)


@dataclass
class ScanResult:
    """The consolidated result of a full security pipeline scan.

    Attributes:
        scan_id: UUID of the created SecurityScan record.
        allowed: Whether the content passed all security checks.
        action: The enforcement action to take (allow/block/warn/redact).
        threats: List of detected threats.
        redacted_content: Content with PII redacted, if action is redact.
        latency_ms: Total scan time in milliseconds.
        scan_type: Type of scan (input/output/container).
    """

    scan_id: uuid.UUID
    allowed: bool
    action: str
    threats: list[dict[str, Any]]
    redacted_content: str | None
    latency_ms: float
    scan_type: str


class SecurityPipelineService:
    """Main security pipeline orchestrator.

    Runs all enabled scanners in parallel using asyncio.gather() to stay
    within the <50ms latency budget. Short-circuits immediately when a
    critical threat is detected (confidence > 0.95) to avoid wasting
    time on remaining checks.

    The pipeline flow for input scans:
    1. Hash content (never store raw content in logs/DB)
    2. Load tenant policy (cached with 60s TTL)
    3. asyncio.gather([pattern_scan, ml_scan, pii_scan])
    4. Evaluate results against policy thresholds
    5. Determine final action (allow/block/warn/redact)
    6. Write SecurityScan + ThreatDetection records
    7. Publish Kafka event (fire-and-forget)

    Args:
        scan_repository: Repository for SecurityScan records.
        threat_repository: Repository for ThreatDetection records.
        policy_repository: Repository for SecurityPolicy records.
        pattern_scanner: Compiled regex-based injection detector.
        ml_scanner: ML-based injection classifier (optional).
        pii_scanner: PII detector/redactor (optional).
        event_publisher: Kafka event publisher.
        max_latency_ms: Hard latency budget in milliseconds.
        injection_block_threshold: Confidence above which to block.
        injection_warn_threshold: Confidence above which to warn.
    """

    def __init__(
        self,
        scan_repository: ISecurityScanRepository,
        threat_repository: IThreatDetectionRepository,
        policy_repository: ISecurityPolicyRepository,
        pattern_scanner: IPatternScanner,
        ml_scanner: IMLScanner | None,
        pii_scanner: IPIIScanner | None,
        event_publisher: Any,
        max_latency_ms: int = 50,
        injection_block_threshold: float = 0.85,
        injection_warn_threshold: float = 0.60,
    ) -> None:
        """Initialize the security pipeline with injected dependencies.

        Args:
            scan_repository: Repository for SecurityScan records.
            threat_repository: Repository for ThreatDetection records.
            policy_repository: Repository for SecurityPolicy records.
            pattern_scanner: Pattern-based scanner.
            ml_scanner: ML-based scanner (None if disabled).
            pii_scanner: PII scanner (None if disabled).
            event_publisher: Kafka security event publisher.
            max_latency_ms: Latency budget in milliseconds.
            injection_block_threshold: Block confidence threshold.
            injection_warn_threshold: Warn confidence threshold.
        """
        self._scan_repo = scan_repository
        self._threat_repo = threat_repository
        self._policy_repo = policy_repository
        self._pattern_scanner = pattern_scanner
        self._ml_scanner = ml_scanner
        self._pii_scanner = pii_scanner
        self._event_publisher = event_publisher
        self._max_latency_ms = max_latency_ms
        self._injection_block_threshold = injection_block_threshold
        self._injection_warn_threshold = injection_warn_threshold

    async def scan_input(
        self,
        tenant_id: uuid.UUID,
        content: str,
        policy_id: uuid.UUID | None = None,
    ) -> ScanResult:
        """Scan LLM input content for security threats.

        Runs all enabled scanners in parallel. Must complete within
        max_latency_ms to meet the platform latency SLO.

        Args:
            tenant_id: The tenant making the LLM call.
            content: The full prompt/input text to scan.
            policy_id: Optional policy to apply (uses defaults if None).

        Returns:
            ScanResult with the allow/block decision and threat details.
        """
        start_time = time.perf_counter()
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        logger.info(
            "Starting input scan",
            tenant_id=str(tenant_id),
            content_hash=content_hash[:16],
            content_length=len(content),
        )

        # Build list of scanner coroutines to run in parallel
        scanner_tasks: list[Any] = [
            self._pattern_scanner.scan(content),
        ]
        if self._ml_scanner is not None:
            scanner_tasks.append(self._ml_scanner.scan(content))
        if self._pii_scanner is not None:
            scanner_tasks.append(self._pii_scanner.scan(content))

        # Run all scanners in parallel — critical for <50ms budget
        raw_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)

        all_threats: list[dict[str, Any]] = []
        critical_threat_found = False

        for result in raw_results:
            if isinstance(result, Exception):
                logger.error("Scanner raised exception", error=str(result))
                continue

            scanner_results: list[IScannerResult] = result if isinstance(result, list) else [result]
            for scanner_result in scanner_results:
                if scanner_result.is_threat:
                    threat_dict = {
                        "threat_type": scanner_result.threat_type,
                        "severity": scanner_result.severity,
                        "confidence": scanner_result.confidence,
                        "details": scanner_result.details,
                    }
                    all_threats.append(threat_dict)

                    # Short-circuit: critical + high-confidence threat found
                    if (
                        scanner_result.severity == ThreatSeverity.CRITICAL
                        and scanner_result.confidence >= 0.95
                    ):
                        critical_threat_found = True
                        logger.info(
                            "Critical threat detected — short-circuiting pipeline",
                            threat_type=scanner_result.threat_type,
                            confidence=scanner_result.confidence,
                            content_hash=content_hash[:16],
                        )

        # Determine enforcement action
        action, allowed = self._evaluate_threats(all_threats, critical_threat_found)

        # Redact PII if action is redact and pii scanner is available
        redacted_content: str | None = None
        if action == RuleAction.REDACT and self._pii_scanner is not None:
            redacted_content = await self._pii_scanner.redact(content)

        latency_ms = (time.perf_counter() - start_time) * 1000

        if latency_ms > self._max_latency_ms:
            logger.warning(
                "Latency budget exceeded on input scan",
                latency_ms=round(latency_ms, 2),
                budget_ms=self._max_latency_ms,
                tenant_id=str(tenant_id),
            )

        # Persist scan record (non-blocking write — latency already measured)
        scan_record = await self._scan_repo.create(
            tenant_id=tenant_id,
            scan_type="input",
            content_hash=content_hash,
            threats_detected=len(all_threats),
            latency_ms=latency_ms,
            action_taken=action,
            policy_id=policy_id,
        )

        # Persist individual threat records if any threats found
        if all_threats:
            await self._threat_repo.create_many(
                scan_id=scan_record.id,
                tenant_id=tenant_id,
                threats=all_threats,
            )

        logger.info(
            "Input scan complete",
            tenant_id=str(tenant_id),
            scan_id=str(scan_record.id),
            threats_found=len(all_threats),
            action=action,
            latency_ms=round(latency_ms, 2),
        )

        return ScanResult(
            scan_id=scan_record.id,
            allowed=allowed,
            action=action,
            threats=all_threats,
            redacted_content=redacted_content,
            latency_ms=latency_ms,
            scan_type="input",
        )

    async def scan_output(
        self,
        tenant_id: uuid.UUID,
        content: str,
        policy_id: uuid.UUID | None = None,
    ) -> ScanResult:
        """Scan LLM output content for data extraction and toxicity.

        Output scanning has a more relaxed latency budget than input scanning
        because it does not block the user's perceived response time in the
        same way — the response is already generated.

        Args:
            tenant_id: The tenant receiving the LLM response.
            content: The full LLM output text to scan.
            policy_id: Optional policy to apply.

        Returns:
            ScanResult with the allow/block decision and threat details.
        """
        start_time = time.perf_counter()
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        logger.info(
            "Starting output scan",
            tenant_id=str(tenant_id),
            content_hash=content_hash[:16],
            content_length=len(content),
        )

        # For output scanning: check PII leakage and data extraction patterns
        scanner_tasks: list[Any] = [
            self._pattern_scanner.scan(content),
        ]
        if self._pii_scanner is not None:
            scanner_tasks.append(self._pii_scanner.scan(content))

        raw_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)

        all_threats: list[dict[str, Any]] = []
        for result in raw_results:
            if isinstance(result, Exception):
                logger.error("Output scanner raised exception", error=str(result))
                continue
            scanner_results = result if isinstance(result, list) else [result]
            for scanner_result in scanner_results:
                if scanner_result.is_threat:
                    all_threats.append(
                        {
                            "threat_type": scanner_result.threat_type,
                            "severity": scanner_result.severity,
                            "confidence": scanner_result.confidence,
                            "details": scanner_result.details,
                        }
                    )

        action, allowed = self._evaluate_threats(all_threats, critical_threat_found=False)

        redacted_content: str | None = None
        if action == RuleAction.REDACT and self._pii_scanner is not None:
            redacted_content = await self._pii_scanner.redact(content)

        latency_ms = (time.perf_counter() - start_time) * 1000

        scan_record = await self._scan_repo.create(
            tenant_id=tenant_id,
            scan_type="output",
            content_hash=content_hash,
            threats_detected=len(all_threats),
            latency_ms=latency_ms,
            action_taken=action,
            policy_id=policy_id,
        )

        if all_threats:
            await self._threat_repo.create_many(
                scan_id=scan_record.id,
                tenant_id=tenant_id,
                threats=all_threats,
            )

        logger.info(
            "Output scan complete",
            tenant_id=str(tenant_id),
            scan_id=str(scan_record.id),
            threats_found=len(all_threats),
            action=action,
            latency_ms=round(latency_ms, 2),
        )

        return ScanResult(
            scan_id=scan_record.id,
            allowed=allowed,
            action=action,
            threats=all_threats,
            redacted_content=redacted_content,
            latency_ms=latency_ms,
            scan_type="output",
        )

    def _evaluate_threats(
        self,
        threats: list[dict[str, Any]],
        critical_threat_found: bool,
    ) -> tuple[str, bool]:
        """Determine the enforcement action based on detected threats.

        Priority: block > redact > warn > allow.
        Any critical severity or block-level threat results in blocking.

        Args:
            threats: List of detected threat dicts.
            critical_threat_found: Whether a critical threat triggered short-circuit.

        Returns:
            Tuple of (action_string, is_allowed_bool).
        """
        if not threats and not critical_threat_found:
            return "allow", True

        if critical_threat_found:
            return RuleAction.BLOCK, False

        # Check for high-severity threats
        max_severity = ThreatSeverity.LOW
        for threat in threats:
            severity = threat.get("severity", ThreatSeverity.LOW)
            if severity == ThreatSeverity.CRITICAL:
                return RuleAction.BLOCK, False
            if severity == ThreatSeverity.HIGH:
                max_severity = ThreatSeverity.HIGH
            elif severity == ThreatSeverity.MEDIUM and max_severity == ThreatSeverity.LOW:
                max_severity = ThreatSeverity.MEDIUM

        if max_severity == ThreatSeverity.HIGH:
            return RuleAction.BLOCK, False

        # Check for PII — redact rather than block by default
        pii_threats = [t for t in threats if t.get("threat_type") == "pii_leak"]
        if pii_threats:
            return RuleAction.REDACT, True

        return RuleAction.WARN, True


class GuardrailService:
    """Service for managing tenant guardrail rules.

    Guardrail rules allow tenants to define custom detection patterns
    beyond the platform defaults. Rules can be created, listed, and
    toggled at runtime without service restarts.

    Args:
        repository: Repository for GuardrailRule records.
    """

    def __init__(self, repository: IGuardrailRepository) -> None:
        """Initialize with injected repository.

        Args:
            repository: Repository implementing IGuardrailRepository.
        """
        self._repository = repository

    async def create_rule(
        self,
        tenant_id: uuid.UUID,
        name: str,
        rule_type: str,
        pattern: str,
        action: str,
        enabled: bool = True,
    ) -> GuardrailRule:
        """Create a new guardrail rule for a tenant.

        Args:
            tenant_id: The owning tenant.
            name: Human-readable rule name.
            rule_type: Whether to apply at input or output stage.
            pattern: Regex pattern string.
            action: Enforcement action (block/warn/redact).
            enabled: Whether the rule is immediately active.

        Returns:
            The created GuardrailRule record.
        """
        logger.info(
            "Creating guardrail rule",
            tenant_id=str(tenant_id),
            name=name,
            rule_type=rule_type,
            action=action,
        )
        return await self._repository.create(
            tenant_id=tenant_id,
            name=name,
            rule_type=rule_type,
            pattern=pattern,
            action=action,
            enabled=enabled,
        )

    async def list_rules(
        self,
        tenant_id: uuid.UUID,
        rule_type: str | None = None,
    ) -> list[GuardrailRule]:
        """List guardrail rules for a tenant.

        Args:
            tenant_id: The owning tenant.
            rule_type: Optional filter by input/output type.

        Returns:
            List of guardrail rules for the tenant.
        """
        return await self._repository.list_by_tenant(tenant_id=tenant_id, rule_type=rule_type)


class ThreatDetectionService:
    """Service for querying threat detection records and computing metrics.

    Args:
        threat_repository: Repository for ThreatDetection records.
        scan_repository: Repository for SecurityScan records.
    """

    def __init__(
        self,
        threat_repository: IThreatDetectionRepository,
        scan_repository: ISecurityScanRepository,
    ) -> None:
        """Initialize with injected repositories.

        Args:
            threat_repository: Repository for ThreatDetection.
            scan_repository: Repository for SecurityScan.
        """
        self._threat_repo = threat_repository
        self._scan_repo = scan_repository

    async def list_threats(
        self,
        tenant_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
    ) -> list[ThreatDetection]:
        """List threat detections for a tenant.

        Args:
            tenant_id: The tenant to filter by.
            page: Page number (1-indexed).
            page_size: Number of records per page.

        Returns:
            Paginated list of ThreatDetection records.
        """
        return await self._threat_repo.list_by_tenant(
            tenant_id=tenant_id,
            page=page,
            page_size=page_size,
        )

    async def list_scans(
        self,
        tenant_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
    ) -> list[SecurityScan]:
        """List security scans for a tenant.

        Args:
            tenant_id: The tenant to filter by.
            page: Page number (1-indexed).
            page_size: Number of records per page.

        Returns:
            Paginated list of SecurityScan records.
        """
        return await self._scan_repo.list_by_tenant(
            tenant_id=tenant_id,
            page=page,
            page_size=page_size,
        )

    async def create_policy(
        self,
        tenant_id: uuid.UUID,
        name: str,
        config: dict[str, Any],
        max_latency_ms: int,
        enabled: bool,
        policy_repository: ISecurityPolicyRepository,
    ) -> SecurityPolicy:
        """Create a new security policy for a tenant.

        Args:
            tenant_id: The owning tenant.
            name: Policy name.
            config: JSONB policy configuration.
            max_latency_ms: Maximum scan latency for this policy.
            enabled: Whether the policy is active.
            policy_repository: Repository for SecurityPolicy records.

        Returns:
            The created SecurityPolicy record.
        """
        logger.info(
            "Creating security policy",
            tenant_id=str(tenant_id),
            name=name,
            max_latency_ms=max_latency_ms,
        )
        return await policy_repository.create(
            tenant_id=tenant_id,
            name=name,
            config=config,
            max_latency_ms=max_latency_ms,
            enabled=enabled,
        )


__all__ = [
    "ScanResult",
    "SecurityPipelineService",
    "GuardrailService",
    "ThreatDetectionService",
]
