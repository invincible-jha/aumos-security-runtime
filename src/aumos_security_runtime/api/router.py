"""API router for aumos-security-runtime.

All endpoints are registered here and included in main.py under /api/v1.
Routes delegate all logic to service layer — no business logic in routes.

Endpoints:
  POST /scan/input          — Scan LLM input, must be <50ms
  POST /scan/output         — Scan LLM output for data extraction
  GET  /scans               — List security scans (paginated)
  POST /guardrails          — Create guardrail rule
  GET  /guardrails          — List guardrail rules
  GET  /threats             — List threat detections (paginated)
  POST /policies            — Create security policy
  GET  /metrics             — Security metrics (detection rate, latency percentiles)
  POST /container-scan      — Trigger Trivy container vulnerability scan
"""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext, get_current_user
from aumos_common.database import get_db_session
from aumos_common.observability import get_logger

from aumos_security_runtime.adapters.repositories import (
    GuardrailRepository,
    SecurityPolicyRepository,
    SecurityScanRepository,
    ThreatDetectionRepository,
)
from aumos_security_runtime.api.schemas import (
    ContainerScanRequest,
    ContainerScanResponse,
    GuardrailCreateRequest,
    GuardrailListResponse,
    GuardrailResponse,
    LatencyPercentiles,
    ScanInputRequest,
    ScanInputResponse,
    ScanOutputRequest,
    ScanOutputResponse,
    SecurityMetricsResponse,
    SecurityPolicyCreateRequest,
    SecurityPolicyResponse,
    SecurityScanListResponse,
    SecurityScanResponse,
    ThreatDetectionListResponse,
    ThreatDetectionResponse,
    ThreatResult,
)
from aumos_security_runtime.core.services import (
    GuardrailService,
    SecurityPipelineService,
    ThreatDetectionService,
)

logger = get_logger(__name__)

router = APIRouter(tags=["security-runtime"])


def _get_pipeline_service(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> SecurityPipelineService:
    """Build SecurityPipelineService with request-scoped dependencies.

    Scanners are loaded from app.state (pre-initialized at startup).
    Repositories are scoped to the current DB session.

    Args:
        request: FastAPI request (to access app.state scanners).
        session: Async DB session from dependency injection.

    Returns:
        Configured SecurityPipelineService.
    """
    from aumos_security_runtime.main import settings

    return SecurityPipelineService(
        scan_repository=SecurityScanRepository(session),
        threat_repository=ThreatDetectionRepository(session),
        policy_repository=SecurityPolicyRepository(session),
        pattern_scanner=request.app.state.pattern_scanner,
        ml_scanner=getattr(request.app.state, "ml_scanner", None),
        pii_scanner=getattr(request.app.state, "pii_scanner", None),
        event_publisher=None,  # TODO: inject Kafka publisher from app.state
        max_latency_ms=settings.max_latency_ms,
        injection_block_threshold=settings.injection_block_threshold,
        injection_warn_threshold=settings.injection_warn_threshold,
    )


@router.post(
    "/scan/input",
    response_model=ScanInputResponse,
    summary="Scan LLM input for security threats",
    description="Scans LLM input content for prompt injection, PII, and other threats. "
    "Target latency: <50ms P95. Short-circuits on critical threats.",
)
async def scan_input(
    body: ScanInputRequest,
    tenant: TenantContext = Depends(get_current_user),
    pipeline: SecurityPipelineService = Depends(_get_pipeline_service),
) -> ScanInputResponse:
    """Scan LLM input content for security threats.

    Runs all enabled scanners in parallel to stay within the 50ms latency budget.
    Returns a block/warn/allow/redact decision with threat details.

    Args:
        body: Request body containing content to scan.
        tenant: Authenticated tenant context.
        pipeline: Security pipeline service (injected).

    Returns:
        ScanInputResponse with the security decision and threat details.
    """
    result = await pipeline.scan_input(
        tenant_id=tenant.tenant_id,
        content=body.content,
        policy_id=body.policy_id,
    )

    return ScanInputResponse(
        scan_id=result.scan_id,
        allowed=result.allowed,
        action=result.action,
        threats=[
            ThreatResult(
                threat_type=t["threat_type"],
                severity=t["severity"],
                confidence=t["confidence"],
                details=t["details"],
            )
            for t in result.threats
        ],
        redacted_content=result.redacted_content,
        latency_ms=result.latency_ms,
        scan_type=result.scan_type,
    )


@router.post(
    "/scan/output",
    response_model=ScanOutputResponse,
    summary="Scan LLM output for data extraction and toxicity",
    description="Scans LLM output content for data extraction attempts, PII leakage, "
    "and toxicity. Runs asynchronously after model response is received.",
)
async def scan_output(
    body: ScanOutputRequest,
    tenant: TenantContext = Depends(get_current_user),
    pipeline: SecurityPipelineService = Depends(_get_pipeline_service),
) -> ScanOutputResponse:
    """Scan LLM output content for data extraction and toxicity threats.

    Args:
        body: Request body containing LLM output to scan.
        tenant: Authenticated tenant context.
        pipeline: Security pipeline service (injected).

    Returns:
        ScanOutputResponse with the security decision and threat details.
    """
    result = await pipeline.scan_output(
        tenant_id=tenant.tenant_id,
        content=body.content,
        policy_id=body.policy_id,
    )

    return ScanOutputResponse(
        scan_id=result.scan_id,
        allowed=result.allowed,
        action=result.action,
        threats=[
            ThreatResult(
                threat_type=t["threat_type"],
                severity=t["severity"],
                confidence=t["confidence"],
                details=t["details"],
            )
            for t in result.threats
        ],
        redacted_content=result.redacted_content,
        latency_ms=result.latency_ms,
        scan_type=result.scan_type,
    )


@router.get(
    "/scans",
    response_model=SecurityScanListResponse,
    summary="List security scans",
    description="Returns a paginated list of security scan records for the current tenant.",
)
async def list_scans(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Records per page"),
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> SecurityScanListResponse:
    """List security scans for the current tenant.

    Args:
        page: Page number (1-indexed).
        page_size: Records per page.
        tenant: Authenticated tenant context.
        session: Async DB session.

    Returns:
        Paginated SecurityScanListResponse.
    """
    service = ThreatDetectionService(
        threat_repository=ThreatDetectionRepository(session),
        scan_repository=SecurityScanRepository(session),
    )
    scans = await service.list_scans(tenant_id=tenant.tenant_id, page=page, page_size=page_size)

    return SecurityScanListResponse(
        items=[
            SecurityScanResponse(
                id=scan.id,
                tenant_id=scan.tenant_id,
                scan_type=scan.scan_type,
                content_hash=scan.content_hash,
                threats_detected=scan.threats_detected,
                latency_ms=scan.latency_ms,
                action_taken=scan.action_taken,
                policy_id=scan.policy_id,
                created_at=scan.created_at,
            )
            for scan in scans
        ],
        total=len(scans),
        page=page,
        page_size=page_size,
    )


@router.post(
    "/guardrails",
    response_model=GuardrailResponse,
    status_code=201,
    summary="Create a guardrail rule",
    description="Creates a tenant-specific guardrail rule to supplement platform defaults.",
)
async def create_guardrail(
    body: GuardrailCreateRequest,
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> GuardrailResponse:
    """Create a guardrail rule for the current tenant.

    Args:
        body: Guardrail rule creation request.
        tenant: Authenticated tenant context.
        session: Async DB session.

    Returns:
        The created GuardrailResponse.
    """
    service = GuardrailService(repository=GuardrailRepository(session))
    rule = await service.create_rule(
        tenant_id=tenant.tenant_id,
        name=body.name,
        rule_type=body.rule_type,
        pattern=body.pattern,
        action=body.action,
        enabled=body.enabled,
    )

    return GuardrailResponse(
        id=rule.id,
        tenant_id=rule.tenant_id,
        name=rule.name,
        rule_type=rule.rule_type,
        pattern=rule.pattern,
        action=rule.action,
        enabled=rule.enabled,
        created_at=rule.created_at,
    )


@router.get(
    "/guardrails",
    response_model=GuardrailListResponse,
    summary="List guardrail rules",
    description="Returns all guardrail rules for the current tenant.",
)
async def list_guardrails(
    rule_type: str | None = Query(default=None, description="Filter by input or output"),
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> GuardrailListResponse:
    """List guardrail rules for the current tenant.

    Args:
        rule_type: Optional filter by input/output stage.
        tenant: Authenticated tenant context.
        session: Async DB session.

    Returns:
        GuardrailListResponse with all matching rules.
    """
    service = GuardrailService(repository=GuardrailRepository(session))
    rules = await service.list_rules(tenant_id=tenant.tenant_id, rule_type=rule_type)

    return GuardrailListResponse(
        items=[
            GuardrailResponse(
                id=rule.id,
                tenant_id=rule.tenant_id,
                name=rule.name,
                rule_type=rule.rule_type,
                pattern=rule.pattern,
                action=rule.action,
                enabled=rule.enabled,
                created_at=rule.created_at,
            )
            for rule in rules
        ],
        total=len(rules),
    )


@router.get(
    "/threats",
    response_model=ThreatDetectionListResponse,
    summary="List threat detections",
    description="Returns a paginated list of threat detections for the current tenant.",
)
async def list_threats(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Records per page"),
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatDetectionListResponse:
    """List threat detections for the current tenant.

    Args:
        page: Page number (1-indexed).
        page_size: Records per page.
        tenant: Authenticated tenant context.
        session: Async DB session.

    Returns:
        Paginated ThreatDetectionListResponse.
    """
    service = ThreatDetectionService(
        threat_repository=ThreatDetectionRepository(session),
        scan_repository=SecurityScanRepository(session),
    )
    threats = await service.list_threats(tenant_id=tenant.tenant_id, page=page, page_size=page_size)

    return ThreatDetectionListResponse(
        items=[
            ThreatDetectionResponse(
                id=threat.id,
                tenant_id=threat.tenant_id,
                scan_id=threat.scan_id,
                threat_type=threat.threat_type,
                severity=threat.severity,
                confidence=threat.confidence,
                details=threat.details,
                created_at=threat.created_at,
            )
            for threat in threats
        ],
        total=len(threats),
        page=page,
        page_size=page_size,
    )


@router.post(
    "/policies",
    response_model=SecurityPolicyResponse,
    status_code=201,
    summary="Create a security policy",
    description="Creates a tenant security policy that governs scan behavior and thresholds.",
)
async def create_policy(
    body: SecurityPolicyCreateRequest,
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> SecurityPolicyResponse:
    """Create a security policy for the current tenant.

    Args:
        body: Policy creation request.
        tenant: Authenticated tenant context.
        session: Async DB session.

    Returns:
        The created SecurityPolicyResponse.
    """
    service = ThreatDetectionService(
        threat_repository=ThreatDetectionRepository(session),
        scan_repository=SecurityScanRepository(session),
    )
    policy = await service.create_policy(
        tenant_id=tenant.tenant_id,
        name=body.name,
        config=body.config,
        max_latency_ms=body.max_latency_ms,
        enabled=body.enabled,
        policy_repository=SecurityPolicyRepository(session),
    )

    return SecurityPolicyResponse(
        id=policy.id,
        tenant_id=policy.tenant_id,
        name=policy.name,
        config=policy.config,
        max_latency_ms=policy.max_latency_ms,
        enabled=policy.enabled,
        created_at=policy.created_at,
    )


@router.get(
    "/metrics",
    response_model=SecurityMetricsResponse,
    summary="Get security metrics",
    description="Returns security metrics including detection rates and latency percentiles "
    "(P50/P95/P99) for the current tenant.",
)
async def get_metrics(
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> SecurityMetricsResponse:
    """Get security metrics for the current tenant.

    Returns detection rates, block rates, and latency percentiles.
    Metrics are computed over the last 24 hours by default.

    Args:
        tenant: Authenticated tenant context.
        session: Async DB session.

    Returns:
        SecurityMetricsResponse with rates and latency statistics.
    """
    from aumos_security_runtime.adapters.repositories import MetricsRepository

    metrics_repo = MetricsRepository(session)
    raw_metrics: dict[str, Any] = await metrics_repo.get_tenant_metrics(tenant_id=tenant.tenant_id)

    return SecurityMetricsResponse(
        total_scans=raw_metrics.get("total_scans", 0),
        total_threats=raw_metrics.get("total_threats", 0),
        detection_rate=raw_metrics.get("detection_rate", 0.0),
        block_rate=raw_metrics.get("block_rate", 0.0),
        latency=LatencyPercentiles(
            p50=raw_metrics.get("latency_p50", 0.0),
            p95=raw_metrics.get("latency_p95", 0.0),
            p99=raw_metrics.get("latency_p99", 0.0),
        ),
        scans_by_type=raw_metrics.get("scans_by_type", {}),
        threats_by_type=raw_metrics.get("threats_by_type", {}),
    )


@router.post(
    "/container-scan",
    response_model=ContainerScanResponse,
    summary="Trigger container vulnerability scan",
    description="Triggers a Trivy-based container vulnerability scan for a given image reference. "
    "Requires AUMOS_SECRUNTIME_TRIVY_ENDPOINT to be configured.",
)
async def trigger_container_scan(
    body: ContainerScanRequest,
    tenant: TenantContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ContainerScanResponse:
    """Trigger a Trivy container vulnerability scan.

    Calls the configured Trivy server to scan a container image and
    stores the results as a SecurityScan record.

    Args:
        body: Container scan request with image reference.
        tenant: Authenticated tenant context.
        session: Async DB session.

    Returns:
        ContainerScanResponse with vulnerability findings.
    """
    from aumos_security_runtime.adapters.container_scanner import ContainerScanner
    from aumos_security_runtime.main import settings

    scanner = ContainerScanner(trivy_endpoint=settings.trivy_endpoint)
    scan_result = await scanner.scan_image(
        image_ref=body.image_ref,
        registry=body.registry,
        severity_threshold=body.severity_threshold,
    )

    scan_repo = SecurityScanRepository(session)
    import hashlib

    content_hash = hashlib.sha256(body.image_ref.encode()).hexdigest()
    scan_record = await scan_repo.create(
        tenant_id=tenant.tenant_id,
        scan_type="container",
        content_hash=content_hash,
        threats_detected=scan_result["total_vulnerabilities"],
        latency_ms=scan_result.get("latency_ms", 0.0),
        action_taken="allow" if scan_result["status"] == "passed" else "warn",
        policy_id=None,
    )

    return ContainerScanResponse(
        scan_id=scan_record.id,
        image_ref=body.image_ref,
        vulnerabilities=scan_result.get("vulnerabilities", []),
        total_vulnerabilities=scan_result["total_vulnerabilities"],
        critical_count=scan_result.get("critical_count", 0),
        high_count=scan_result.get("high_count", 0),
        status=scan_result["status"],
    )
