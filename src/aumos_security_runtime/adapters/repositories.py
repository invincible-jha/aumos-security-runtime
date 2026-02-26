"""SQLAlchemy repository implementations for aumos-security-runtime.

Repositories extend BaseRepository from aumos-common which provides:
  - Automatic RLS tenant isolation (set_tenant_context)
  - Standard CRUD operations (get, list, create, update, delete)
  - Pagination support via paginate()

Table prefix: sec_
"""

import uuid
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.database import BaseRepository
from aumos_common.observability import get_logger

from aumos_security_runtime.core.interfaces import (
    IGuardrailRepository,
    ISecurityPolicyRepository,
    ISecurityScanRepository,
    IThreatDetectionRepository,
)
from aumos_security_runtime.core.models import (
    GuardrailRule,
    SecurityPolicy,
    SecurityScan,
    ThreatDetection,
)

logger = get_logger(__name__)


class SecurityScanRepository(BaseRepository, ISecurityScanRepository):
    """Repository for SecurityScan records (sec_security_scans).

    Args:
        session: Async SQLAlchemy session injected by FastAPI.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with async database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

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
            tenant_id: Owning tenant.
            scan_type: Type of scan (input/output/container).
            content_hash: SHA-256 hash of scanned content.
            threats_detected: Number of threats found.
            latency_ms: Total scan latency.
            action_taken: Enforcement action applied.
            policy_id: Optional security policy UUID.

        Returns:
            The created SecurityScan ORM instance.
        """
        scan = SecurityScan(
            tenant_id=tenant_id,
            scan_type=scan_type,
            content_hash=content_hash,
            threats_detected=threats_detected,
            latency_ms=latency_ms,
            action_taken=action_taken,
            policy_id=policy_id,
        )
        self.session.add(scan)
        await self.session.flush()
        await self.session.refresh(scan)
        return scan

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> list[SecurityScan]:
        """List security scans for a tenant with pagination.

        Args:
            tenant_id: Tenant to filter by.
            page: Page number (1-indexed).
            page_size: Records per page.

        Returns:
            List of SecurityScan records for the tenant.
        """
        offset = (page - 1) * page_size
        result = await self.session.execute(
            select(SecurityScan)
            .where(SecurityScan.tenant_id == tenant_id)
            .order_by(SecurityScan.created_at.desc())
            .limit(page_size)
            .offset(offset)
        )
        return list(result.scalars().all())


class ThreatDetectionRepository(BaseRepository, IThreatDetectionRepository):
    """Repository for ThreatDetection records (sec_threat_detections).

    Args:
        session: Async SQLAlchemy session injected by FastAPI.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with async database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def create_many(
        self,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        threats: list[dict[str, Any]],
    ) -> list[ThreatDetection]:
        """Bulk-create threat detection records for a scan.

        Args:
            scan_id: Associated scan UUID.
            tenant_id: Owning tenant.
            threats: List of threat data dicts.

        Returns:
            List of created ThreatDetection records.
        """
        records = [
            ThreatDetection(
                tenant_id=tenant_id,
                scan_id=scan_id,
                threat_type=threat["threat_type"],
                severity=threat["severity"],
                confidence=threat["confidence"],
                details=threat.get("details", {}),
            )
            for threat in threats
        ]
        self.session.add_all(records)
        await self.session.flush()
        for record in records:
            await self.session.refresh(record)
        return records

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> list[ThreatDetection]:
        """List threat detections for a tenant with pagination.

        Args:
            tenant_id: Tenant to filter by.
            page: Page number (1-indexed).
            page_size: Records per page.

        Returns:
            List of ThreatDetection records.
        """
        offset = (page - 1) * page_size
        result = await self.session.execute(
            select(ThreatDetection)
            .where(ThreatDetection.tenant_id == tenant_id)
            .order_by(ThreatDetection.created_at.desc())
            .limit(page_size)
            .offset(offset)
        )
        return list(result.scalars().all())


class GuardrailRepository(BaseRepository, IGuardrailRepository):
    """Repository for GuardrailRule records (sec_guardrail_rules).

    Args:
        session: Async SQLAlchemy session injected by FastAPI.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with async database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

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
            tenant_id: Owning tenant.
            name: Human-readable rule name.
            rule_type: Input or output stage.
            pattern: Regex pattern string.
            action: Enforcement action.
            enabled: Whether the rule is active.

        Returns:
            The created GuardrailRule record.
        """
        rule = GuardrailRule(
            tenant_id=tenant_id,
            name=name,
            rule_type=rule_type,
            pattern=pattern,
            action=action,
            enabled=enabled,
        )
        self.session.add(rule)
        await self.session.flush()
        await self.session.refresh(rule)
        return rule

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        rule_type: str | None,
    ) -> list[GuardrailRule]:
        """List guardrail rules for a tenant.

        Args:
            tenant_id: Owning tenant.
            rule_type: Optional filter by input/output type.

        Returns:
            List of GuardrailRule records.
        """
        query = (
            select(GuardrailRule)
            .where(GuardrailRule.tenant_id == tenant_id)
            .where(GuardrailRule.enabled.is_(True))
            .order_by(GuardrailRule.created_at.asc())
        )
        if rule_type is not None:
            query = query.where(GuardrailRule.rule_type == rule_type)

        result = await self.session.execute(query)
        return list(result.scalars().all())


class SecurityPolicyRepository(BaseRepository, ISecurityPolicyRepository):
    """Repository for SecurityPolicy records (sec_security_policies).

    Args:
        session: Async SQLAlchemy session injected by FastAPI.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with async database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

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
            tenant_id: Owning tenant.
            name: Policy name.
            config: JSONB policy configuration.
            max_latency_ms: Maximum allowed scan latency.
            enabled: Whether the policy is active.

        Returns:
            The created SecurityPolicy record.
        """
        policy = SecurityPolicy(
            tenant_id=tenant_id,
            name=name,
            config=config,
            max_latency_ms=max_latency_ms,
            enabled=enabled,
        )
        self.session.add(policy)
        await self.session.flush()
        await self.session.refresh(policy)
        return policy

    async def get_by_id(
        self,
        policy_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> SecurityPolicy | None:
        """Retrieve a policy by ID within a tenant scope.

        Args:
            policy_id: Policy UUID.
            tenant_id: Owning tenant.

        Returns:
            The SecurityPolicy or None.
        """
        result = await self.session.execute(
            select(SecurityPolicy)
            .where(SecurityPolicy.id == policy_id)
            .where(SecurityPolicy.tenant_id == tenant_id)
        )
        return result.scalar_one_or_none()


class MetricsRepository:
    """Repository for computing security metrics using aggregate queries.

    Uses raw SQL aggregates for performance. Does not bypass RLS —
    all queries filter by tenant_id explicitly.

    Args:
        session: Async SQLAlchemy session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with async database session.

        Args:
            session: Async SQLAlchemy session.
        """
        self.session = session

    async def get_tenant_metrics(self, tenant_id: uuid.UUID) -> dict[str, Any]:
        """Compute security metrics for a tenant over the last 24 hours.

        Args:
            tenant_id: Tenant to compute metrics for.

        Returns:
            Dict with metrics: total_scans, detection_rate, latency percentiles, etc.
        """
        # Aggregate scan metrics
        scan_result = await self.session.execute(
            text("""
                SELECT
                    COUNT(*) AS total_scans,
                    SUM(CASE WHEN threats_detected > 0 THEN 1 ELSE 0 END) AS scans_with_threats,
                    SUM(CASE WHEN action_taken = 'block' THEN 1 ELSE 0 END) AS blocked_scans,
                    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms) AS p50,
                    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95,
                    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms) AS p99
                FROM sec_security_scans
                WHERE tenant_id = :tenant_id
                  AND created_at >= NOW() - INTERVAL '24 hours'
            """),
            {"tenant_id": str(tenant_id)},
        )
        row = scan_result.fetchone()

        total_scans = row.total_scans or 0
        scans_with_threats = row.scans_with_threats or 0
        blocked_scans = row.blocked_scans or 0

        # Aggregate threat type breakdown
        threat_result = await self.session.execute(
            text("""
                SELECT threat_type, COUNT(*) AS threat_count
                FROM sec_threat_detections
                WHERE tenant_id = :tenant_id
                  AND created_at >= NOW() - INTERVAL '24 hours'
                GROUP BY threat_type
            """),
            {"tenant_id": str(tenant_id)},
        )
        threats_by_type: dict[str, int] = {row.threat_type: row.threat_count for row in threat_result}
        total_threats = sum(threats_by_type.values())

        # Aggregate scan type breakdown
        scan_type_result = await self.session.execute(
            text("""
                SELECT scan_type, COUNT(*) AS scan_count
                FROM sec_security_scans
                WHERE tenant_id = :tenant_id
                  AND created_at >= NOW() - INTERVAL '24 hours'
                GROUP BY scan_type
            """),
            {"tenant_id": str(tenant_id)},
        )
        scans_by_type: dict[str, int] = {row.scan_type: row.scan_count for row in scan_type_result}

        return {
            "total_scans": total_scans,
            "total_threats": total_threats,
            "detection_rate": scans_with_threats / total_scans if total_scans > 0 else 0.0,
            "block_rate": blocked_scans / total_scans if total_scans > 0 else 0.0,
            "latency_p50": float(row.p50 or 0.0),
            "latency_p95": float(row.p95 or 0.0),
            "latency_p99": float(row.p99 or 0.0),
            "scans_by_type": scans_by_type,
            "threats_by_type": threats_by_type,
        }
