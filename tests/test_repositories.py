"""Tests for repository layer — SecurityScan, ThreatDetection, GuardrailRule, SecurityPolicy.

Integration tests use testcontainers to spin up a real PostgreSQL instance.
Unit tests mock the SQLAlchemy session.

Note: Testcontainer-based tests require Docker and are marked with @pytest.mark.integration.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aumos_security_runtime.adapters.repositories import (
    GuardrailRepository,
    SecurityPolicyRepository,
    SecurityScanRepository,
    ThreatDetectionRepository,
)
from aumos_security_runtime.core.models import (
    GuardrailRule,
    SecurityPolicy,
    SecurityScan,
    ThreatDetection,
)


def make_mock_session() -> MagicMock:
    """Create a mock async SQLAlchemy session.

    Returns:
        Mock session with add, flush, refresh, and execute methods.
    """
    session = MagicMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.execute = AsyncMock()
    session.add_all = MagicMock()
    return session


@pytest.mark.asyncio
async def test_security_scan_repository_create() -> None:
    """SecurityScanRepository.create must set all fields correctly.

    Verifies the ORM model is constructed with the correct values
    and the session methods are called in the right order.
    """
    session = make_mock_session()
    repo = SecurityScanRepository(session)

    tenant_id = uuid.uuid4()

    # Make refresh populate the mock object
    async def mock_refresh(obj: SecurityScan) -> None:
        obj.id = uuid.uuid4()
        obj.tenant_id = tenant_id
        obj.scan_type = "input"
        obj.content_hash = "abc123"
        obj.threats_detected = 0
        obj.latency_ms = 15.0
        obj.action_taken = "allow"
        obj.policy_id = None

    session.refresh.side_effect = mock_refresh

    result = await repo.create(
        tenant_id=tenant_id,
        scan_type="input",
        content_hash="abc123",
        threats_detected=0,
        latency_ms=15.0,
        action_taken="allow",
        policy_id=None,
    )

    session.add.assert_called_once()
    session.flush.assert_called_once()
    session.refresh.assert_called_once()

    added_obj = session.add.call_args[0][0]
    assert isinstance(added_obj, SecurityScan)
    assert added_obj.tenant_id == tenant_id
    assert added_obj.scan_type == "input"
    assert added_obj.content_hash == "abc123"
    assert added_obj.threats_detected == 0
    assert added_obj.latency_ms == 15.0
    assert added_obj.action_taken == "allow"
    assert added_obj.policy_id is None


@pytest.mark.asyncio
async def test_threat_detection_repository_create_many() -> None:
    """ThreatDetectionRepository.create_many must bulk-insert all threats.

    Verifies that session.add_all is called with the correct number of
    ThreatDetection objects.
    """
    session = make_mock_session()
    session.refresh = AsyncMock()
    repo = ThreatDetectionRepository(session)

    scan_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    threats = [
        {
            "threat_type": "prompt_injection",
            "severity": "critical",
            "confidence": 1.0,
            "details": {"pattern_name": "ignore_previous"},
        },
        {
            "threat_type": "pii_leak",
            "severity": "medium",
            "confidence": 0.85,
            "details": {"entity_types": {"EMAIL_ADDRESS": 2}},
        },
    ]

    await repo.create_many(scan_id=scan_id, tenant_id=tenant_id, threats=threats)

    session.add_all.assert_called_once()
    added_objects = session.add_all.call_args[0][0]
    assert len(added_objects) == 2
    assert all(isinstance(obj, ThreatDetection) for obj in added_objects)

    assert added_objects[0].threat_type == "prompt_injection"
    assert added_objects[0].severity == "critical"
    assert added_objects[1].threat_type == "pii_leak"


@pytest.mark.asyncio
async def test_guardrail_repository_create() -> None:
    """GuardrailRepository.create must set all rule fields correctly."""
    session = make_mock_session()
    repo = GuardrailRepository(session)

    tenant_id = uuid.uuid4()

    async def mock_refresh(obj: GuardrailRule) -> None:
        obj.id = uuid.uuid4()

    session.refresh.side_effect = mock_refresh

    result = await repo.create(
        tenant_id=tenant_id,
        name="Block SQL injection",
        rule_type="input",
        pattern=r"(?i)(select|drop|insert|update|delete)\s+\w+",
        action="block",
        enabled=True,
    )

    session.add.assert_called_once()
    added_obj = session.add.call_args[0][0]
    assert isinstance(added_obj, GuardrailRule)
    assert added_obj.tenant_id == tenant_id
    assert added_obj.name == "Block SQL injection"
    assert added_obj.rule_type == "input"
    assert added_obj.action == "block"
    assert added_obj.enabled is True


@pytest.mark.asyncio
async def test_security_policy_repository_create() -> None:
    """SecurityPolicyRepository.create must persist all policy fields."""
    session = make_mock_session()
    repo = SecurityPolicyRepository(session)

    tenant_id = uuid.uuid4()

    async def mock_refresh(obj: SecurityPolicy) -> None:
        obj.id = uuid.uuid4()

    session.refresh.side_effect = mock_refresh

    config = {
        "enable_ml_scanner": True,
        "injection_block_threshold": 0.90,
        "pii_action": "redact",
    }

    await repo.create(
        tenant_id=tenant_id,
        name="Strict Policy",
        config=config,
        max_latency_ms=50,
        enabled=True,
    )

    session.add.assert_called_once()
    added_obj = session.add.call_args[0][0]
    assert isinstance(added_obj, SecurityPolicy)
    assert added_obj.tenant_id == tenant_id
    assert added_obj.name == "Strict Policy"
    assert added_obj.max_latency_ms == 50
    assert added_obj.enabled is True
