"""Shared test fixtures for aumos-security-runtime.

Import standard fixtures from aumos_common.testing where available.
Override auth dependencies in endpoint tests using override_auth_dependency.
"""

import uuid
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from aumos_common.auth import get_current_user
from aumos_common.testing import UserFactory, override_auth_dependency

from aumos_security_runtime.main import app


@pytest.fixture
def mock_user() -> UserFactory:
    """Create a test user with default permissions.

    Returns:
        A UserFactory instance suitable for auth override.
    """
    return UserFactory.create()


@pytest.fixture
def mock_tenant_id() -> uuid.UUID:
    """Create a fixed tenant UUID for tests.

    Returns:
        A consistent UUID for use in test assertions.
    """
    return uuid.UUID("550e8400-e29b-41d4-a716-446655440000")


@pytest.fixture
async def client(mock_user: UserFactory) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client with auth overrides applied.

    Args:
        mock_user: The test user fixture for auth override.

    Yields:
        Configured HTTPX AsyncClient for test requests.
    """
    app.dependency_overrides[get_current_user] = override_auth_dependency(mock_user)
    async with AsyncClient(app=app, base_url="http://test") as async_client:
        yield async_client
    app.dependency_overrides.clear()


@pytest.fixture
def mock_pattern_scanner() -> MagicMock:
    """Mock PatternScanner that returns no threats by default.

    Returns:
        Mock pattern scanner with async scan() method.
    """
    scanner = MagicMock()
    scanner.scan = AsyncMock(return_value=[])
    scanner.initialize = AsyncMock()
    return scanner


@pytest.fixture
def mock_ml_scanner() -> MagicMock:
    """Mock MLScanner that returns no threats by default.

    Returns:
        Mock ML scanner with async scan() method.
    """
    from aumos_security_runtime.adapters.prompt_injection.ml_scanner import MLScanResult

    scanner = MagicMock()
    scanner.scan = AsyncMock(
        return_value=MLScanResult(
            is_threat=False,
            confidence=0.1,
            details={"method": "ml_scanner", "status": "mocked"},
        )
    )
    scanner.initialize = AsyncMock()
    return scanner


@pytest.fixture
def mock_pii_scanner() -> MagicMock:
    """Mock PIIScanner that returns no PII by default.

    Returns:
        Mock PII scanner with async scan() and redact() methods.
    """
    scanner = MagicMock()
    scanner.scan = AsyncMock(return_value=[])
    scanner.redact = AsyncMock(side_effect=lambda content: content)
    scanner.initialize = AsyncMock()
    return scanner


@pytest.fixture
def mock_scan_repository() -> MagicMock:
    """Mock SecurityScanRepository.

    Returns:
        Mock repository with async create() and list_by_tenant() methods.
    """
    import uuid
    from unittest.mock import MagicMock

    from aumos_security_runtime.core.models import SecurityScan

    mock_scan = MagicMock(spec=SecurityScan)
    mock_scan.id = uuid.uuid4()
    mock_scan.tenant_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
    mock_scan.scan_type = "input"
    mock_scan.content_hash = "abc123"
    mock_scan.threats_detected = 0
    mock_scan.latency_ms = 15.0
    mock_scan.action_taken = "allow"
    mock_scan.policy_id = None

    repo = MagicMock()
    repo.create = AsyncMock(return_value=mock_scan)
    repo.list_by_tenant = AsyncMock(return_value=[])
    return repo


@pytest.fixture
def mock_threat_repository() -> MagicMock:
    """Mock ThreatDetectionRepository.

    Returns:
        Mock repository with async create_many() and list_by_tenant() methods.
    """
    repo = MagicMock()
    repo.create_many = AsyncMock(return_value=[])
    repo.list_by_tenant = AsyncMock(return_value=[])
    return repo


@pytest.fixture
def mock_policy_repository() -> MagicMock:
    """Mock SecurityPolicyRepository.

    Returns:
        Mock repository with async create() and get_by_id() methods.
    """
    repo = MagicMock()
    repo.create = AsyncMock()
    repo.get_by_id = AsyncMock(return_value=None)
    return repo
