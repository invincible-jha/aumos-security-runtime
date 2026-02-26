"""API endpoint tests for aumos-security-runtime.

Tests verify the FastAPI route layer:
- Request/response schema validation
- Auth dependency enforcement
- Service delegation

Note: Service dependencies are mocked — these are route-layer tests,
not integration tests. See test_services.py for business logic tests.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from aumos_security_runtime.main import app


@pytest.mark.asyncio
async def test_scan_input_requires_auth() -> None:
    """POST /api/v1/scan/input must return 401 without auth token.

    Auth is enforced by aumos-common middleware. Unauthenticated
    requests must be rejected before reaching the service layer.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/scan/input",
            json={"content": "test content"},
        )

    # 401 Unauthorized (no token provided)
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_scan_input_rejects_empty_content() -> None:
    """POST /api/v1/scan/input must reject empty content with 422.

    Pydantic validation enforces min_length=1 on the content field.
    Empty or missing content must return 422 Unprocessable Entity.
    """
    from aumos_common.auth import get_current_user
    from aumos_common.testing import UserFactory, override_auth_dependency

    user = UserFactory.create()
    app.dependency_overrides[get_current_user] = override_auth_dependency(user)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Empty string content — should fail Pydantic validation
            response = await client.post(
                "/api/v1/scan/input",
                json={"content": ""},
            )

        assert response.status_code == 422
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_create_guardrail_returns_201() -> None:
    """POST /api/v1/guardrails must return 201 Created with the new rule.

    Verifies the route correctly delegates to GuardrailService and
    returns the created rule in the response body.
    """
    from aumos_common.auth import get_current_user
    from aumos_common.testing import UserFactory, override_auth_dependency
    from aumos_security_runtime.core.models import GuardrailRule

    user = UserFactory.create()
    tenant_id = uuid.uuid4()

    mock_rule = MagicMock(spec=GuardrailRule)
    mock_rule.id = uuid.uuid4()
    mock_rule.tenant_id = tenant_id
    mock_rule.name = "test-rule"
    mock_rule.rule_type = "input"
    mock_rule.pattern = r"evil.*pattern"
    mock_rule.action = "block"
    mock_rule.enabled = True

    from datetime import datetime, timezone

    mock_rule.created_at = datetime.now(timezone.utc)

    app.dependency_overrides[get_current_user] = override_auth_dependency(user)

    try:
        with patch(
            "aumos_security_runtime.api.router.GuardrailService.create_rule",
            new_callable=AsyncMock,
            return_value=mock_rule,
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/api/v1/guardrails",
                    json={
                        "name": "test-rule",
                        "rule_type": "input",
                        "pattern": r"evil.*pattern",
                        "action": "block",
                        "enabled": True,
                    },
                )

        assert response.status_code == 201
        body = response.json()
        assert "id" in body
        assert body["name"] == "test-rule"
        assert body["rule_type"] == "input"
        assert body["action"] == "block"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_create_policy_validates_latency_range() -> None:
    """POST /api/v1/policies must reject max_latency_ms below 10 or above 5000.

    Pydantic validation enforces ge=10, le=5000 on max_latency_ms.
    """
    from aumos_common.auth import get_current_user
    from aumos_common.testing import UserFactory, override_auth_dependency

    user = UserFactory.create()
    app.dependency_overrides[get_current_user] = override_auth_dependency(user)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # max_latency_ms = 5 is below the minimum of 10
            response = await client.post(
                "/api/v1/policies",
                json={
                    "name": "test-policy",
                    "config": {},
                    "max_latency_ms": 5,
                    "enabled": True,
                },
            )

        assert response.status_code == 422
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_list_scans_returns_200() -> None:
    """GET /api/v1/scans must return 200 with paginated results.

    With mocked repository returning an empty list, the response
    should still be valid and contain the pagination envelope.
    """
    from aumos_common.auth import get_current_user
    from aumos_common.testing import UserFactory, override_auth_dependency

    user = UserFactory.create()
    app.dependency_overrides[get_current_user] = override_auth_dependency(user)

    try:
        with patch(
            "aumos_security_runtime.adapters.repositories.SecurityScanRepository.list_by_tenant",
            new_callable=AsyncMock,
            return_value=[],
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/v1/scans?page=1&page_size=20")

        assert response.status_code == 200
        body = response.json()
        assert "items" in body
        assert "total" in body
        assert "page" in body
        assert body["page"] == 1
        assert body["page_size"] == 20
    finally:
        app.dependency_overrides.clear()
