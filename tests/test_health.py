"""Basic smoke tests for aumos-security-runtime.

These tests verify the service starts correctly and health endpoints respond.
They run without infrastructure dependencies (no database, no Kafka).
"""

import pytest
from httpx import ASGITransport, AsyncClient

from aumos_security_runtime.main import app


@pytest.mark.asyncio
async def test_liveness_endpoint_returns_200() -> None:
    """Liveness probe must return 200 OK with no dependencies.

    The /live endpoint must never fail due to infrastructure issues —
    it only signals whether the process itself is alive.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/live")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_openapi_schema_is_accessible() -> None:
    """OpenAPI schema endpoint must be accessible in development.

    Verifies the FastAPI app is correctly configured and routes are registered.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert "openapi" in schema
    assert "info" in schema


@pytest.mark.asyncio
async def test_docs_endpoint_is_accessible() -> None:
    """Swagger UI docs endpoint must be accessible.

    Verifies the docs are served correctly for local development.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/docs")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_openapi_schema_has_security_endpoints() -> None:
    """OpenAPI schema must include all required security endpoints.

    Validates that all scan, guardrail, threat, policy, metrics, and
    container-scan routes are correctly registered.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/openapi.json")

    schema = response.json()
    paths = schema.get("paths", {})

    expected_paths = [
        "/api/v1/scan/input",
        "/api/v1/scan/output",
        "/api/v1/scans",
        "/api/v1/guardrails",
        "/api/v1/threats",
        "/api/v1/policies",
        "/api/v1/metrics",
        "/api/v1/container-scan",
    ]

    for path in expected_paths:
        assert path in paths, f"Expected endpoint {path} not found in OpenAPI schema"
