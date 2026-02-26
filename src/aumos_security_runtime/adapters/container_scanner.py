"""Trivy container scanning integration.

Integrates with a Trivy server (trivy server mode) to scan container images
for known CVEs and security vulnerabilities. Trivy is Apache 2.0 licensed.

Trivy server mode is used (not CLI) to avoid subprocess spawning latency
and to reuse the vulnerability database across scans.

Setup: Run Trivy in server mode:
  trivy server --listen 0.0.0.0:4954

Configure endpoint via:
  AUMOS_SECRUNTIME_TRIVY_ENDPOINT=http://trivy-server:4954

Container scans are not subject to the <50ms latency budget —
they run asynchronously and are typically triggered by CI/CD pipelines
or on-demand via the /container-scan API endpoint.
"""

import time
from typing import Any

import httpx

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class ContainerScanner:
    """Trivy-based container vulnerability scanner.

    Calls the Trivy server REST API to scan a container image and
    returns structured vulnerability results.

    Args:
        trivy_endpoint: Base URL of the Trivy server (e.g., http://trivy:4954).
        timeout_seconds: HTTP request timeout in seconds (default 300).
    """

    def __init__(
        self,
        trivy_endpoint: str,
        timeout_seconds: int = 300,
    ) -> None:
        """Initialize the container scanner.

        Args:
            trivy_endpoint: Trivy server URL.
            timeout_seconds: Timeout for scan requests.
        """
        self._trivy_endpoint = trivy_endpoint
        self._timeout_seconds = timeout_seconds

    async def scan_image(
        self,
        image_ref: str,
        registry: str | None = None,
        severity_threshold: str = "HIGH",
    ) -> dict[str, Any]:
        """Scan a container image for vulnerabilities using Trivy.

        Args:
            image_ref: Container image reference (e.g., myrepo/myimage:latest).
            registry: Optional registry URL override.
            severity_threshold: Minimum severity to include in results.

        Returns:
            Dict with vulnerability findings and summary statistics.

        Raises:
            RuntimeError: If Trivy endpoint is not configured.
            httpx.HTTPError: If the Trivy server request fails.
        """
        if not self._trivy_endpoint:
            raise RuntimeError(
                "Container scanning is not configured. "
                "Set AUMOS_SECRUNTIME_TRIVY_ENDPOINT to enable."
            )

        logger.info(
            "Starting container scan",
            image_ref=image_ref,
            severity_threshold=severity_threshold,
        )

        start_time = time.perf_counter()

        # Trivy server scan request
        scan_url = f"{self._trivy_endpoint}/scan"
        request_body: dict[str, Any] = {
            "image": image_ref,
            "severity": severity_threshold,
        }
        if registry:
            request_body["registry"] = registry

        async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
            response = await client.post(scan_url, json=request_body)
            response.raise_for_status()
            trivy_response = response.json()

        latency_ms = (time.perf_counter() - start_time) * 1000

        # Parse Trivy response format
        vulnerabilities = self._parse_trivy_response(trivy_response)

        critical_count = sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")
        total_vulnerabilities = len(vulnerabilities)

        # Determine pass/fail status
        status = "passed" if critical_count == 0 and high_count == 0 else "failed"

        logger.info(
            "Container scan complete",
            image_ref=image_ref,
            total_vulnerabilities=total_vulnerabilities,
            critical_count=critical_count,
            high_count=high_count,
            status=status,
            latency_ms=round(latency_ms, 2),
        )

        return {
            "vulnerabilities": vulnerabilities,
            "total_vulnerabilities": total_vulnerabilities,
            "critical_count": critical_count,
            "high_count": high_count,
            "status": status,
            "latency_ms": latency_ms,
        }

    def _parse_trivy_response(self, trivy_response: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse the Trivy server response into structured vulnerability records.

        Trivy's response format may vary by version. This method handles
        the common format from trivy server mode.

        Args:
            trivy_response: Raw JSON response from Trivy server.

        Returns:
            List of normalized vulnerability records.
        """
        vulnerabilities: list[dict[str, Any]] = []

        # Handle Trivy server response format
        results = trivy_response.get("Results", trivy_response.get("results", []))
        for result_group in results:
            group_vulns = result_group.get("Vulnerabilities", result_group.get("vulnerabilities", []))
            if not group_vulns:
                continue

            for vuln in group_vulns:
                vulnerabilities.append(
                    {
                        "vulnerability_id": vuln.get("VulnerabilityID", vuln.get("vulnerability_id", "UNKNOWN")),
                        "severity": vuln.get("Severity", vuln.get("severity", "UNKNOWN")).upper(),
                        "package_name": vuln.get("PkgName", vuln.get("package_name", "unknown")),
                        "installed_version": vuln.get(
                            "InstalledVersion", vuln.get("installed_version", "unknown")
                        ),
                        "fixed_version": vuln.get("FixedVersion", vuln.get("fixed_version")),
                        "description": vuln.get("Description", vuln.get("description", ""))[:500],
                    }
                )

        return vulnerabilities
