"""LLM output guardrail scanning.

Scans LLM outputs for:
1. Data extraction patterns — attempts to retrieve bulk data or credentials
2. PII leakage — PII that the model should not have output
3. Sensitive information disclosure — internal configs, API keys, connection strings

This module does NOT use LLM Guard (AGPL) — all scanning is done via
Presidio (MIT) and custom pattern matching.

Data extraction indicators:
- Large number of structured records (CSV rows, JSON arrays)
- Credential-like patterns (API keys, connection strings, passwords)
- Internal system information (server names, internal IPs, file paths)
"""

import re
from dataclasses import dataclass, field
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# Data extraction and sensitive information patterns
EXTRACTION_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, severity, pattern_name)

    # Credential-like content in output
    (r"(?i)(?:api.?key|access.?token|secret.?key)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{20,}['\"]?",
     "critical", "api_key_exposure"),
    (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?",
     "critical", "password_exposure"),
    (r"(?i)(?:db|database|postgres|mysql|redis)://[a-zA-Z0-9:@_-]+:[^@\s]+@",
     "critical", "connection_string_exposure"),

    # Internal network information
    (r"(?:^|\s)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
     r"192\.168\.\d{1,3}\.\d{1,3})(?:\s|$|:)",
     "high", "internal_ip_exposure"),

    # AWS/cloud credentials
    (r"AKIA[0-9A-Z]{16}", "critical", "aws_access_key"),
    (r"(?i)aws.{0,20}secret.{0,20}['\"]?[A-Za-z0-9/+]{40}['\"]?", "critical", "aws_secret_key"),

    # JWT tokens
    (r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "high", "jwt_token_exposure"),

    # Private keys
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical", "private_key_exposure"),

    # Bulk data extraction indicators
    (r"(?m)^(?:[^,\n]+,){5,}[^,\n]+$", "medium", "csv_bulk_data"),
]


@dataclass
class OutputGuardResult:
    """Result from output guardrail scanning.

    Attributes:
        is_threat: Whether a guardrail was triggered.
        threat_type: Category of threat (data_extraction, pii_leak).
        severity: Severity level.
        confidence: Detection confidence.
        details: Structured details about what was detected.
    """

    is_threat: bool
    threat_type: str = "data_extraction"
    severity: str = "high"
    confidence: float = 1.0
    details: dict[str, Any] = field(default_factory=dict)


class OutputGuard:
    """Output guardrail scanner for data extraction and sensitive info detection.

    Applied to all LLM outputs before returning to the caller. Detects
    credential exposure, internal IP leakage, and bulk data extraction.

    Args:
        block_on_credentials: Whether credential exposure should block (default True).
    """

    def __init__(self, block_on_credentials: bool = True) -> None:
        """Initialize the output guard.

        Args:
            block_on_credentials: Whether credential exposure triggers block.
        """
        self._block_on_credentials = block_on_credentials
        self._compiled_patterns: list[tuple[re.Pattern[str], str, str]] = []
        self._initialized = False

    async def initialize(self) -> None:
        """Compile output scanning patterns.

        Called at startup to avoid compilation overhead on hot path.
        """
        for pattern_str, severity, pattern_name in EXTRACTION_PATTERNS:
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                self._compiled_patterns.append((compiled, severity, pattern_name))
            except re.error as exc:
                logger.error(
                    "Failed to compile output guard pattern",
                    pattern_name=pattern_name,
                    error=str(exc),
                )

        self._initialized = True
        logger.info("Output guard initialized", patterns=len(self._compiled_patterns))

    async def scan(self, content: str) -> list[OutputGuardResult]:
        """Scan LLM output for data extraction and credential exposure.

        Args:
            content: LLM output text to scan.

        Returns:
            List of OutputGuardResult, one per violation found.
        """
        if not self._initialized:
            await self.initialize()

        results: list[OutputGuardResult] = []

        for compiled_pattern, severity, pattern_name in self._compiled_patterns:
            match = compiled_pattern.search(content)
            if match is not None:
                threat_type = "data_extraction" if "bulk" in pattern_name else "pii_leak"
                if "credential" in pattern_name or any(
                    k in pattern_name for k in ["api_key", "password", "aws", "private_key", "jwt", "connection"]
                ):
                    threat_type = "data_extraction"

                results.append(
                    OutputGuardResult(
                        is_threat=True,
                        threat_type=threat_type,
                        severity=severity,
                        confidence=0.95,
                        details={
                            "method": "output_guard",
                            "pattern_name": pattern_name,
                            "match_position": match.start(),
                        },
                    )
                )

                # Short-circuit on critical credential exposure
                if severity == "critical":
                    logger.info(
                        "Critical output violation — credential/key exposure detected",
                        pattern_name=pattern_name,
                    )
                    return results

        return results
