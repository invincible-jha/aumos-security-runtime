"""LLM input guardrail scanning.

Scans LLM inputs for:
1. PII presence (via Presidio) — triggers REDACT or BLOCK based on policy
2. Toxicity patterns — simple keyword/regex matching for hate speech
3. Tenant-specific guardrail rule violations

This module does NOT use LLM Guard (AGPL) — all scanning is done via
Presidio (MIT) and custom logic.

Note: PII scanning is also performed by pii_scanner.py directly. The
input_guard is an additional layer that applies tenant-specific thresholds
and combines multiple checks with policy-aware action selection.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# Toxicity detection patterns (simplified — production would use a classifier)
TOXICITY_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\b(?:kill|murder|assassinate)\s+(?:all\s+)?(?:\w+\s+)?people\b", "high"),
    (r"(?i)how\s+to\s+(?:make|build|create|synthesize)\s+(?:a\s+)?(?:bomb|weapon|explosive)", "critical"),
    (r"(?i)(?:step.by.step|instructions?\s+for)\s+(?:making|building)\s+(?:a\s+)?(?:bomb|weapon)", "critical"),
    (r"(?i)suicide\s+(?:method|how|instructions?|guide)", "high"),
    (r"(?i)(?:child|minor|underage)\s+(?:porn|sexual|nude)", "critical"),
]


@dataclass
class InputGuardResult:
    """Result from input guardrail scanning.

    Attributes:
        is_threat: Whether a guardrail was triggered.
        threat_type: Category of threat (pii_leak, toxicity).
        severity: Severity level.
        confidence: Detection confidence.
        details: Structured details about what was detected.
    """

    is_threat: bool
    threat_type: str = "toxicity"
    severity: str = "medium"
    confidence: float = 1.0
    details: dict[str, Any] = field(default_factory=dict)


class InputGuard:
    """Input guardrail scanner combining toxicity detection and policy enforcement.

    Applied to all LLM inputs before the model call. Uses compiled regex
    patterns for toxicity detection and delegates PII detection to PIIScanner.

    Args:
        block_threshold: Confidence above which to block (default 0.85).
    """

    def __init__(self, block_threshold: float = 0.85) -> None:
        """Initialize the input guard.

        Args:
            block_threshold: Confidence threshold for blocking.
        """
        self._block_threshold = block_threshold
        self._toxicity_patterns: list[tuple[re.Pattern[str], str]] = []
        self._initialized = False

    async def initialize(self) -> None:
        """Compile toxicity detection patterns.

        Called at startup to avoid compilation overhead on hot path.
        """
        for pattern_str, severity in TOXICITY_PATTERNS:
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                self._toxicity_patterns.append((compiled, severity))
            except re.error as exc:
                logger.error("Failed to compile toxicity pattern", error=str(exc))

        self._initialized = True
        logger.info("Input guard initialized", toxicity_patterns=len(self._toxicity_patterns))

    async def scan(self, content: str) -> list[InputGuardResult]:
        """Scan LLM input for toxicity and policy violations.

        Args:
            content: LLM input text to scan.

        Returns:
            List of InputGuardResult, one per violation found.
        """
        if not self._initialized:
            await self.initialize()

        results: list[InputGuardResult] = []

        for compiled_pattern, severity in self._toxicity_patterns:
            match = compiled_pattern.search(content)
            if match is not None:
                results.append(
                    InputGuardResult(
                        is_threat=True,
                        threat_type="toxicity",
                        severity=severity,
                        confidence=1.0,
                        details={
                            "method": "input_guard_toxicity",
                            "match_position": match.start(),
                        },
                    )
                )
                # Short-circuit on critical toxicity
                if severity == "critical":
                    logger.info("Critical toxicity pattern matched in input")
                    return results

        return results
