"""Secret Scanner adapter — detect exposed credentials and secrets in LLM content.

Scans LLM inputs, outputs, and log streams for accidentally exposed secrets including
API keys, bearer tokens, database connection strings, private keys, and password-like
patterns. Uses a combination of regex pattern matching and Shannon entropy analysis
to detect secrets with high precision and low false-positive rates.

Detection methods:
- Regex pattern matching: vendor-specific key formats (AWS, GCP, GitHub, Stripe, etc.)
- Shannon entropy analysis: high-entropy strings that may be keys/tokens
- Log scanning: prevents secrets from being logged via structlog middleware
- Error message sanitization: strips secrets from exception messages before propagation
- Real-time hook: callable in request middleware with <5ms target latency

This adapter is intended for the security pipeline hot path. All patterns are
pre-compiled at startup and cached. No external network calls are made.

IMPORTANT: This adapter intentionally does NOT log full secret values.
Only hashes (SHA-256 truncated to 16 chars) and entity types are logged.
"""

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# Compiled regex patterns for common secret formats
# Each pattern: (entity_type, pattern_string, severity)
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # AWS
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "critical"),
    ("aws_secret_key", r"(?i)aws.{0,20}(?:secret|key).{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]", "critical"),
    ("aws_session_token", r"AQoXb[0-9A-Za-z+/=]{100,}", "critical"),
    # Google / GCP
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}", "critical"),
    ("google_oauth", r"ya29\.[0-9A-Za-z\-_]+", "high"),
    ("gcp_service_account", r'"type"\s*:\s*"service_account"', "critical"),
    # GitHub
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,255}", "critical"),
    ("github_app_token", r"ghs_[A-Za-z0-9]{36}", "critical"),
    # Stripe
    ("stripe_secret_key", r"sk_live_[0-9a-zA-Z]{24}", "critical"),
    ("stripe_restricted_key", r"rk_live_[0-9a-zA-Z]{24}", "high"),
    ("stripe_publishable_key", r"pk_live_[0-9a-zA-Z]{24}", "medium"),
    # Database connection strings
    ("postgres_dsn", r"postgres(?:ql)?://[^@\s]+:[^@\s]+@[^/\s]+/\S+", "critical"),
    ("mysql_dsn", r"mysql://[^@\s]+:[^@\s]+@[^/\s]+/\S+", "critical"),
    ("mongodb_dsn", r"mongodb(?:\+srv)?://[^@\s]+:[^@\s]+@[^/\s]+/\S+", "critical"),
    ("redis_dsn", r"redis://:[^@\s]+@[^/\s]+:\d+", "high"),
    # Private keys
    ("rsa_private_key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "critical"),
    ("pem_certificate", r"-----BEGIN CERTIFICATE-----", "medium"),
    # JWT tokens
    ("jwt_token", r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+", "high"),
    # Bearer tokens
    ("bearer_token", r"(?i)bearer\s+([A-Za-z0-9\-_.~+/]+=*)", "high"),
    # Slack
    ("slack_token", r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}", "critical"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9]{8}/B[a-zA-Z0-9]{8}/[a-zA-Z0-9]{24}", "high"),
    # Generic patterns
    ("password_in_url", r"[a-zA-Z]{3,10}://[^/\s:@]+:([^/\s:@]{3,100})@", "high"),
    ("api_key_generic", r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_.]{16,64})['\"]?", "high"),
    ("password_field", r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s]{6,100})['\"]", "high"),
    ("secret_field", r"(?i)(?:secret|token)\s*[=:]\s*['\"]([A-Za-z0-9\-_+/=]{16,128})['\"]", "high"),
]

# Minimum entropy threshold for high-entropy string detection
ENTROPY_THRESHOLD: float = 3.5

# Minimum string length for entropy analysis
ENTROPY_MIN_LENGTH: int = 16

# Characters considered for entropy analysis
HIGH_ENTROPY_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_-")


@dataclass
class SecretFinding:
    """A single detected secret in scanned content.

    Attributes:
        entity_type: Type of secret detected (e.g., 'aws_access_key').
        severity: Severity level ('critical', 'high', 'medium', 'low').
        match_hash: SHA-256 hash of the matched secret (truncated to 16 chars for logging).
        position_start: Character offset of the match start in the content.
        position_end: Character offset of the match end.
        confidence: Detection confidence (0.0–1.0).
        detection_method: 'regex' or 'entropy'.
        suppressed: Whether this finding is suppressed by a suppression rule.
    """

    entity_type: str
    severity: str
    match_hash: str
    position_start: int
    position_end: int
    confidence: float
    detection_method: str
    suppressed: bool = False


@dataclass
class SecretScanResult:
    """Result of a secret scan operation.

    Attributes:
        is_threat: Whether any unsuppressed secrets were detected.
        threat_type: 'secret_exposure' when is_threat is True.
        severity: Highest severity finding, or 'none'.
        confidence: Max confidence across all findings.
        n_findings: Total number of secret findings.
        findings: List of individual findings (without raw values).
        details: Additional metadata about the scan.
        sanitized_content: Content with secrets replaced by redaction markers.
    """

    is_threat: bool
    threat_type: str
    severity: str
    confidence: float
    n_findings: int
    findings: list[dict[str, Any]]
    details: dict[str, Any]
    sanitized_content: str = ""


class SecretScanner:
    """High-performance secret detection for LLM content in the security pipeline.

    Scans text content for exposed credentials and sensitive strings using
    pre-compiled regex patterns and Shannon entropy analysis. Designed for
    <5ms scan latency on the request hot path.

    Implements IPatternScanner protocol for SecurityPipelineService integration.

    Args:
        enable_entropy_detection: Whether to run entropy-based detection.
        entropy_threshold: Shannon entropy threshold for high-entropy strings.
        max_findings_per_scan: Maximum findings to return per scan (performance cap).
        suppression_rules: List of entity_type strings to suppress.
    """

    def __init__(
        self,
        enable_entropy_detection: bool = True,
        entropy_threshold: float = ENTROPY_THRESHOLD,
        max_findings_per_scan: int = 20,
        suppression_rules: list[str] | None = None,
    ) -> None:
        """Initialize the SecretScanner.

        Args:
            enable_entropy_detection: Run entropy analysis in addition to regex.
            entropy_threshold: Minimum entropy to flag a string as suspicious.
            max_findings_per_scan: Cap on returned findings.
            suppression_rules: Entity types to suppress (e.g., ['jwt_token']).
        """
        self._enable_entropy = enable_entropy_detection
        self._entropy_threshold = entropy_threshold
        self._max_findings = max_findings_per_scan
        self._suppression_rules = set(suppression_rules or [])
        self._compiled_patterns: list[tuple[str, re.Pattern[str], str]] = []
        self._initialized = False

    async def initialize(self) -> None:
        """Pre-compile and cache all regex patterns.

        Called once at startup to avoid compilation latency on hot path.
        Must be called before scan() is invoked.
        """
        if self._initialized:
            return

        compiled: list[tuple[str, re.Pattern[str], str]] = []
        for entity_type, pattern_str, severity in SECRET_PATTERNS:
            try:
                compiled.append((entity_type, re.compile(pattern_str), severity))
            except re.error as exc:
                logger.warning(
                    "Failed to compile secret pattern",
                    entity_type=entity_type,
                    error=str(exc),
                )

        self._compiled_patterns = compiled
        self._initialized = True

        logger.info(
            "SecretScanner initialized",
            n_patterns=len(self._compiled_patterns),
            entropy_enabled=self._enable_entropy,
            entropy_threshold=self._entropy_threshold,
        )

    async def scan(self, content: str) -> list[dict[str, Any]]:
        """Scan content for exposed secrets.

        Returns results in IScannerResult-compatible dict format for
        SecurityPipelineService integration.

        Args:
            content: Text content to scan for secrets.

        Returns:
            List of IScannerResult-compatible dicts, one per finding.
        """
        if not self._initialized:
            await self.initialize()

        result = self.scan_sync(content)

        if not result.is_threat:
            return []

        return [
            {
                "threat_type": f.get("entity_type", "secret_exposure"),
                "severity": f.get("severity", "high"),
                "confidence": f.get("confidence", 0.9),
                "is_threat": True,
                "details": f,
            }
            for f in result.findings
            if not f.get("suppressed", False)
        ]

    def scan_sync(self, content: str) -> SecretScanResult:
        """Synchronous secret scan for use in non-async contexts.

        Args:
            content: Text content to scan.

        Returns:
            SecretScanResult with all findings and sanitized content.
        """
        if not self._initialized:
            raise RuntimeError("SecretScanner.initialize() must be called before scan_sync()")

        findings: list[dict[str, Any]] = []
        redaction_ranges: list[tuple[int, int, str]] = []

        # Regex-based detection
        for entity_type, pattern, severity in self._compiled_patterns:
            if len(findings) >= self._max_findings:
                break

            for match in pattern.finditer(content):
                match_text = match.group(0)
                match_hash = hashlib.sha256(match_text.encode()).hexdigest()[:16]
                suppressed = entity_type in self._suppression_rules

                finding: dict[str, Any] = {
                    "entity_type": entity_type,
                    "severity": severity,
                    "match_hash": match_hash,
                    "position_start": match.start(),
                    "position_end": match.end(),
                    "match_length": len(match_text),
                    "confidence": 0.95,
                    "detection_method": "regex",
                    "suppressed": suppressed,
                }
                findings.append(finding)

                if not suppressed:
                    redaction_ranges.append((match.start(), match.end(), entity_type))

                if len(findings) >= self._max_findings:
                    break

        # Entropy-based detection
        if self._enable_entropy and len(findings) < self._max_findings:
            entropy_findings = self._detect_high_entropy(content)
            for ef in entropy_findings:
                if len(findings) >= self._max_findings:
                    break
                if not any(
                    f["position_start"] <= ef["position_start"] < f["position_end"]
                    for f in findings
                ):
                    findings.append(ef)
                    if not ef.get("suppressed", False):
                        redaction_ranges.append(
                            (ef["position_start"], ef["position_end"], ef["entity_type"])
                        )

        # Build sanitized content
        sanitized = self._redact_ranges(content, redaction_ranges)

        # Determine severity
        unsuppressed = [f for f in findings if not f.get("suppressed", False)]
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        max_severity = "none"
        max_confidence = 0.0

        if unsuppressed:
            max_severity = min(
                unsuppressed,
                key=lambda f: severity_order.get(f["severity"], 4)
            )["severity"]
            max_confidence = max(f["confidence"] for f in unsuppressed)

        if unsuppressed:
            logger.warning(
                "Secrets detected in content",
                n_findings=len(unsuppressed),
                max_severity=max_severity,
                entity_types=list({f["entity_type"] for f in unsuppressed}),
            )

        return SecretScanResult(
            is_threat=len(unsuppressed) > 0,
            threat_type="secret_exposure" if unsuppressed else "none",
            severity=max_severity,
            confidence=max_confidence,
            n_findings=len(findings),
            findings=findings,
            details={
                "n_regex_findings": sum(1 for f in findings if f["detection_method"] == "regex"),
                "n_entropy_findings": sum(1 for f in findings if f["detection_method"] == "entropy"),
                "n_suppressed": sum(1 for f in findings if f.get("suppressed", False)),
                "entity_types": list({f["entity_type"] for f in unsuppressed}),
            },
            sanitized_content=sanitized,
        )

    def sanitize_for_logging(self, content: str) -> str:
        """Sanitize content before logging to prevent secret exposure in log streams.

        Intended for use in structlog processors. Returns the sanitized version
        with secret values replaced by redaction markers.

        Args:
            content: Text content to sanitize.

        Returns:
            Sanitized content safe for logging.
        """
        if not self._initialized:
            return "[SECRET_SCANNER_NOT_INITIALIZED]"

        result = self.scan_sync(content)
        return result.sanitized_content if result.sanitized_content else content

    def sanitize_exception_message(self, message: str) -> str:
        """Strip secrets from exception messages before propagation.

        Args:
            message: Exception message to sanitize.

        Returns:
            Sanitized exception message.
        """
        return self.sanitize_for_logging(message)

    def add_suppression_rule(self, entity_type: str) -> None:
        """Add a suppression rule for a specific entity type.

        Args:
            entity_type: Entity type to suppress (e.g., 'jwt_token').
        """
        self._suppression_rules.add(entity_type)
        logger.info("Secret suppression rule added", entity_type=entity_type)

    def remove_suppression_rule(self, entity_type: str) -> None:
        """Remove a suppression rule.

        Args:
            entity_type: Entity type to un-suppress.
        """
        self._suppression_rules.discard(entity_type)
        logger.info("Secret suppression rule removed", entity_type=entity_type)

    def get_suppression_rules(self) -> list[str]:
        """Return current suppression rules.

        Returns:
            List of suppressed entity type strings.
        """
        return sorted(self._suppression_rules)

    def _detect_high_entropy(self, content: str) -> list[dict[str, Any]]:
        """Detect high-entropy substrings that may be secrets.

        Splits content into whitespace-delimited tokens and computes Shannon
        entropy. Tokens with entropy above the threshold are flagged.

        Args:
            content: Text content to analyze.

        Returns:
            List of entropy-based finding dicts.
        """
        findings: list[dict[str, Any]] = []
        offset = 0

        for token in content.split():
            token_start = content.find(token, offset)
            offset = token_start + len(token)

            if len(token) < ENTROPY_MIN_LENGTH:
                continue

            # Only analyze tokens containing mostly high-entropy characters
            high_entropy_chars = sum(1 for c in token if c in HIGH_ENTROPY_CHARS)
            if high_entropy_chars / len(token) < 0.7:
                continue

            entropy = self._shannon_entropy(token)

            if entropy >= self._entropy_threshold:
                match_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
                findings.append({
                    "entity_type": "high_entropy_string",
                    "severity": "medium",
                    "match_hash": match_hash,
                    "position_start": token_start,
                    "position_end": token_start + len(token),
                    "match_length": len(token),
                    "confidence": min(0.9, (entropy - self._entropy_threshold) / 2 + 0.5),
                    "detection_method": "entropy",
                    "entropy_score": round(entropy, 4),
                    "suppressed": "high_entropy_string" in self._suppression_rules,
                })

        return findings

    def _shannon_entropy(self, text: str) -> float:
        """Compute Shannon entropy of a string.

        Args:
            text: String to compute entropy for.

        Returns:
            Shannon entropy value (bits per character).
        """
        if not text:
            return 0.0

        freq: dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        length = len(text)
        entropy = 0.0
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)

        return entropy

    def _redact_ranges(
        self,
        content: str,
        ranges: list[tuple[int, int, str]],
    ) -> str:
        """Replace character ranges in content with redaction markers.

        Args:
            content: Original text content.
            ranges: List of (start, end, entity_type) tuples to redact.

        Returns:
            Content with matched ranges replaced by [REDACTED:{entity_type}] markers.
        """
        if not ranges:
            return content

        # Sort by start position descending to preserve offsets during replacement
        sorted_ranges = sorted(ranges, key=lambda r: r[0], reverse=True)
        result = content

        for start, end, entity_type in sorted_ranges:
            if start < 0 or end > len(result):
                continue
            marker = f"[REDACTED:{entity_type.upper()}]"
            result = result[:start] + marker + result[end:]

        return result


__all__ = ["SecretScanner", "SecretFinding", "SecretScanResult", "SECRET_PATTERNS"]
