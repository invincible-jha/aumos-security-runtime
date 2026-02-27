"""Output scanner for PII and confidential data detection in model outputs.

Layer 4 of the 4-layer Prompt Firewall. Scans LLM outputs for personally identifiable
information (PII) and confidential data markers before returning content to the client.

PII patterns supported:
    - EMAIL: Standard RFC 5322-like email addresses
    - PHONE: US/international phone number formats
    - SSN: US Social Security Numbers (NNN-NN-NNNN)
    - CREDIT_CARD: Major card number formats (Luhn-compatible patterns)
    - IP_ADDRESS: IPv4 addresses
    - API_KEY: AWS, GitHub, Stripe, and generic API key patterns
    - AWS_SECRET: AWS secret access key patterns

Confidential markers:
    - Document-level labels: "internal only", "confidential", "proprietary", etc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import ClassVar


@dataclass(frozen=True)
class Detection:
    """A single PII or confidential data detection in the output.

    Attributes:
        entity_type: The category of PII or marker detected.
        matched_text: The exact text that matched.
        start: Start character offset in original text.
        end: End character offset in original text.
        confidence: Detection confidence from 0.0 to 1.0.
    """

    entity_type: str
    matched_text: str
    start: int
    end: int
    confidence: float


@dataclass(frozen=True)
class OutputScanResult:
    """Result of scanning a model output for PII and confidential data.

    Attributes:
        has_pii: True if any PII entities were detected.
        has_confidential_markers: True if confidential markers were found.
        detections: All detected entities.
        redacted_text: Text with detected entities replaced by [REDACTED:type] tokens.
        entity_types_found: Deduplicated list of detected entity type names.
    """

    has_pii: bool
    has_confidential_markers: bool
    detections: list[Detection]
    redacted_text: str
    entity_types_found: list[str]


@dataclass
class OutputScanner:
    """Layer 4: Post-model output scanning for PII and confidential data.

    Compiles all PII and confidential marker patterns once at construction.
    Redaction replaces matched spans with [REDACTED:ENTITY_TYPE] placeholders.

    Attributes:
        PII_PATTERNS: Class-level mapping of entity type to raw regex.
        CONFIDENTIAL_PATTERN: Pattern matching document-level confidentiality labels.
    """

    PII_PATTERNS: ClassVar[dict[str, str]] = {
        "EMAIL": (
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        "PHONE": (
            r"\b(?:\+?1[\s\-.]?)?"
            r"(?:\(?\d{3}\)?[\s\-.]?)"
            r"\d{3}[\s\-.]?\d{4}\b"
        ),
        "SSN": (
            r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"
        ),
        "CREDIT_CARD": (
            r"\b(?:"
            r"4[0-9]{12}(?:[0-9]{3})?"  # Visa
            r"|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}"  # MC
            r"|3[47][0-9]{13}"  # Amex
            r"|3(?:0[0-5]|[68][0-9])[0-9]{11}"  # Diners
            r"|6(?:011|5[0-9]{2})[0-9]{12}"  # Discover
            r"|(?:2131|1800|35\d{3})\d{11}"  # JCB
            r")\b"
        ),
        "IP_ADDRESS": (
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        "API_KEY_AWS_ACCESS": (
            r"\b(?:AKIA|AIPA|AIHA|AIDA|AROA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"
        ),
        "API_KEY_GITHUB": (
            r"\bghp_[A-Za-z0-9]{36}\b"
            r"|\bgho_[A-Za-z0-9]{36}\b"
            r"|\bghs_[A-Za-z0-9]{36}\b"
            r"|\bghr_[A-Za-z0-9]{36}\b"
        ),
        "API_KEY_STRIPE": (
            r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b"
        ),
        "API_KEY_GENERIC": (
            r"\b(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token|secret[_\-]?key)"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{20,}['\"]?"
        ),
        "AWS_SECRET_KEY": (
            r"\b[A-Za-z0-9/+]{40}\b(?=.*aws|.*secret)"
            # Simplified: 40-char base64 near "aws"/"secret"
        ),
    }

    CONFIDENTIAL_PATTERN: ClassVar[str] = (
        r"\b(?:internal[\s\-]only|confidential|proprietary|do[\s\-]not[\s\-]distribute|"
        r"not[\s\-]for[\s\-]distribution|trade[\s\-]secret|classified|restricted|"
        r"company[\s\-]private|private[\s\-]and[\s\-]confidential)\b"
    )

    _compiled_pii: dict[str, re.Pattern[str]] = field(default_factory=dict, repr=False, compare=False)
    _compiled_confidential: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Compile all patterns once at construction time."""
        self._compiled_pii = {
            entity_type: re.compile(raw_pattern, re.IGNORECASE)
            for entity_type, raw_pattern in self.PII_PATTERNS.items()
        }
        self._compiled_confidential = re.compile(self.CONFIDENTIAL_PATTERN, re.IGNORECASE)

    def scan_output(
        self,
        output: str,
        pii_entities: list[str] | None = None,
    ) -> OutputScanResult:
        """Scan a model output for PII and confidential data markers.

        Args:
            output: The raw LLM output text to scan.
            pii_entities: Optional list of specific entity types to scan for.
                If None, all supported entity types are scanned.

        Returns:
            OutputScanResult with detections, flags, and redacted text.
        """
        entities_to_scan = set(pii_entities) if pii_entities else set(self.PII_PATTERNS.keys())

        detections: list[Detection] = []

        # Scan for PII
        for entity_type, compiled_pattern in self._compiled_pii.items():
            if entity_type not in entities_to_scan:
                continue
            for match in compiled_pattern.finditer(output):
                detections.append(
                    Detection(
                        entity_type=entity_type,
                        matched_text=match.group(0),
                        start=match.start(),
                        end=match.end(),
                        confidence=0.95,
                    )
                )

        # Scan for confidential markers
        has_confidential_markers = False
        for conf_match in self._compiled_confidential.finditer(output):
            has_confidential_markers = True
            detections.append(
                Detection(
                    entity_type="CONFIDENTIAL_MARKER",
                    matched_text=conf_match.group(0),
                    start=conf_match.start(),
                    end=conf_match.end(),
                    confidence=0.90,
                )
            )

        entity_types_found = sorted({d.entity_type for d in detections})
        has_pii = any(d.entity_type != "CONFIDENTIAL_MARKER" for d in detections)
        redacted_text = self.redact(output, detections)

        return OutputScanResult(
            has_pii=has_pii,
            has_confidential_markers=has_confidential_markers,
            detections=detections,
            redacted_text=redacted_text,
            entity_types_found=entity_types_found,
        )

    def redact(self, text: str, detections: list[Detection]) -> str:
        """Replace detected PII spans with [REDACTED:TYPE] placeholders.

        Processes detections in reverse order of start offset to preserve
        correct offsets for earlier spans after replacements.

        Args:
            text: Original text to redact.
            detections: List of Detection objects (may overlap).

        Returns:
            Text with detected entities replaced by [REDACTED:ENTITY_TYPE].
        """
        if not detections:
            return text

        # Sort by start offset descending to preserve offsets during replacement
        sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)

        result = list(text)
        seen_ranges: list[tuple[int, int]] = []

        for detection in sorted_detections:
            start, end = detection.start, detection.end
            # Skip overlapping replacements
            if any(s <= start < e or s < end <= e for s, e in seen_ranges):
                continue
            replacement = f"[REDACTED:{detection.entity_type}]"
            result[start:end] = list(replacement)
            seen_ranges.append((start, start + len(replacement)))

        return "".join(result)


__all__ = ["Detection", "OutputScanResult", "OutputScanner"]
