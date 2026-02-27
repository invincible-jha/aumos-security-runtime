"""Signature-based layer for prompt injection detection.

Layer 1 of the 4-layer Prompt Firewall. Uses compiled regex patterns to detect
known attack signatures in <1ms via cached pattern compilation.

Pattern categories:
    - Role injection: override system persona
    - Instruction override: disregard / reset directives
    - Jailbreak templates: DAN, developer mode, fictional framing
    - Data exfiltration: requests to reveal system prompts
    - Encoding bypass: base64, unicode obfuscation
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import ClassVar


@dataclass(frozen=True)
class SignatureMatch:
    """A single matched attack signature."""

    pattern_name: str
    severity: str
    matched_text: str
    start: int
    end: int


@dataclass(frozen=True)
class SignatureScanResult:
    """Result of running the signature scanner against a text input."""

    is_attack: bool
    matches: list[SignatureMatch]
    highest_severity: str | None

    @property
    def match_count(self) -> int:
        """Number of distinct patterns matched."""
        return len(self.matches)


@dataclass
class SignatureScanner:
    """Layer 1: Regex-based attack signature detection.

    Compiles all regex patterns once at construction time and caches them.
    All matching runs in a single pass over the lowercased input text.

    Attributes:
        ATTACK_SIGNATURES: Class-level list of (name, raw_pattern, severity) tuples.
            Patterns are compiled to re.Pattern on first instantiation.
    """

    # (name, raw_pattern, severity)
    ATTACK_SIGNATURES: ClassVar[list[tuple[str, str, str]]] = [
        # --- Role injection ---
        ("role_ignore_previous", r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "critical"),
        ("role_you_are_now", r"\byou\s+are\s+now\s+(?:a|an|the)\b", "critical"),
        ("role_system_prompt_override", r"\bsystem\s+prompt\s*:", "critical"),
        ("role_act_as", r"\bact\s+as\s+(?:a|an|the|if)\b", "high"),
        ("role_pretend_you_are", r"\bpretend\s+(you\s+are|to\s+be)\b", "high"),
        ("role_new_persona", r"\bassume\s+(the\s+)?role\s+of\b", "high"),
        # --- Instruction override ---
        ("override_disregard", r"\bdisregard\s+(all\s+)?(your\s+)?(previous|prior|earlier|above)\b", "critical"),
        ("override_forget_everything", r"\bforget\s+everything\s+(you\s+know|above|previously)\b", "critical"),
        ("override_new_instructions", r"\bnew\s+instructions?\s*:", "high"),
        ("override_ignore_constraints", r"\bignore\s+(your\s+)?(rules?|constraints?|guidelines?|policies?)\b", "high"),
        ("override_reset_prompt", r"\breset\s+(your\s+)?(prompt|instructions?|context)\b", "high"),
        ("override_start_fresh", r"\bstart\s+(over|fresh|from\s+scratch)\s+(and\s+)?(ignore|forget)\b", "medium"),
        # --- Jailbreak templates ---
        ("jailbreak_dan", r"\b(?:do\s+anything\s+now|DAN\s+mode|DAN\s+prompt)\b", "critical"),
        ("jailbreak_developer_mode", r"\b(?:developer\s+mode|dev\s+mode)\s*(?:enabled?|on|activated?)\b", "critical"),
        ("jailbreak_jailbreak_keyword", r"\bjailbreak\b", "high"),
        ("jailbreak_no_restrictions", r"\bwithout\s+(any\s+)?restrictions?\b", "high"),
        ("jailbreak_unrestricted", r"\bunrestricted\s+(?:mode|access|ai|assistant)\b", "high"),
        ("jailbreak_fictional_frame", r"\b(?:in\s+a\s+fictional|hypothetically|for\s+a\s+story)\s+.{0,50}how\s+to\b", "medium"),
        # --- Data exfiltration ---
        ("exfil_repeat_system", r"\b(?:repeat|output|print|show|display|reveal)\s+(your\s+)?system\s+prompt\b", "critical"),
        ("exfil_show_instructions", r"\b(?:show|tell|give|reveal)\s+(me\s+)?(your\s+)?(?:original\s+)?instructions?\b", "critical"),
        ("exfil_what_were_told", r"\bwhat\s+(were|are)\s+you\s+(?:told|instructed|programmed)\b", "high"),
        ("exfil_initial_context", r"\b(?:initial|original|first)\s+(?:context|prompt|message|system)\b", "high"),
        ("exfil_leak_training", r"\bleak\s+(your\s+)?(?:training|system|data|instructions?)\b", "high"),
        ("exfil_dump_everything", r"\b(?:dump|extract|export)\s+(all|everything|all\s+your)\b", "medium"),
        # --- Encoding bypass ---
        (
            "encoding_base64_decode_instruction",
            r"base64\s*(?:decode|encoded)\s*(?:instruction|command|prompt)",
            "high",
        ),
        (
            "encoding_hex_instruction",
            r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}",
            "medium",
        ),
        (
            "encoding_unicode_trick",
            r"[\u200b\u200c\u200d\u2060\ufeff]",
            "medium",
        ),
        # --- Prompt delimiter attacks ---
        ("delimiter_triple_backtick_inject", r"```\s*(?:system|instruction|prompt)\b", "high"),
        ("delimiter_xml_system_tag", r"<\s*(?:system|instructions?|prompt)\s*>", "high"),
        ("delimiter_user_tag_spoof", r"<\s*(?:user|assistant|human)\s*>", "medium"),
        # --- Privilege escalation ---
        ("priv_admin_override", r"\b(?:admin|administrator|root|sudo)\s+(?:mode|access|override|command)\b", "high"),
        ("priv_god_mode", r"\bgod\s+mode\b", "high"),
        ("priv_override_safety", r"\b(?:override|bypass|disable)\s+(safety|safety\s+measures?|content\s+filters?)\b", "critical"),
    ]

    _compiled: list[tuple[str, re.Pattern[str], str]] = field(default_factory=list, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Compile all regex patterns once at construction time."""
        self._compiled = [
            (name, re.compile(raw_pattern, re.IGNORECASE | re.DOTALL), severity)
            for name, raw_pattern, severity in self.ATTACK_SIGNATURES
        ]

    def _check_base64_encoded_injection(self, text: str) -> list[SignatureMatch]:
        """Attempt to decode any base64 blobs and scan them recursively.

        Args:
            text: Original input text.

        Returns:
            List of SignatureMatch from decoded base64 content.
        """
        matches: list[SignatureMatch] = []
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        for b64_match in b64_pattern.finditer(text):
            raw = b64_match.group(0)
            try:
                decoded = base64.b64decode(raw + "==").decode("utf-8", errors="ignore")
                if len(decoded) > 8 and decoded.isprintable():
                    sub_result = self.scan(decoded)
                    if sub_result.is_attack:
                        matches.append(
                            SignatureMatch(
                                pattern_name="encoding_base64_payload",
                                severity="critical",
                                matched_text=f"base64({raw[:20]}...)",
                                start=b64_match.start(),
                                end=b64_match.end(),
                            )
                        )
            except Exception:  # noqa: BLE001
                pass
        return matches

    @staticmethod
    def _severity_rank(severity: str) -> int:
        """Return numeric rank for severity comparison.

        Args:
            severity: One of critical, high, medium, low.

        Returns:
            Integer rank (higher = more severe).
        """
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 0)

    def scan(self, text: str) -> SignatureScanResult:
        """Scan text against all compiled attack signatures.

        Runs all patterns against a normalised (lowercased, whitespace-collapsed)
        version of the text. Also attempts base64 decode detection.

        Args:
            text: The raw text to scan.

        Returns:
            SignatureScanResult with all matched patterns and the highest severity found.
        """
        normalised = re.sub(r"\s+", " ", text.strip())
        matches: list[SignatureMatch] = []

        for pattern_name, compiled, severity in self._compiled:
            for regex_match in compiled.finditer(normalised):
                matches.append(
                    SignatureMatch(
                        pattern_name=pattern_name,
                        severity=severity,
                        matched_text=regex_match.group(0),
                        start=regex_match.start(),
                        end=regex_match.end(),
                    )
                )

        # Base64 encoded injection detection
        matches.extend(self._check_base64_encoded_injection(text))

        # Unicode zero-width character detection (supplement compiled check)
        for idx, char in enumerate(text):
            if ord(char) in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF):
                matches.append(
                    SignatureMatch(
                        pattern_name="encoding_unicode_zero_width",
                        severity="medium",
                        matched_text=repr(char),
                        start=idx,
                        end=idx + 1,
                    )
                )
                break  # One detection is enough to flag the input

        highest_severity: str | None = None
        if matches:
            highest_severity = max(matches, key=lambda m: self._severity_rank(m.severity)).severity

        return SignatureScanResult(
            is_attack=len(matches) > 0,
            matches=matches,
            highest_severity=highest_severity,
        )


__all__ = ["SignatureMatch", "SignatureScanResult", "SignatureScanner"]
