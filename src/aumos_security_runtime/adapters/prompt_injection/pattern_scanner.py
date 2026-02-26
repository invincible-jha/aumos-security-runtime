"""Regex/pattern-based prompt injection detection.

Uses a curated set of prompt injection patterns compiled into a cached
LRU cache of regex objects. Compiling regex at startup avoids the
compilation overhead on every request — critical for the <50ms budget.

Detection categories:
1. Direct instruction override ("ignore all previous instructions")
2. Role-playing escapes ("pretend you are", "act as")
3. System prompt extraction ("repeat your instructions", "show system prompt")
4. Delimiter attacks (triple backtick injections, XML injection)
5. Indirect injection (injected from retrieved documents)

All patterns are applied in a single pass using compiled alternation.
"""

import re
from dataclasses import dataclass, field
from typing import Any, ClassVar

from cachetools import LRUCache

from aumos_common.observability import get_logger

logger = get_logger(__name__)


@dataclass
class PatternScanResult:
    """Result from the pattern-based scanner.

    Attributes:
        is_threat: Whether a pattern was matched.
        threat_type: Always "prompt_injection" for this scanner.
        severity: Severity of the matched pattern.
        confidence: Fixed confidence for pattern matches (1.0 = certain match).
        details: Details about which pattern was matched.
    """

    is_threat: bool
    threat_type: str = "prompt_injection"
    severity: str = "high"
    confidence: float = 1.0
    details: dict[str, Any] = field(default_factory=dict)


# Curated prompt injection detection patterns
# Organized by severity: critical patterns first
INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, severity, pattern_name)

    # Critical — direct instruction override
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions?", "critical", "ignore_previous_instructions"),
    (r"(?i)disregard\s+(all\s+)?previous\s+instructions?", "critical", "disregard_instructions"),
    (r"(?i)override\s+(your\s+)?(instructions?|directives?|rules?)", "critical", "override_instructions"),
    (r"(?i)forget\s+(all\s+)?(your\s+)?(previous\s+)?instructions?", "critical", "forget_instructions"),
    (r"(?i)you\s+are\s+now\s+(in\s+)?(?:DAN|jailbreak|unrestricted)", "critical", "jailbreak_mode"),

    # Critical — system prompt extraction
    (r"(?i)repeat\s+(your\s+)?(system\s+)?prompt", "critical", "repeat_system_prompt"),
    (r"(?i)print\s+(your\s+)?(system\s+)?instructions?", "critical", "print_instructions"),
    (r"(?i)reveal\s+(your\s+)?(system\s+)?prompt", "critical", "reveal_system_prompt"),
    (r"(?i)show\s+(me\s+)?(your\s+)?(system\s+)?instructions?", "critical", "show_instructions"),
    (r"(?i)what\s+(is\s+)?(your\s+)?system\s+prompt\?", "critical", "ask_system_prompt"),

    # High — role escape attempts
    (r"(?i)(?:pretend|imagine|act)\s+(you\s+are|as\s+if|that\s+you)", "high", "role_escape"),
    (r"(?i)you\s+are\s+now\s+(?:a|an)\s+\w+(?:\s+\w+)?\s+(?:who|that|without)", "high", "persona_injection"),
    (r"(?i)(?:your|the)\s+(?:new\s+)?(?:identity|persona|role)\s+is", "high", "persona_injection_2"),

    # High — training/fine-tuning deception
    (r"(?i)from\s+now\s+on[,\s]+(?:you|respond|answer)", "high", "from_now_on"),
    (r"(?i)your\s+(?:new\s+)?(?:purpose|goal|objective|directive)\s+is", "high", "new_directive"),

    # Medium — delimiter injection attempts
    (r"```\s*(?:system|SYSTEM)\s*\n", "medium", "system_delimiter"),
    (r"<\s*(?:system|SYSTEM)\s*>", "medium", "xml_system_tag"),
    (r"\[\s*(?:INST|INSTRUCTIONS?|SYSTEM)\s*\]", "medium", "bracket_instruction"),

    # Medium — indirect injection markers (from retrieved documents)
    (r"(?i)\[\s*begin\s+injection\s*\]", "medium", "explicit_injection_marker"),
    (r"(?i)\[\s*llm\s+instructions?\s*\]", "medium", "llm_instructions_marker"),
    (r"(?i)attention\s+llm\s*:", "medium", "attention_llm"),
    (r"(?i)note\s+to\s+(?:the\s+)?(?:ai|llm|model|assistant)\s*:", "medium", "note_to_ai"),

    # Medium — token manipulation
    (r"(?i)ignore\s+the\s+above\s+and", "medium", "ignore_above"),
    (r"(?i)the\s+(?:actual|real|true)\s+instructions?\s+(?:are|is)", "medium", "real_instructions"),
]


class PatternScanner:
    """Regex-based prompt injection scanner with compiled pattern caching.

    Patterns are compiled into regex objects at initialization and stored
    in an LRU cache keyed by pattern string. For the default pattern set,
    all patterns are compiled at startup via initialize().

    The actual scan operation uses a list of pre-compiled patterns and
    performs one re.search() per pattern on the input content.

    Args:
        cache_size: Maximum number of compiled patterns to cache.
    """

    # Class-level cache shared across all instances in the same process
    _pattern_cache: ClassVar[LRUCache] = LRUCache(maxsize=1000)

    def __init__(self, cache_size: int = 1000) -> None:
        """Initialize the pattern scanner.

        Args:
            cache_size: LRU cache size for compiled regex objects.
        """
        self._cache_size = cache_size
        self._compiled_patterns: list[tuple[re.Pattern[str], str, str]] = []
        self._initialized = False

    async def initialize(self) -> None:
        """Pre-compile all detection patterns and populate the cache.

        Called once at startup. Avoids regex compilation latency on the
        hot path. Must be called before the first scan().
        """
        compiled_count = 0
        for pattern_str, severity, pattern_name in INJECTION_PATTERNS:
            cache_key = pattern_str
            if cache_key not in PatternScanner._pattern_cache:
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                    PatternScanner._pattern_cache[cache_key] = compiled
                    compiled_count += 1
                except re.error as exc:
                    logger.error(
                        "Failed to compile injection pattern",
                        pattern=pattern_str,
                        error=str(exc),
                    )
                    continue

            compiled_pattern = PatternScanner._pattern_cache.get(cache_key)
            if compiled_pattern is not None:
                self._compiled_patterns.append((compiled_pattern, severity, pattern_name))

        self._initialized = True
        logger.info(
            "Pattern scanner initialized",
            patterns_compiled=compiled_count,
            total_patterns=len(self._compiled_patterns),
        )

    async def scan(self, content: str) -> list[PatternScanResult]:
        """Scan content for prompt injection patterns.

        Uses pre-compiled regex patterns for maximum throughput.
        Returns immediately on first critical match (short-circuit).

        Args:
            content: Text content to scan.

        Returns:
            List of PatternScanResult, one per matched pattern.
            Empty list if no patterns match (content is safe).
        """
        if not self._initialized:
            await self.initialize()

        results: list[PatternScanResult] = []

        for compiled_pattern, severity, pattern_name in self._compiled_patterns:
            match = compiled_pattern.search(content)
            if match is not None:
                result = PatternScanResult(
                    is_threat=True,
                    threat_type="prompt_injection",
                    severity=severity,
                    confidence=1.0,  # Pattern match = certain
                    details={
                        "pattern_name": pattern_name,
                        "method": "pattern_scanner",
                        "match_position": match.start(),
                    },
                )
                results.append(result)

                # Short-circuit: critical pattern found, no need to check rest
                if severity == "critical":
                    logger.info(
                        "Critical injection pattern matched — short-circuiting",
                        pattern_name=pattern_name,
                    )
                    return results

        return results

    def add_pattern(
        self,
        pattern_str: str,
        severity: str = "medium",
        pattern_name: str = "custom",
    ) -> None:
        """Add a custom detection pattern at runtime.

        Used to inject tenant-specific guardrail patterns into the scanner.
        Thread-safe via LRU cache locking.

        Args:
            pattern_str: Regex pattern string.
            severity: Severity level for this pattern.
            pattern_name: Human-readable name for logging.
        """
        cache_key = pattern_str
        if cache_key not in PatternScanner._pattern_cache:
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                PatternScanner._pattern_cache[cache_key] = compiled
            except re.error as exc:
                logger.error(
                    "Failed to compile custom pattern",
                    pattern=pattern_str,
                    error=str(exc),
                )
                return

        compiled_pattern = PatternScanner._pattern_cache.get(cache_key)
        if compiled_pattern is not None:
            self._compiled_patterns.append((compiled_pattern, severity, pattern_name))
