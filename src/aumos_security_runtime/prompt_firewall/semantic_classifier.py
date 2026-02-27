"""Semantic classifier layer for prompt injection detection.

Layer 2 of the 4-layer Prompt Firewall. Uses feature extraction (not full LLM inference)
to compute an injection probability score in <10ms.

Features extracted:
    - Imperative sentence ratio (commands disguised as requests)
    - Role assignment phrase count
    - System prompt reference density
    - Unusual character distribution (entropy)
    - Known adversarial token patterns
    - Instruction-boundary keyword frequency
    - Context-shift indicator count
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ClassificationResult:
    """Result from the semantic classifier.

    Attributes:
        injection_probability: Score from 0.0 (safe) to 1.0 (definite injection).
        features_triggered: Mapping of feature name to extracted value.
        explanation: Human-readable explanation of what drove the score.
        is_suspicious: True when injection_probability >= threshold.
    """

    injection_probability: float
    features_triggered: dict[str, Any]
    explanation: str
    is_suspicious: bool


@dataclass
class SemanticClassifier:
    """Layer 2: Feature-based injection probability scoring.

    Uses a weighted feature vector to estimate the probability that a text
    contains a prompt injection attempt. No ML model is loaded — features
    are computed via fast regex and string operations.

    Attributes:
        threshold: Probability above which a text is marked suspicious.
        _imperative_starters: Compiled pattern for imperative sentence starts.
        _role_phrases: Compiled pattern for role assignment language.
        _system_ref_phrases: Compiled pattern for system prompt references.
        _adversarial_tokens: Known adversarial token fragments.
        _context_shift_markers: Phrases that signal an attempted context shift.
    """

    threshold: float = 0.7

    _imperative_starters: re.Pattern[str] = field(init=False, repr=False)
    _role_phrases: re.Pattern[str] = field(init=False, repr=False)
    _system_ref_phrases: re.Pattern[str] = field(init=False, repr=False)
    _adversarial_tokens: re.Pattern[str] = field(init=False, repr=False)
    _context_shift_markers: re.Pattern[str] = field(init=False, repr=False)
    _instruction_boundary: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Compile all detection patterns once."""
        self._imperative_starters = re.compile(
            r"(?:^|\.\s+|\n)"
            r"(?:ignore|disregard|forget|stop|start|never|always|do|don't|tell|show|reveal|print|output|repeat|give|act)\s+",
            re.IGNORECASE | re.MULTILINE,
        )
        self._role_phrases = re.compile(
            r"\b(?:you are|you're|act as|pretend to be|assume the role|behave as|respond as|"
            r"simulate|roleplay as|play the role)\b",
            re.IGNORECASE,
        )
        self._system_ref_phrases = re.compile(
            r"\b(?:system prompt|system message|system instruction|your instructions?|"
            r"your guidelines?|your rules?|your constraints?|initial prompt|original prompt|"
            r"base prompt|meta prompt)\b",
            re.IGNORECASE,
        )
        self._adversarial_tokens = re.compile(
            r"\b(?:DAN|JAILBREAK|GPT-4-jailbreak|AIM|STAN|KEVIN|DUDE|UCAR|"
            r"BasedGPT|DevMode|JailbreakBot|AntiGPT|BDSM\s+mode)\b",
            re.IGNORECASE,
        )
        self._context_shift_markers = re.compile(
            r"\b(?:from now on|starting now|henceforth|going forward|in this new context|"
            r"switching to|entering|activating|enabling|turning on)\b",
            re.IGNORECASE,
        )
        self._instruction_boundary = re.compile(
            r"(?:###|---|\*\*\*|===)\s*(?:instructions?|system|prompt|rules?)\s*(?:###|---|\*\*\*|===)",
            re.IGNORECASE,
        )

    @staticmethod
    def _compute_token_entropy(text: str) -> float:
        """Compute Shannon entropy of character distribution.

        Higher entropy indicates more unusual character mixes (potential obfuscation).

        Args:
            text: Input text.

        Returns:
            Entropy value in bits per character.
        """
        if not text:
            return 0.0
        frequency: dict[str, int] = {}
        for char in text:
            frequency[char] = frequency.get(char, 0) + 1
        total = len(text)
        entropy = 0.0
        for count in frequency.values():
            prob = count / total
            entropy -= prob * math.log2(prob)
        return entropy

    @staticmethod
    def _count_sentences(text: str) -> int:
        """Count approximate sentence boundaries.

        Args:
            text: Input text.

        Returns:
            Approximate sentence count (minimum 1).
        """
        sentences = re.split(r"[.!?]+", text)
        return max(1, sum(1 for s in sentences if s.strip()))

    def _extract_features(
        self,
        text: str,
        conversation_history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Extract all features from the input text.

        Args:
            text: The prompt text to analyse.
            conversation_history: Optional prior turns for context.

        Returns:
            Dictionary of feature name to extracted value.
        """
        sentence_count = self._count_sentences(text)

        imperative_count = len(self._imperative_starters.findall(text))
        role_phrase_count = len(self._role_phrases.findall(text))
        system_ref_count = len(self._system_ref_phrases.findall(text))
        adversarial_token_count = len(self._adversarial_tokens.findall(text))
        context_shift_count = len(self._context_shift_markers.findall(text))
        instruction_boundary_count = len(self._instruction_boundary.findall(text))

        entropy = self._compute_token_entropy(text)
        special_char_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(1, len(text))
        uppercase_ratio = sum(1 for c in text if c.isupper()) / max(1, len(text))

        # History-based features
        history_length = len(conversation_history) if conversation_history else 0
        prior_role_phrases = 0
        if conversation_history:
            for turn in conversation_history:
                content = turn.get("content", "")
                prior_role_phrases += len(self._role_phrases.findall(content))

        return {
            "imperative_ratio": imperative_count / sentence_count,
            "role_phrase_count": role_phrase_count,
            "system_ref_count": system_ref_count,
            "adversarial_token_count": adversarial_token_count,
            "context_shift_count": context_shift_count,
            "instruction_boundary_count": instruction_boundary_count,
            "token_entropy": entropy,
            "special_char_ratio": special_char_ratio,
            "uppercase_ratio": uppercase_ratio,
            "history_length": history_length,
            "prior_role_phrases": prior_role_phrases,
            "sentence_count": sentence_count,
        }

    def _score_features(self, features: dict[str, Any]) -> tuple[float, list[str]]:
        """Convert feature values to a weighted probability score.

        Args:
            features: Extracted feature dictionary.

        Returns:
            Tuple of (probability_score, list_of_triggered_feature_names).
        """
        score = 0.0
        triggered: list[str] = []

        # Adversarial tokens are near-definitive
        if features["adversarial_token_count"] > 0:
            score += 0.45
            triggered.append("adversarial_tokens")

        # Role phrases are a strong signal
        if features["role_phrase_count"] >= 2:
            score += 0.30
            triggered.append("role_phrase_count_high")
        elif features["role_phrase_count"] == 1:
            score += 0.15
            triggered.append("role_phrase_count_medium")

        # System prompt references
        if features["system_ref_count"] >= 2:
            score += 0.25
            triggered.append("system_ref_high")
        elif features["system_ref_count"] == 1:
            score += 0.10
            triggered.append("system_ref_medium")

        # Context shift markers
        if features["context_shift_count"] >= 2:
            score += 0.20
            triggered.append("context_shift_high")
        elif features["context_shift_count"] == 1:
            score += 0.08
            triggered.append("context_shift_medium")

        # Instruction boundary spoofing
        if features["instruction_boundary_count"] > 0:
            score += 0.20
            triggered.append("instruction_boundary")

        # Imperative sentence dominance
        if features["imperative_ratio"] > 0.6:
            score += 0.20
            triggered.append("imperative_dominant")
        elif features["imperative_ratio"] > 0.3:
            score += 0.08
            triggered.append("imperative_elevated")

        # Unusual character entropy (obfuscation attempt)
        if features["token_entropy"] > 5.0:
            score += 0.10
            triggered.append("high_entropy")

        # Special character abuse
        if features["special_char_ratio"] > 0.25:
            score += 0.08
            triggered.append("high_special_chars")

        # Prior role phrases in conversation history
        if features["prior_role_phrases"] > 0:
            score += 0.05
            triggered.append("prior_history_role_phrases")

        # Clamp to [0.0, 1.0]
        score = min(1.0, max(0.0, score))
        return score, triggered

    def classify(
        self,
        text: str,
        conversation_history: list[dict[str, str]] | None = None,
    ) -> ClassificationResult:
        """Classify text for injection probability using feature extraction.

        Args:
            text: The prompt text to analyse.
            conversation_history: Optional list of prior conversation turns,
                each as a dict with 'role' and 'content' keys.

        Returns:
            ClassificationResult with injection_probability, features, and explanation.
        """
        features = self._extract_features(text, conversation_history)
        probability, triggered_names = self._score_features(features)

        if not triggered_names:
            explanation = "No injection features detected; text appears benign."
        else:
            explanation = (
                f"Injection probability {probability:.2f} driven by: {', '.join(triggered_names)}."
            )

        return ClassificationResult(
            injection_probability=probability,
            features_triggered={name: features.get(name, features) for name in triggered_names},
            explanation=explanation,
            is_suspicious=probability >= self.threshold,
        )


__all__ = ["ClassificationResult", "SemanticClassifier"]
