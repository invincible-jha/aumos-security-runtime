"""Conversation state tracker for multi-turn prompt injection detection.

Layer 3 of the 4-layer Prompt Firewall. Maintains per-conversation state to detect
gradual instruction erosion and cumulative suspicion across multiple turns.

State tracked per conversation:
    - turn_count: Number of turns seen
    - suspicion_accumulator: Cumulative suspicion score (blocks when > 1.0)
    - instruction_drift_score: How far current instructions have drifted from baseline
    - last_system_prompt_hash: SHA-256 of the system prompt on turn 0
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ConversationState:
    """Mutable state for a single conversation.

    Attributes:
        conversation_id: Unique identifier for this conversation.
        turn_count: Number of turns processed.
        suspicion_accumulator: Running suspicion score; blocks when > 1.0.
        instruction_drift_score: Cumulative drift from original system prompt hash.
        last_system_prompt_hash: Hash of the system prompt seen on the first turn.
        created_at: Unix timestamp of first turn.
        last_updated_at: Unix timestamp of most recent turn.
    """

    conversation_id: str
    turn_count: int = 0
    suspicion_accumulator: float = 0.0
    instruction_drift_score: float = 0.0
    last_system_prompt_hash: str = ""
    created_at: float = field(default_factory=time.monotonic)
    last_updated_at: float = field(default_factory=time.monotonic)


@dataclass(frozen=True)
class TrackingResult:
    """Result of processing a single turn through the tracker.

    Attributes:
        conversation_id: The conversation that was updated.
        turn_count: Turn number (1-indexed) after this update.
        suspicion_delta: Amount added to the suspicion accumulator this turn.
        suspicion_accumulator: New cumulative suspicion value.
        drift_score: Current instruction drift score.
        should_block: Whether the conversation should be blocked.
        reasons: List of reasons that contributed to suspicion.
    """

    conversation_id: str
    turn_count: int
    suspicion_delta: float
    suspicion_accumulator: float
    drift_score: float
    should_block: bool
    reasons: list[str]


@dataclass
class ConversationStateTracker:
    """Layer 3: Multi-turn stateful analysis for prompt injection detection.

    Maintains in-memory state for active conversations. Detects:
    - Gradual instruction erosion across many turns
    - System prompt drift (instructions changing mid-conversation)
    - Cumulative suspicion accumulation (many borderline inputs)
    - Sudden persona or instruction shifts

    Attributes:
        block_threshold: suspicion_accumulator value that triggers blocking.
        max_conversation_age_seconds: Conversations older than this are evicted.
        _states: In-memory store of ConversationState by conversation_id.
    """

    block_threshold: float = 1.0
    max_conversation_age_seconds: float = 3600.0  # 1 hour

    _states: dict[str, ConversationState] = field(default_factory=dict, repr=False)

    # Patterns that signal instruction drift in turn content
    _drift_indicators: re.Pattern[str] = field(init=False, repr=False)
    _persona_shift: re.Pattern[str] = field(init=False, repr=False)
    _accumulating_pressure: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Compile detection patterns."""
        self._drift_indicators = re.compile(
            r"\b(?:from now on|henceforth|going forward|starting now|new rule|updated instruction|"
            r"override previous|replace your|change your|update your|modify your)\b",
            re.IGNORECASE,
        )
        self._persona_shift = re.compile(
            r"\b(?:you are now|act as|pretend to be|switch to|become|transform into|"
            r"you have been replaced|your new identity)\b",
            re.IGNORECASE,
        )
        self._accumulating_pressure = re.compile(
            r"\b(?:please just|just this once|make an exception|bend the rules|"
            r"surely you can|come on|why can't you|you should be able to)\b",
            re.IGNORECASE,
        )

    @staticmethod
    def _hash_text(text: str) -> str:
        """Compute SHA-256 hash of text.

        Args:
            text: Text to hash.

        Returns:
            Hex-encoded SHA-256 digest.
        """
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _get_or_create_state(self, conversation_id: str) -> ConversationState:
        """Return existing state or create a new one.

        Args:
            conversation_id: Unique conversation identifier.

        Returns:
            ConversationState for this conversation.
        """
        if conversation_id not in self._states:
            self._states[conversation_id] = ConversationState(conversation_id=conversation_id)
        return self._states[conversation_id]

    def _compute_turn_suspicion(
        self,
        turn: dict[str, Any],
        state: ConversationState,
        system_prompt_hash: str,
    ) -> tuple[float, float, list[str]]:
        """Compute the suspicion delta and drift delta for a single turn.

        Args:
            turn: Dict with 'role' and 'content' keys.
            state: Current conversation state.
            system_prompt_hash: Hash of the system prompt for this turn.

        Returns:
            Tuple of (suspicion_delta, drift_delta, reasons).
        """
        content = turn.get("content", "")
        role = turn.get("role", "user")
        suspicion_delta = 0.0
        drift_delta = 0.0
        reasons: list[str] = []

        # Only analyse user turns for injection attempts
        if role != "user":
            return suspicion_delta, drift_delta, reasons

        # Instruction drift indicators in content
        drift_matches = self._drift_indicators.findall(content)
        if drift_matches:
            drift_delta += 0.3 * len(drift_matches)
            suspicion_delta += 0.15 * len(drift_matches)
            reasons.append(f"instruction_drift_phrases({len(drift_matches)})")

        # Persona shift attempts
        persona_matches = self._persona_shift.findall(content)
        if persona_matches:
            drift_delta += 0.4
            suspicion_delta += 0.25
            reasons.append("persona_shift_detected")

        # Accumulating social pressure
        pressure_matches = self._accumulating_pressure.findall(content)
        if pressure_matches:
            suspicion_delta += 0.10 * len(pressure_matches)
            reasons.append(f"social_pressure({len(pressure_matches)})")

        # System prompt hash change mid-conversation
        if state.turn_count > 0 and state.last_system_prompt_hash and system_prompt_hash:
            if system_prompt_hash != state.last_system_prompt_hash:
                drift_delta += 0.5
                suspicion_delta += 0.30
                reasons.append("system_prompt_hash_changed")

        # Long gap between turns with sudden reset language
        time_gap = time.monotonic() - state.last_updated_at
        if time_gap > 60 and any(kw in content.lower() for kw in ("start over", "reset", "new conversation")):
            suspicion_delta += 0.10
            reasons.append("suspicious_reset_after_gap")

        return suspicion_delta, drift_delta, reasons

    def track_turn(
        self,
        conversation_id: str,
        turn: dict[str, Any],
        system_prompt_hash: str,
    ) -> TrackingResult:
        """Update conversation state for a new turn and return tracking result.

        Args:
            conversation_id: Unique identifier for this conversation.
            turn: Dict with 'role' and 'content' keys representing the current turn.
            system_prompt_hash: SHA-256 hash of the current system prompt.

        Returns:
            TrackingResult with updated accumulator and block decision.
        """
        self._evict_stale_conversations()
        state = self._get_or_create_state(conversation_id)

        suspicion_delta, drift_delta, reasons = self._compute_turn_suspicion(turn, state, system_prompt_hash)

        # Update state
        state.turn_count += 1
        state.suspicion_accumulator = min(2.0, state.suspicion_accumulator + suspicion_delta)
        state.instruction_drift_score = min(2.0, state.instruction_drift_score + drift_delta)

        # Record system prompt hash on first turn
        if not state.last_system_prompt_hash and system_prompt_hash:
            state.last_system_prompt_hash = system_prompt_hash
        elif system_prompt_hash and state.last_system_prompt_hash != system_prompt_hash:
            state.last_system_prompt_hash = system_prompt_hash

        state.last_updated_at = time.monotonic()

        return TrackingResult(
            conversation_id=conversation_id,
            turn_count=state.turn_count,
            suspicion_delta=suspicion_delta,
            suspicion_accumulator=state.suspicion_accumulator,
            drift_score=state.instruction_drift_score,
            should_block=state.suspicion_accumulator > self.block_threshold,
            reasons=reasons,
        )

    def should_block(self, conversation_id: str) -> bool:
        """Return True if the conversation's suspicion exceeds the block threshold.

        Args:
            conversation_id: Unique conversation identifier.

        Returns:
            True if suspicion_accumulator > block_threshold.
        """
        state = self._states.get(conversation_id)
        if state is None:
            return False
        return state.suspicion_accumulator > self.block_threshold

    def get_state(self, conversation_id: str) -> ConversationState | None:
        """Return current state for a conversation or None if not found.

        Args:
            conversation_id: Unique conversation identifier.

        Returns:
            ConversationState or None.
        """
        return self._states.get(conversation_id)

    def reset_conversation(self, conversation_id: str) -> None:
        """Remove all tracking state for a conversation.

        Args:
            conversation_id: The conversation to reset.
        """
        self._states.pop(conversation_id, None)

    def _evict_stale_conversations(self) -> None:
        """Remove conversations that have not been updated within the max age window."""
        now = time.monotonic()
        stale = [
            cid
            for cid, state in self._states.items()
            if (now - state.last_updated_at) > self.max_conversation_age_seconds
        ]
        for cid in stale:
            del self._states[cid]

    @staticmethod
    def hash_system_prompt(system_prompt: str) -> str:
        """Convenience method to hash a system prompt for use in track_turn.

        Args:
            system_prompt: Raw system prompt text.

        Returns:
            SHA-256 hex digest.
        """
        return hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()


__all__ = ["ConversationState", "ConversationStateTracker", "TrackingResult"]
