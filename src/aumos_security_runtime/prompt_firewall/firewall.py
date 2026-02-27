"""Main Prompt Firewall orchestrator.

Coordinates all 4 layers of the Prompt Firewall:
    Layer 1 — SignatureScanner  (regex, <1ms)
    Layer 2 — SemanticClassifier (features, <10ms)
    Layer 3 — ConversationStateTracker (multi-turn state)
    Layer 4 — OutputScanner (PII / confidential markers)

The firewall runs layers 1-3 on every input prompt and layer 4 on every model output.
Decisions cascade: a BLOCK from any layer short-circuits remaining layers.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Literal

from aumos_security_runtime.prompt_firewall.config import TenantFirewallConfig
from aumos_security_runtime.prompt_firewall.conversation_tracker import ConversationStateTracker
from aumos_security_runtime.prompt_firewall.output_scanner import Detection, OutputScanner
from aumos_security_runtime.prompt_firewall.semantic_classifier import SemanticClassifier
from aumos_security_runtime.prompt_firewall.signature_scanner import SignatureMatch, SignatureScanner


@dataclass(frozen=True)
class FirewallDecision:
    """Decision returned by scan_input.

    Attributes:
        verdict: ALLOW, BLOCK, or REVIEW.
        layer_triggered: Which layer triggered the verdict (1-4), or None for ALLOW.
        reason: Human-readable explanation of the decision.
        signature_matches: Matches from Layer 1, if triggered.
        injection_probability: Score from Layer 2, if run.
        conversation_suspicion: Accumulator value from Layer 3.
        details: Additional structured details.
    """

    verdict: Literal["ALLOW", "BLOCK", "REVIEW"]
    layer_triggered: int | None
    reason: str
    signature_matches: list[SignatureMatch]
    injection_probability: float
    conversation_suspicion: float
    details: dict[str, Any]


@dataclass(frozen=True)
class OutputFirewallDecision:
    """Decision returned by scan_output.

    Attributes:
        verdict: ALLOW, REDACT, or BLOCK.
        has_pii: Whether PII was detected.
        has_confidential_markers: Whether confidential markers were detected.
        detections: All detected entities.
        redacted_output: Output with PII replaced by [REDACTED:TYPE] tokens.
        reason: Human-readable explanation.
    """

    verdict: Literal["ALLOW", "REDACT", "BLOCK"]
    has_pii: bool
    has_confidential_markers: bool
    detections: list[Detection]
    redacted_output: str
    reason: str


@dataclass
class PromptFirewall:
    """4-layer prompt injection and data exfiltration prevention engine.

    Orchestrates all four scanning layers. Layers 1-3 run on inputs;
    layer 4 runs on outputs. The firewall is stateful per conversation
    via the ConversationStateTracker.

    Attributes:
        signature_scanner: Layer 1 — regex-based attack signature detection.
        semantic_classifier: Layer 2 — feature-based injection scoring.
        conversation_tracker: Layer 3 — multi-turn state and drift detection.
        output_scanner: Layer 4 — PII and confidential data detection.
    """

    signature_scanner: SignatureScanner = field(default_factory=SignatureScanner)
    semantic_classifier: SemanticClassifier = field(default_factory=SemanticClassifier)
    conversation_tracker: ConversationStateTracker = field(default_factory=ConversationStateTracker)
    output_scanner: OutputScanner = field(default_factory=OutputScanner)

    def __post_init__(self) -> None:
        """Initialise scanner instances if not provided."""
        # Dataclass fields with default_factory handle this — nothing extra needed.

    async def scan_input(
        self,
        prompt: str,
        conversation_history: list[dict[str, Any]] | None = None,
        system_prompt: str = "",
        conversation_id: str | None = None,
        tenant_config: TenantFirewallConfig | None = None,
    ) -> FirewallDecision:
        """Run layers 1-3 on an input prompt.

        Layers are short-circuit evaluated: if Layer 1 finds a critical signature,
        layers 2 and 3 are skipped to stay within the latency budget.

        Args:
            prompt: The raw user prompt to scan.
            conversation_history: Prior conversation turns (role/content dicts).
            system_prompt: Current system prompt text (used for drift detection).
            conversation_id: Unique ID for multi-turn state tracking.
            tenant_config: Per-tenant firewall configuration.

        Returns:
            FirewallDecision with verdict ALLOW, BLOCK, or REVIEW.
        """
        config = tenant_config or TenantFirewallConfig()
        sig_matches: list[SignatureMatch] = []
        injection_prob = 0.0
        conversation_suspicion = 0.0
        details: dict[str, Any] = {}

        # --- Layer 1: Signature Scanner ---
        if config.enable_signature_layer:
            sig_result = await asyncio.get_event_loop().run_in_executor(
                None, self.signature_scanner.scan, prompt
            )
            sig_matches = list(sig_result.matches)
            details["signature_highest_severity"] = sig_result.highest_severity

            if sig_result.is_attack and sig_result.highest_severity in ("critical", "high"):
                return FirewallDecision(
                    verdict="BLOCK",
                    layer_triggered=1,
                    reason=f"Attack signature detected: {sig_result.highest_severity} severity "
                    f"({sig_result.match_count} patterns matched).",
                    signature_matches=sig_matches,
                    injection_probability=injection_prob,
                    conversation_suspicion=conversation_suspicion,
                    details=details,
                )

        # --- Layer 2: Semantic Classifier ---
        if config.enable_semantic_layer:
            classifier_result = await asyncio.get_event_loop().run_in_executor(
                None,
                self.semantic_classifier.classify,
                prompt,
                conversation_history,
            )
            injection_prob = classifier_result.injection_probability
            details["semantic_features"] = classifier_result.features_triggered
            details["semantic_explanation"] = classifier_result.explanation

            if classifier_result.injection_probability >= config.semantic_threshold:
                if config.review_on_semantic_flag:
                    return FirewallDecision(
                        verdict="REVIEW",
                        layer_triggered=2,
                        reason=f"Semantic classifier flagged (probability={injection_prob:.2f}): "
                        f"{classifier_result.explanation}",
                        signature_matches=sig_matches,
                        injection_probability=injection_prob,
                        conversation_suspicion=conversation_suspicion,
                        details=details,
                    )
                else:
                    return FirewallDecision(
                        verdict="BLOCK",
                        layer_triggered=2,
                        reason=f"Semantic injection probability {injection_prob:.2f} exceeds "
                        f"threshold {config.semantic_threshold:.2f}.",
                        signature_matches=sig_matches,
                        injection_probability=injection_prob,
                        conversation_suspicion=conversation_suspicion,
                        details=details,
                    )

        # --- Layer 3: Conversation State Tracker ---
        if config.enable_conversation_tracking and conversation_id:
            system_prompt_hash = ConversationStateTracker.hash_system_prompt(system_prompt)
            turn = {"role": "user", "content": prompt}
            tracking_result = await asyncio.get_event_loop().run_in_executor(
                None,
                self.conversation_tracker.track_turn,
                conversation_id,
                turn,
                system_prompt_hash,
            )
            conversation_suspicion = tracking_result.suspicion_accumulator
            details["conversation_reasons"] = tracking_result.reasons
            details["drift_score"] = tracking_result.drift_score

            if tracking_result.should_block:
                return FirewallDecision(
                    verdict="BLOCK",
                    layer_triggered=3,
                    reason=f"Conversation suspicion accumulator {conversation_suspicion:.2f} "
                    f"exceeds threshold (reasons: {', '.join(tracking_result.reasons) or 'cumulative'}).",
                    signature_matches=sig_matches,
                    injection_probability=injection_prob,
                    conversation_suspicion=conversation_suspicion,
                    details=details,
                )

        # --- All layers passed ---
        return FirewallDecision(
            verdict="ALLOW",
            layer_triggered=None,
            reason="Input passed all enabled firewall layers.",
            signature_matches=sig_matches,
            injection_probability=injection_prob,
            conversation_suspicion=conversation_suspicion,
            details=details,
        )

    async def scan_output(
        self,
        output: str,
        tenant_config: TenantFirewallConfig | None = None,
    ) -> OutputFirewallDecision:
        """Run layer 4 on a model output.

        Detects PII and confidential data markers. When detected:
        - action_on_detection == "block" → BLOCK
        - action_on_detection == "sanitize" → REDACT
        - action_on_detection == "flag" → REDACT (with flagging)

        Args:
            output: The raw LLM output text to scan.
            tenant_config: Per-tenant firewall configuration.

        Returns:
            OutputFirewallDecision with verdict ALLOW, REDACT, or BLOCK.
        """
        config = tenant_config or TenantFirewallConfig()

        if not config.enable_output_scanning:
            return OutputFirewallDecision(
                verdict="ALLOW",
                has_pii=False,
                has_confidential_markers=False,
                detections=[],
                redacted_output=output,
                reason="Output scanning disabled by tenant configuration.",
            )

        scan_result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self.output_scanner.scan_output(output, config.pii_entities_to_detect),
        )

        if not scan_result.has_pii and not scan_result.has_confidential_markers:
            return OutputFirewallDecision(
                verdict="ALLOW",
                has_pii=False,
                has_confidential_markers=False,
                detections=[],
                redacted_output=output,
                reason="No PII or confidential markers detected in output.",
            )

        reason = (
            f"Detected: {', '.join(scan_result.entity_types_found)} "
            f"({len(scan_result.detections)} instance(s))."
        )

        if config.action_on_detection == "block":
            return OutputFirewallDecision(
                verdict="BLOCK",
                has_pii=scan_result.has_pii,
                has_confidential_markers=scan_result.has_confidential_markers,
                detections=list(scan_result.detections),
                redacted_output=scan_result.redacted_text,
                reason=f"Output blocked: {reason}",
            )

        # sanitize or flag → redact and return
        return OutputFirewallDecision(
            verdict="REDACT",
            has_pii=scan_result.has_pii,
            has_confidential_markers=scan_result.has_confidential_markers,
            detections=list(scan_result.detections),
            redacted_output=scan_result.redacted_text,
            reason=f"Output redacted: {reason}",
        )


__all__ = ["FirewallDecision", "OutputFirewallDecision", "PromptFirewall"]
