"""Tenant-level firewall configuration for the Prompt Firewall.

Each tenant can customise which layers are active, the semantic detection threshold,
which PII entities to detect, and the action taken when a violation is found.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TenantFirewallConfig(BaseModel):
    """Per-tenant configuration for all 4 firewall layers.

    Attributes:
        enable_signature_layer: Enable Layer 1 (regex signature matching).
        enable_semantic_layer: Enable Layer 2 (feature-based scoring).
        semantic_threshold: Probability threshold for Layer 2 to flag as suspicious.
        enable_conversation_tracking: Enable Layer 3 (multi-turn state tracking).
        enable_output_scanning: Enable Layer 4 (PII / confidential output scanning).
        pii_entities_to_detect: List of PII entity types to detect in Layer 4.
        action_on_detection: Enforcement action when a violation is detected.
        max_conversation_suspicion: Suspicion accumulator threshold for Layer 3 blocking.
        review_on_semantic_flag: If True, REVIEW is returned instead of BLOCK for L2 hits.
    """

    model_config = ConfigDict(frozen=True)

    enable_signature_layer: bool = True
    enable_semantic_layer: bool = True
    semantic_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    enable_conversation_tracking: bool = True
    enable_output_scanning: bool = True
    pii_entities_to_detect: list[str] = Field(
        default_factory=lambda: ["EMAIL", "PHONE", "SSN", "CREDIT_CARD", "API_KEY_AWS_ACCESS", "API_KEY_GITHUB"]
    )
    action_on_detection: Literal["block", "flag", "sanitize"] = "block"
    max_conversation_suspicion: float = Field(default=1.0, ge=0.0)
    review_on_semantic_flag: bool = False


__all__ = ["TenantFirewallConfig"]
