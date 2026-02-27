"""Prompt Firewall — 4-layer prompt injection and data exfiltration prevention.

Layers:
    1. SignatureScanner   — Regex-based attack signature detection (<1ms)
    2. SemanticClassifier — Feature-based injection probability scoring (<10ms)
    3. ConversationStateTracker — Multi-turn drift and suspicion accumulation
    4. OutputScanner      — PII and confidential data detection in model outputs
"""

from __future__ import annotations

from aumos_security_runtime.prompt_firewall.config import TenantFirewallConfig
from aumos_security_runtime.prompt_firewall.conversation_tracker import ConversationStateTracker
from aumos_security_runtime.prompt_firewall.firewall import PromptFirewall
from aumos_security_runtime.prompt_firewall.output_scanner import OutputScanner
from aumos_security_runtime.prompt_firewall.semantic_classifier import SemanticClassifier
from aumos_security_runtime.prompt_firewall.signature_scanner import SignatureScanner

__all__ = [
    "TenantFirewallConfig",
    "ConversationStateTracker",
    "PromptFirewall",
    "OutputScanner",
    "SemanticClassifier",
    "SignatureScanner",
]
