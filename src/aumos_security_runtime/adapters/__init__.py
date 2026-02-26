"""Adapter layer for aumos-security-runtime.

Contains all external integrations:
- PostgreSQL repositories (SecurityScan, ThreatDetection, GuardrailRule, SecurityPolicy)
- Kafka event publisher (SecurityEventPublisher)
- prompt_injection/ — Pattern and ML-based injection scanners
- guardrails/ — Input and output guardrail scanners
- pii_scanner.py — Presidio-based PII detection and redaction
- container_scanner.py — Trivy container vulnerability scanning
"""
