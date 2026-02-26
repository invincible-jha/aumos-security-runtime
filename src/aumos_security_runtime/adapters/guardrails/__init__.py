"""Guardrail adapters for input and output scanning.

input_guard.py — Scans LLM inputs for PII, toxicity, and policy violations
output_guard.py — Scans LLM outputs for data extraction and sensitive information leakage

Both use Microsoft Presidio (MIT license) for PII detection.
Note: LLM Guard is AGPL-licensed and must NOT be used here.
"""
