"""AumOS Security Runtime service.

Runtime AI security enforcement engine providing:
- Pattern + ML-based prompt injection detection (>95% recall target)
- Real-time PII detection and redaction via Microsoft Presidio
- Input and output guardrail scanning
- Data extraction prevention
- Trivy container scanning integration
- All within a strict <50ms latency budget for input scans
"""

__version__ = "0.1.0"
